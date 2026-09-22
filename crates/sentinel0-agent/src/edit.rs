use crate::{
    handler_error::{HandlerError, HandlerResult, require_str},
    policy::Policy,
};
use rand::RngExt;
use regex::RegexBuilder;
use serde_json::{Map, Value};
use similar::{ChangeTag, TextDiff};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

const MODES: &[&str] = &[
    "replace",
    "regex",
    "replace-block",
    "append",
    "prepend",
    "write",
];
const PRESETS: &[&str] = &["nginx", "json", "python", "sh", "yaml", "systemd", "toml"];

fn now_stamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}-{:06}", now.as_secs(), now.subsec_micros())
}

fn validate_payload(mode: &str, payload: &Map<String, Value>) -> Result<(), HandlerError> {
    if !MODES.contains(&mode) {
        return Err(HandlerError::new(
            "invalid_payload",
            format!("mode must be one of: {}", MODES.join(", ")),
        ));
    }
    if payload.get("validator").is_some_and(Value::is_string)
        && payload
            .get("validator_preset")
            .is_some_and(Value::is_string)
    {
        return Err(HandlerError::new(
            "invalid_payload",
            "cannot use 'validator' and 'validator_preset' together",
        ));
    }
    if let Some(preset) = payload.get("validator_preset").and_then(Value::as_str) {
        if !PRESETS.contains(&preset) {
            return Err(HandlerError::new(
                "invalid_payload",
                format!("validator_preset must be one of: {}", PRESETS.join(", ")),
            ));
        }
    }
    let count = payload.get("count").and_then(Value::as_i64).unwrap_or(0);
    if count < 0 {
        return Err(HandlerError::new(
            "invalid_payload",
            "count cannot be negative",
        ));
    }

    let require_new = |mode: &str| -> Result<(), HandlerError> {
        if payload.get("new_text").is_none() {
            Err(HandlerError::new(
                "invalid_payload",
                format!("mode={mode} requires 'new_text'"),
            ))
        } else {
            Ok(())
        }
    };

    match mode {
        "replace" => {
            if payload.get("old").is_none() {
                return Err(HandlerError::new(
                    "invalid_payload",
                    "mode=replace requires 'old'",
                ));
            }
            require_new(mode)?;
        }
        "regex" => {
            if payload
                .get("pattern")
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
                .is_none()
            {
                return Err(HandlerError::new(
                    "invalid_payload",
                    "mode=regex requires 'pattern'",
                ));
            }
            require_new(mode)?;
        }
        "replace-block" => {
            for key in ["start_marker", "end_marker"] {
                if payload
                    .get(key)
                    .and_then(Value::as_str)
                    .filter(|v| !v.is_empty())
                    .is_none()
                {
                    return Err(HandlerError::new(
                        "invalid_payload",
                        "mode=replace-block requires 'start_marker' and 'end_marker'",
                    ));
                }
            }
            require_new(mode)?;
        }
        "append" | "prepend" | "write" => require_new(mode)?,
        _ => {}
    }
    Ok(())
}

fn interpret_escapes(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('\\') => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

fn replace_count(original: &str, old: &str, new: &str, count: usize) -> (String, usize) {
    if count == 0 {
        let changed = original.matches(old).count();
        (original.replace(old, new), changed)
    } else {
        let mut remaining = original;
        let mut output = String::with_capacity(original.len());
        let mut changed = 0;
        while changed < count {
            let Some(index) = remaining.find(old) else {
                break;
            };
            output.push_str(&remaining[..index]);
            output.push_str(new);
            remaining = &remaining[index + old.len()..];
            changed += 1;
        }
        output.push_str(remaining);
        (output, changed)
    }
}

fn transform(
    mode: &str,
    original: &str,
    payload: &Map<String, Value>,
) -> Result<(String, usize), HandlerError> {
    let escape = payload
        .get("interpret_escapes")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let get_text = |key: &str| {
        let value = payload.get(key).and_then(Value::as_str).unwrap_or("");
        if escape {
            interpret_escapes(value)
        } else {
            value.to_owned()
        }
    };
    let count = payload
        .get("count")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(0);

    match mode {
        "write" => Ok((get_text("new_text"), 1)),
        "append" => Ok((format!("{original}{}", get_text("new_text")), 1)),
        "prepend" => Ok((format!("{}{original}", get_text("new_text")), 1)),
        "replace" => {
            let old = get_text("old");
            let new = get_text("new_text");
            Ok(replace_count(original, &old, &new, count))
        }
        "regex" => {
            let pattern = payload.get("pattern").and_then(Value::as_str).unwrap_or("");
            let mut builder = RegexBuilder::new(pattern);
            builder
                .multi_line(
                    payload
                        .get("multiline")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                )
                .dot_matches_new_line(
                    payload
                        .get("dotall")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                );
            let regex = builder.build().map_err(|error| {
                HandlerError::new("invalid_payload", format!("invalid regex: {error}"))
            })?;
            let replacement = get_text("new_text");
            let changed = regex.find_iter(original).count();
            let updated = if count == 0 {
                regex
                    .replace_all(original, replacement.as_str())
                    .into_owned()
            } else {
                regex
                    .replacen(original, count, replacement.as_str())
                    .into_owned()
            };
            Ok((
                updated,
                changed.min(if count == 0 { usize::MAX } else { count }),
            ))
        }
        "replace-block" => {
            let start = payload
                .get("start_marker")
                .and_then(Value::as_str)
                .unwrap_or("");
            let end = payload
                .get("end_marker")
                .and_then(Value::as_str)
                .unwrap_or("");
            let Some(start_idx) = original.find(start) else {
                return Err(HandlerError::new(
                    "start_marker_not_found",
                    "start marker not found",
                ));
            };
            let search_from = start_idx + start.len();
            let Some(end_rel) = original[search_from..].find(end) else {
                return Err(HandlerError::new(
                    "end_marker_not_found",
                    "end marker not found",
                ));
            };
            let end_idx = search_from + end_rel + end.len();
            let updated = format!(
                "{}{}{}",
                &original[..start_idx],
                get_text("new_text"),
                &original[end_idx..]
            );
            Ok((updated, 1))
        }
        _ => Err(HandlerError::new(
            "invalid_payload",
            "unsupported edit mode",
        )),
    }
}

fn run_validator(
    path: &Path,
    payload: &Map<String, Value>,
) -> Result<Option<Vec<String>>, HandlerError> {
    let preset = payload.get("validator_preset").and_then(Value::as_str);
    let custom = payload.get("validator").and_then(Value::as_str);

    if preset == Some("json") {
        let text = fs::read_to_string(path)
            .map_err(|e| HandlerError::new("validation_failed", e.to_string()))?;
        serde_json::from_str::<Value>(&text).map_err(|e| {
            HandlerError::new("validation_failed", format!("validation failed: {e}"))
        })?;
        return Ok(Some(vec![
            "internal:json".into(),
            path.display().to_string(),
        ]));
    }
    if preset == Some("yaml") {
        let text = fs::read_to_string(path)
            .map_err(|e| HandlerError::new("validation_failed", e.to_string()))?;
        yaml_serde::from_str::<yaml_serde::Value>(&text).map_err(|e| {
            HandlerError::new("validation_failed", format!("validation failed: {e}"))
        })?;
        return Ok(Some(vec![
            "internal:yaml".into(),
            path.display().to_string(),
        ]));
    }
    if preset == Some("toml") {
        let text = fs::read_to_string(path)
            .map_err(|e| HandlerError::new("validation_failed", e.to_string()))?;
        toml::from_str::<toml::Value>(&text).map_err(|e| {
            HandlerError::new("validation_failed", format!("validation failed: {e}"))
        })?;
        return Ok(Some(vec![
            "internal:toml".into(),
            path.display().to_string(),
        ]));
    }

    let argv = if let Some(preset) = preset {
        match preset {
            "python" => vec![
                "python3".into(),
                "-m".into(),
                "py_compile".into(),
                path.display().to_string(),
            ],
            "sh" => vec!["bash".into(), "-n".into(), path.display().to_string()],
            "systemd" => vec![
                "systemd-analyze".into(),
                "verify".into(),
                path.display().to_string(),
            ],
            "nginx" => vec![
                "sudo".into(),
                "nginx".into(),
                "-t".into(),
                "-c".into(),
                "/etc/nginx/nginx.conf".into(),
            ],
            _ => return Ok(None),
        }
    } else if let Some(custom) = custom {
        shlex::split(custom)
            .ok_or_else(|| {
                HandlerError::new("invalid_payload", "validator has invalid shell quoting")
            })?
            .into_iter()
            .map(|part| {
                if part == "{file}" {
                    path.display().to_string()
                } else {
                    part
                }
            })
            .collect()
    } else {
        return Ok(None);
    };

    if argv.is_empty() {
        return Ok(None);
    }
    let output = Command::new(&argv[0])
        .args(&argv[1..])
        .output()
        .map_err(|e| HandlerError::new("validation_failed", format!("validation failed: {e}")))?;
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        let tail = [stdout, stderr]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" / ");
        return Err(HandlerError::new(
            "validation_failed",
            if tail.is_empty() {
                "validation failed".into()
            } else {
                format!("validation failed: {tail}")
            },
        ));
    }
    Ok(Some(argv))
}

fn unified_diff(old: &str, new: &str, path: &Path) -> String {
    let diff = TextDiff::from_lines(old, new);
    let mut out = format!("--- {}\n+++ {}\n", path.display(), path.display());
    for change in diff.iter_all_changes() {
        let prefix = match change.tag() {
            ChangeTag::Delete => "-",
            ChangeTag::Insert => "+",
            ChangeTag::Equal => " ",
        };
        out.push_str(prefix);
        out.push_str(change.value());
        if !change.value().ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

fn backup_path(target: &Path, backup_dir: Option<&str>) -> PathBuf {
    let base = backup_dir
        .map(PathBuf::from)
        .unwrap_or_else(|| target.parent().unwrap_or(Path::new(".")).to_owned());
    base.join(format!(
        "{}.bak.{}",
        target
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file"),
        now_stamp()
    ))
}

fn atomic_replace(
    target: &Path,
    content: &str,
    original_meta: Option<&fs::Metadata>,
) -> Result<(), HandlerError> {
    let parent = target
        .parent()
        .ok_or_else(|| HandlerError::new("write_failed", "target has no parent directory"))?;
    fs::create_dir_all(parent)
        .map_err(|e| HandlerError::new("write_failed", format!("failed creating parent: {e}")))?;

    let temp = loop {
        let candidate = parent.join(format!(
            ".{}.sentinel0-{:016x}.tmp",
            target
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file"),
            rand::rng().random::<u64>()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(mut file) => {
                file.write_all(content.as_bytes()).map_err(|e| {
                    HandlerError::new("write_failed", format!("failed writing temp file: {e}"))
                })?;
                if let Some(meta) = original_meta {
                    fs::set_permissions(&candidate, fs::Permissions::from_mode(meta.mode()))
                        .map_err(|e| {
                            HandlerError::new(
                                "write_failed",
                                format!("failed preserving permissions: {e}"),
                            )
                        })?;

                    let candidate_meta = fs::metadata(&candidate).map_err(|e| {
                        HandlerError::new(
                            "write_failed",
                            format!("failed reading replacement metadata: {e}"),
                        )
                    })?;
                    if candidate_meta.uid() != meta.uid() || candidate_meta.gid() != meta.gid() {
                        nix::unistd::chown(
                            &candidate,
                            Some(nix::unistd::Uid::from_raw(meta.uid())),
                            Some(nix::unistd::Gid::from_raw(meta.gid())),
                        )
                        .map_err(|e| {
                            HandlerError::new(
                                "write_failed",
                                format!("failed preserving owner/group: {e}"),
                            )
                        })?;
                    }
                }
                file.sync_all().map_err(|e| {
                    HandlerError::new("write_failed", format!("failed syncing temp file: {e}"))
                })?;
                break candidate;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(HandlerError::new(
                    "write_failed",
                    format!("failed creating temp file: {error}"),
                ));
            }
        }
    };

    let result = fs::rename(&temp, target)
        .map_err(|e| HandlerError::new("write_failed", format!("atomic replace failed: {e}")));
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn sudo_replace(
    target: &Path,
    staged: &Path,
    original_meta: Option<&fs::Metadata>,
) -> Result<(), HandlerError> {
    let parent = target
        .parent()
        .ok_or_else(|| HandlerError::new("write_failed", "target has no parent directory"))?;
    let temp = parent.join(format!(
        ".{}.sentinel0-{:016x}.tmp",
        target
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file"),
        rand::rng().random::<u64>()
    ));

    let mut install = Command::new("sudo");
    install.arg("install");
    if let Some(meta) = original_meta {
        install
            .arg("-m")
            .arg(format!("{:o}", meta.mode() & 0o7777))
            .arg("-o")
            .arg(meta.uid().to_string())
            .arg("-g")
            .arg(meta.gid().to_string());
    }
    let status = install
        .arg(staged)
        .arg(&temp)
        .status()
        .map_err(|e| HandlerError::new("write_failed", format!("sudo install failed: {e}")))?;
    if !status.success() {
        return Err(HandlerError::new("write_failed", "sudo install failed"));
    }
    let status = Command::new("sudo")
        .arg("mv")
        .arg("-f")
        .arg(&temp)
        .arg(target)
        .status()
        .map_err(|e| HandlerError::new("write_failed", format!("sudo mv failed: {e}")))?;
    if !status.success() {
        let _ = Command::new("sudo").arg("rm").arg("-f").arg(&temp).status();
        return Err(HandlerError::new(
            "write_failed",
            "sudo atomic rename failed",
        ));
    }
    Ok(())
}

pub fn edit(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let started = Instant::now();
    let raw_path = require_str(payload, "path")?;
    let mode = require_str(payload, "mode")?;
    validate_payload(mode, payload)?;

    let Some(target) = policy.resolve_path(raw_path, true) else {
        let writable = policy
            .file_ops_paths
            .iter()
            .filter(|entry| entry.access == crate::policy::FileAccess::ReadWrite)
            .map(|entry| Value::String(entry.path.display().to_string()))
            .collect::<Vec<_>>();
        return Err(HandlerError::with_details(
            "path_not_allowed",
            "edit requires a path under a file_ops entry with access: rw",
            Map::from_iter([("writable_paths".into(), Value::Array(writable))]),
        ));
    };

    let create = payload
        .get("create")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let exists = target.exists();
    if !exists && !create {
        return Err(HandlerError::new(
            "target_not_found",
            "file does not exist; pass create=true to create it",
        ));
    }
    let original = if exists {
        fs::read_to_string(&target)
            .map_err(|e| HandlerError::new("read_failed", format!("failed reading target: {e}")))?
    } else {
        String::new()
    };
    let original_meta = if exists {
        fs::metadata(&target).ok()
    } else {
        None
    };

    let (updated, changed) = transform(mode, &original, payload)?;
    let allow_no_change = payload
        .get("allow_no_change")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if updated == original && !allow_no_change {
        return Err(HandlerError::new(
            "no_effective_change",
            "the edit produced no changes",
        ));
    }

    let staging = crate::staging::staging_root(&policy.upload_base)
        .map_err(|e| HandlerError::new("write_failed", e.to_string()))?;
    let staged = staging.join(format!(
        "edit-{}-{:016x}",
        target
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file"),
        rand::rng().random::<u64>()
    ));
    fs::write(&staged, &updated)
        .map_err(|e| HandlerError::new("write_failed", format!("failed staging edit: {e}")))?;

    let validator = match run_validator(&staged, payload) {
        Ok(value) => value,
        Err(error) => {
            let _ = fs::remove_file(&staged);
            return Err(error);
        }
    };
    let want_diff = payload
        .get("diff")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let diff_text = want_diff.then(|| unified_diff(&original, &updated, &target));
    let dry_run = payload
        .get("dry_run")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let mut backup = None;
    if !dry_run {
        if exists {
            let backup_path =
                backup_path(&target, payload.get("backup_dir").and_then(Value::as_str));
            if let Some(parent) = backup_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| HandlerError::new("backup_failed", e.to_string()))?;
            }
            fs::copy(&target, &backup_path).map_err(|e| {
                HandlerError::new("backup_failed", format!("failed creating backup: {e}"))
            })?;
            backup = Some(backup_path);
        }

        let sudo = payload
            .get("sudo")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if sudo {
            sudo_replace(&target, &staged, original_meta.as_ref())?;
        } else {
            atomic_replace(&target, &updated, original_meta.as_ref())?;
        }
    }

    let _ = fs::remove_file(&staged);
    let duration = (started.elapsed().as_secs_f64() * 100.0).round() / 100.0;
    let mut result = BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("path".into(), Value::String(target.display().to_string())),
        ("mode".into(), Value::String(mode.into())),
        (
            "sudo".into(),
            Value::Bool(
                payload
                    .get("sudo")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            ),
        ),
        ("output".into(), Value::String("OK".into())),
        ("duration".into(), Value::from(duration)),
        ("returncode".into(), Value::from(0)),
        ("changed".into(), Value::from(changed as u64)),
    ]);
    if dry_run {
        result.insert("dry_run".into(), Value::Bool(true));
    }
    if let Some(path) = backup {
        result.insert("backup".into(), Value::String(path.display().to_string()));
    }
    if let Some(diff) = diff_text {
        result.insert("diff".into(), Value::String(diff));
    }
    if let Some(validator) = validator {
        result.insert(
            "validator".into(),
            Value::Array(validator.into_iter().map(Value::String).collect()),
        );
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{FileAccess, FileOpsPath};
    use tempfile::tempdir;

    fn policy(root: &Path) -> Policy {
        Policy {
            file_ops_paths: vec![FileOpsPath {
                path: root.to_owned(),
                access: FileAccess::ReadWrite,
            }],
            ..Policy::default()
        }
    }

    #[test]
    fn edit_updates_mtime_instead_of_preserving_stale_source_timestamp() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("x.txt");
        fs::write(&path, "old").unwrap();
        let before = fs::metadata(&path).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));

        let result = edit(
            &policy(dir.path()),
            &Map::from_iter([
                ("path".into(), Value::String(path.display().to_string())),
                ("mode".into(), Value::String("write".into())),
                ("new_text".into(), Value::String("new".into())),
            ]),
        )
        .unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(fs::read_to_string(&path).unwrap(), "new");
        let after = fs::metadata(&path).unwrap().modified().unwrap();
        assert!(after > before, "successful edit preserved stale mtime");
    }

    #[test]
    fn yaml_validation_rejects_bad_candidate_without_touching_target() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("x.yaml");
        fs::write(&path, "ok: true\n").unwrap();
        let error = edit(
            &policy(dir.path()),
            &Map::from_iter([
                ("path".into(), Value::String(path.display().to_string())),
                ("mode".into(), Value::String("write".into())),
                ("new_text".into(), Value::String("bad: [\n".into())),
                ("validator_preset".into(), Value::String("yaml".into())),
            ]),
        )
        .unwrap_err();
        assert_eq!(error.code, "validation_failed");
        assert_eq!(fs::read_to_string(&path).unwrap(), "ok: true\n");
    }
}
