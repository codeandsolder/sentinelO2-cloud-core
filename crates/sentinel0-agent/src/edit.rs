use crate::{
    handler_error::{HandlerError, HandlerResult, require_str},
    policy::Policy,
    process_output::read_bounded_sync,
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
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MODES: &[&str] = &[
    "replace",
    "regex",
    "replace-block",
    "append",
    "prepend",
    "write",
];
const VALIDATOR_TIMEOUT: Duration = Duration::from_secs(30);
const VALIDATOR_CAPTURE_BYTES: usize = 256 * 1024;
const PRESETS: &[&str] = &["nginx", "json", "python", "sh", "yaml", "systemd", "toml"];
const SYSTEMD_UNIT_SUFFIXES: &[&str] = &[
    "service",
    "socket",
    "device",
    "mount",
    "automount",
    "swap",
    "target",
    "path",
    "timer",
    "slice",
    "scope",
];
const SYSTEMD_UNSUPPORTED_MESSAGE: &str = "validator_preset=systemd verifies unit files (.service, .socket, .timer and the other unit types) with systemd-analyze, which cannot check a drop-in or other file on its own. Nothing was changed. Apply the edit without the validator, then run systemctl daemon-reload and check the unit with systemctl cat and systemctl show.";

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
    if let Some(preset) = payload.get("validator_preset").and_then(Value::as_str)
        && !PRESETS.contains(&preset)
    {
        return Err(HandlerError::new(
            "invalid_payload",
            format!("validator_preset must be one of: {}", PRESETS.join(", ")),
        ));
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
                .is_none_or(str::is_empty)
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
                    .is_none_or(str::is_empty)
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
            Some('\\') | None => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
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

fn internal_validator(
    preset: Option<&str>,
    path: &Path,
) -> Result<Option<Vec<String>>, HandlerError> {
    let Some(preset) = preset else {
        return Ok(None);
    };
    let tag = match preset {
        "json" => {
            let text = fs::read_to_string(path)
                .map_err(|e| HandlerError::new("validation_failed", e.to_string()))?;
            serde_json::from_str::<Value>(&text).map_err(|e| {
                HandlerError::new("validation_failed", format!("validation failed: {e}"))
            })?;
            "internal:json"
        }
        "yaml" => {
            let text = fs::read_to_string(path)
                .map_err(|e| HandlerError::new("validation_failed", e.to_string()))?;
            yaml_serde::from_str::<yaml_serde::Value>(&text).map_err(|e| {
                HandlerError::new("validation_failed", format!("validation failed: {e}"))
            })?;
            "internal:yaml"
        }
        "toml" => {
            let text = fs::read_to_string(path)
                .map_err(|e| HandlerError::new("validation_failed", e.to_string()))?;
            toml::from_str::<toml::Value>(&text).map_err(|e| {
                HandlerError::new("validation_failed", format!("validation failed: {e}"))
            })?;
            "internal:toml"
        }
        _ => return Ok(None),
    };
    Ok(Some(vec![tag.into(), path.display().to_string()]))
}

fn validator_argv(
    policy: &Policy,
    path: &Path,
    preset: Option<&str>,
    custom: Option<&str>,
) -> Result<Option<Vec<String>>, HandlerError> {
    let argv = if let Some(preset) = preset {
        match preset {
            "python" => vec![
                policy.tooling.command("uv").display().to_string(),
                "run".into(),
                "--no-project".into(),
                "--python".into(),
                policy.tooling.uv_python.clone(),
                "python".into(),
                "-m".into(),
                "py_compile".into(),
                path.display().to_string(),
            ],
            "sh" => vec![
                policy.tooling.command("bash").display().to_string(),
                "-n".into(),
                path.display().to_string(),
            ],
            "systemd" => vec![
                policy
                    .tooling
                    .command("systemd-analyze")
                    .display()
                    .to_string(),
                "verify".into(),
                path.display().to_string(),
            ],
            "nginx" => vec![
                policy.tooling.command("sudo").display().to_string(),
                "-n".into(),
                policy.tooling.command("nginx").display().to_string(),
                "-t".into(),
                "-c".into(),
                "/etc/nginx/nginx.conf".into(),
            ],
            _ => return Ok(None),
        }
    } else if let Some(custom) = custom {
        if let Some(kind) = policy.tooling.direct_python_violation(custom) {
            return Err(HandlerError::new(
                "use_uv",
                format!("direct {kind} validator is disabled; invoke it through uv"),
            ));
        }
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
    Ok((!argv.is_empty()).then_some(argv))
}

fn timed_out_validator_error(child: &mut std::process::Child, pid: u32) -> HandlerError {
    let mut cleanup_error = None;
    #[cfg(unix)]
    {
        let process_group = nix::unistd::Pid::from_raw(pid.cast_signed());
        if let Err(error) =
            nix::sys::signal::killpg(process_group, nix::sys::signal::Signal::SIGKILL)
            && error != nix::errno::Errno::ESRCH
        {
            let message = format!("failed killing validator process group: {error}");
            tracing::warn!(%message);
            cleanup_error = Some(message);
        }
    }
    if let Err(error) = child.wait() {
        let message = format!("failed reaping timed-out validator: {error}");
        tracing::warn!(%message);
        cleanup_error.get_or_insert(message);
    }
    let details = cleanup_error
        .map(|error| Map::from_iter([("cleanup_error".into(), Value::String(error))]))
        .unwrap_or_default();
    HandlerError::with_details(
        "validation_timeout",
        format!("validator exceeded {} seconds", VALIDATOR_TIMEOUT.as_secs()),
        details,
    )
}

fn execute_validator(policy: &Policy, argv: &[String]) -> Result<(), HandlerError> {
    use wait_timeout::ChildExt as _;

    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    policy.tooling.configure_std(&mut command)?;
    let mut child = command.spawn().map_err(|e| {
        HandlerError::new(
            "validation_failed",
            format!("failed starting validator {:?}: {e}", argv[0]),
        )
    })?;
    let pid = child.id();
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| HandlerError::new("validation_failed", "validator stdout was not piped"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| HandlerError::new("validation_failed", "validator stderr was not piped"))?;
    let per_stream = VALIDATOR_CAPTURE_BYTES / 2;
    let stdout_reader = std::thread::spawn(move || read_bounded_sync(stdout, per_stream));
    let stderr_reader = std::thread::spawn(move || read_bounded_sync(stderr, per_stream));
    let Some(status) = child.wait_timeout(VALIDATOR_TIMEOUT).map_err(|e| {
        HandlerError::new("validation_failed", format!("validator wait failed: {e}"))
    })?
    else {
        return Err(timed_out_validator_error(&mut child, pid));
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| HandlerError::new("validation_failed", "validator stdout reader panicked"))?
        .map_err(|e| {
            HandlerError::new("validation_failed", format!("validator stdout failed: {e}"))
        })?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| HandlerError::new("validation_failed", "validator stderr reader panicked"))?
        .map_err(|e| {
            HandlerError::new("validation_failed", format!("validator stderr failed: {e}"))
        })?;
    if status.success() {
        return Ok(());
    }
    let tail = [
        stdout.rendered_trimmed_lossy(),
        stderr.rendered_trimmed_lossy(),
    ]
    .into_iter()
    .filter(|text| !text.is_empty())
    .collect::<Vec<_>>()
    .join(" / ");
    Err(HandlerError::new(
        "validation_failed",
        if tail.is_empty() {
            "validation failed".into()
        } else {
            format!("validation failed: {tail}")
        },
    ))
}

fn run_validator(
    policy: &Policy,
    staged_path: &Path,
    target_path: &Path,
    payload: &Map<String, Value>,
) -> Result<Option<Vec<String>>, HandlerError> {
    let preset = payload.get("validator_preset").and_then(Value::as_str);
    if let Some(result) = internal_validator(preset, staged_path)? {
        return Ok(Some(result));
    }

    let mut systemd_verify_dir = None;
    let validate_path = if preset == Some("systemd") {
        let suffix = target_path.extension().and_then(|value| value.to_str());
        if suffix.is_none_or(|value| !SYSTEMD_UNIT_SUFFIXES.contains(&value)) {
            return Err(HandlerError::new(
                "validator_unsupported",
                SYSTEMD_UNSUPPORTED_MESSAGE,
            ));
        }
        let verify_dir = tempfile::Builder::new()
            .prefix("sx-verify-")
            .tempdir()
            .map_err(|error| {
                HandlerError::new(
                    "validation_failed",
                    format!("failed creating systemd verification directory: {error}"),
                )
            })?;
        let filename = target_path.file_name().ok_or_else(|| {
            HandlerError::new("validator_unsupported", SYSTEMD_UNSUPPORTED_MESSAGE)
        })?;
        let verify_path = verify_dir.path().join(filename);
        fs::copy(staged_path, &verify_path).map_err(|error| {
            HandlerError::new(
                "validation_failed",
                format!("failed staging systemd verification copy: {error}"),
            )
        })?;
        systemd_verify_dir = Some(verify_dir);
        verify_path
    } else {
        staged_path.to_owned()
    };

    let custom = payload.get("validator").and_then(Value::as_str);
    let Some(argv) = validator_argv(policy, &validate_path, preset, custom)? else {
        return Ok(None);
    };
    execute_validator(policy, &argv)?;
    drop(systemd_verify_dir);
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

struct RemoveFileOnDrop(PathBuf);

impl Drop for RemoveFileOnDrop {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_file(&self.0)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(
                path = %self.0.display(),
                %error,
                "failed cleaning temporary edit file"
            );
        }
    }
}

fn backup_path(target: &Path, backup_dir: Option<&str>) -> PathBuf {
    let base = backup_dir.map_or_else(
        || target.parent().unwrap_or_else(|| Path::new(".")).to_owned(),
        PathBuf::from,
    );
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

    let (temp, mut file) = loop {
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
            Ok(file) => break (candidate, file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(HandlerError::new(
                    "write_failed",
                    format!("failed creating temp file: {error}"),
                ));
            }
        }
    };
    let _temp_cleanup = RemoveFileOnDrop(temp.clone());

    file.write_all(content.as_bytes())
        .map_err(|e| HandlerError::new("write_failed", format!("failed writing temp file: {e}")))?;
    if let Some(meta) = original_meta {
        fs::set_permissions(&temp, fs::Permissions::from_mode(meta.mode())).map_err(|e| {
            HandlerError::new(
                "write_failed",
                format!("failed preserving permissions: {e}"),
            )
        })?;

        let candidate_meta = fs::metadata(&temp).map_err(|e| {
            HandlerError::new(
                "write_failed",
                format!("failed reading replacement metadata: {e}"),
            )
        })?;
        if candidate_meta.uid() != meta.uid() || candidate_meta.gid() != meta.gid() {
            nix::unistd::chown(
                &temp,
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
    file.sync_all()
        .map_err(|e| HandlerError::new("write_failed", format!("failed syncing temp file: {e}")))?;
    drop(file);
    fs::rename(&temp, target)
        .map_err(|e| HandlerError::new("write_failed", format!("atomic replace failed: {e}")))
}

fn sudo_replace(
    policy: &Policy,
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

    let mut install = Command::new(policy.tooling.command("sudo"));
    install.arg("-n").arg("install");
    if let Some(meta) = original_meta {
        install
            .arg("-m")
            .arg(format!("{:o}", meta.mode() & 0o7777))
            .arg("-o")
            .arg(meta.uid().to_string())
            .arg("-g")
            .arg(meta.gid().to_string());
    }
    policy.tooling.configure_std(&mut install)?;
    let status = install
        .arg(staged)
        .arg(&temp)
        .status()
        .map_err(|e| HandlerError::new("write_failed", format!("sudo install failed: {e}")))?;
    let cleanup_temp = |context: &str| -> Option<String> {
        let mut cleanup = Command::new(policy.tooling.command("sudo"));
        cleanup.args(["-n", "rm", "-f"]).arg(&temp);
        if let Err(error) = policy.tooling.configure_std(&mut cleanup) {
            return Some(format!("{context}; temp cleanup setup failed: {error}"));
        }
        match cleanup.status() {
            Ok(status) if status.success() => None,
            Ok(status) => Some(format!(
                "{context}; temp cleanup command exited with {status}"
            )),
            Err(error) => Some(format!("{context}; temp cleanup failed: {error}")),
        }
    };

    if !status.success() {
        let message =
            cleanup_temp("sudo install failed").unwrap_or_else(|| "sudo install failed".into());
        return Err(HandlerError::new("write_failed", message));
    }

    let mut mv = Command::new(policy.tooling.command("sudo"));
    mv.args(["-n", "mv", "-f"]).arg(&temp).arg(target);
    policy.tooling.configure_std(&mut mv)?;
    let status = mv
        .status()
        .map_err(|e| HandlerError::new("write_failed", format!("sudo mv failed: {e}")))?;
    if !status.success() {
        let message = cleanup_temp("sudo atomic rename failed")
            .unwrap_or_else(|| "sudo atomic rename failed".into());
        return Err(HandlerError::new("write_failed", message));
    }
    Ok(())
}

struct EditTarget {
    path: PathBuf,
    existed: bool,
    original: String,
    metadata: Option<fs::Metadata>,
}

fn load_edit_target(
    policy: &Policy,
    payload: &Map<String, Value>,
    raw_path: &str,
) -> Result<EditTarget, HandlerError> {
    let Some(path) = policy.resolve_path(raw_path, true) else {
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
    let existed = path.exists();
    if !existed && !create {
        return Err(HandlerError::new(
            "target_not_found",
            "file does not exist; pass create=true to create it",
        ));
    }
    let original = if existed {
        fs::read_to_string(&path)
            .map_err(|e| HandlerError::new("read_failed", format!("failed reading target: {e}")))?
    } else {
        String::new()
    };
    let metadata = existed.then(|| fs::metadata(&path).ok()).flatten();
    Ok(EditTarget {
        path,
        existed,
        original,
        metadata,
    })
}

fn stage_edit(policy: &Policy, target: &Path, updated: &str) -> Result<PathBuf, HandlerError> {
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
    fs::write(&staged, updated)
        .map_err(|e| HandlerError::new("write_failed", format!("failed staging edit: {e}")))?;
    Ok(staged)
}

fn apply_edit(
    policy: &Policy,
    target: &EditTarget,
    staged: &Path,
    updated: &str,
    payload: &Map<String, Value>,
) -> Result<Option<PathBuf>, HandlerError> {
    if payload
        .get("dry_run")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(None);
    }
    let backup = if target.existed {
        let backup = backup_path(
            &target.path,
            payload.get("backup_dir").and_then(Value::as_str),
        );
        if let Some(parent) = backup.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| HandlerError::new("backup_failed", e.to_string()))?;
        }
        fs::copy(&target.path, &backup).map_err(|e| {
            HandlerError::new("backup_failed", format!("failed creating backup: {e}"))
        })?;
        Some(backup)
    } else {
        None
    };
    let sudo = payload
        .get("sudo")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if sudo {
        sudo_replace(policy, &target.path, staged, target.metadata.as_ref())?;
    } else {
        atomic_replace(&target.path, updated, target.metadata.as_ref())?;
    }
    Ok(backup)
}

struct EditOutcome<'a> {
    target: &'a Path,
    mode: &'a str,
    changed: usize,
    dry_run: bool,
    backup: Option<PathBuf>,
    diff: Option<String>,
    validator: Option<Vec<String>>,
    sudo: bool,
    duration: f64,
}

fn edit_result(outcome: EditOutcome<'_>) -> BTreeMap<String, Value> {
    let mut result = BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        (
            "path".into(),
            Value::String(outcome.target.display().to_string()),
        ),
        ("mode".into(), Value::String(outcome.mode.into())),
        ("sudo".into(), Value::Bool(outcome.sudo)),
        ("output".into(), Value::String("OK".into())),
        ("duration".into(), Value::from(outcome.duration)),
        ("returncode".into(), Value::from(0)),
        (
            "changed".into(),
            Value::from(u64::try_from(outcome.changed).unwrap_or(u64::MAX)),
        ),
    ]);
    if outcome.dry_run {
        result.insert("dry_run".into(), Value::Bool(true));
    }
    if let Some(path) = outcome.backup {
        result.insert("backup".into(), Value::String(path.display().to_string()));
    }
    if let Some(diff) = outcome.diff {
        result.insert("diff".into(), Value::String(diff));
    }
    if let Some(validator) = outcome.validator {
        result.insert(
            "validator".into(),
            Value::Array(validator.into_iter().map(Value::String).collect()),
        );
    }
    result
}

/// # Errors
/// Returns an error when the edit request is invalid, disallowed, or cannot be applied safely.
pub fn edit(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let started = Instant::now();
    let raw_path = require_str(payload, "path")?;
    let mode = require_str(payload, "mode")?;
    validate_payload(mode, payload)?;
    let target = load_edit_target(policy, payload, raw_path)?;

    let (updated, changed) = transform(mode, &target.original, payload)?;
    let allow_no_change = payload
        .get("allow_no_change")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if updated == target.original && !allow_no_change {
        return Err(HandlerError::new(
            "no_effective_change",
            "the edit produced no changes",
        ));
    }

    let staged = stage_edit(policy, &target.path, &updated)?;
    let _staged_cleanup = RemoveFileOnDrop(staged.clone());
    let validator = run_validator(policy, &staged, &target.path, payload)?;
    let diff = payload
        .get("diff")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        .then(|| unified_diff(&target.original, &updated, &target.path));
    let dry_run = payload
        .get("dry_run")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let backup = apply_edit(policy, &target, &staged, &updated, payload)?;
    let sudo = payload
        .get("sudo")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let duration = (started.elapsed().as_secs_f64() * 100.0).round() / 100.0;
    Ok(edit_result(EditOutcome {
        target: &target.path,
        mode,
        changed,
        dry_run,
        backup,
        diff,
        validator,
        sudo,
        duration,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{FileAccess, FileOpsPath};
    use crate::test_support::{TestError as _, TestResult, TestValue as _};
    use tempfile::tempdir;

    fn policy(root: &Path) -> Policy {
        Policy {
            upload_base: root.to_owned(),
            file_ops_paths: vec![FileOpsPath {
                path: root.to_owned(),
                access: FileAccess::ReadWrite,
            }],
            ..Policy::default()
        }
    }

    #[test]
    fn edit_updates_mtime_instead_of_preserving_stale_source_timestamp() -> TestResult {
        let dir = tempdir().test_value()?;
        let path = dir.path().join("x.txt");
        fs::write(&path, "old").test_value()?;
        let before = fs::metadata(&path).test_value()?.modified().test_value()?;
        std::thread::sleep(std::time::Duration::from_millis(20));

        let result = edit(
            &policy(dir.path()),
            &Map::from_iter([
                ("path".into(), Value::String(path.display().to_string())),
                ("mode".into(), Value::String("write".into())),
                ("new_text".into(), Value::String("new".into())),
            ]),
        )
        .test_value()?;
        assert_eq!(result["ok"], true);
        assert_eq!(fs::read_to_string(&path).test_value()?, "new");
        let after = fs::metadata(&path).test_value()?.modified().test_value()?;
        assert!(after > before, "successful edit preserved stale mtime");

        Ok(())
    }

    #[test]
    fn dry_run_create_leaves_target_tree_absent() -> TestResult {
        let dir = tempdir().test_value()?;
        let target = dir.path().join("share").join("nested").join("new.txt");

        let result = edit(
            &policy(dir.path()),
            &Map::from_iter([
                ("path".into(), Value::String(target.display().to_string())),
                ("mode".into(), Value::String("write".into())),
                ("new_text".into(), Value::String("hello\n".into())),
                ("create".into(), Value::Bool(true)),
                ("dry_run".into(), Value::Bool(true)),
                ("diff".into(), Value::Bool(true)),
            ]),
        )
        .test_value()?;

        assert_eq!(result["dry_run"], true);
        assert!(result["diff"].as_str().test_value()?.contains("+hello"));
        assert!(!target.exists());
        assert!(!target.parent().test_value()?.exists());
        assert!(!dir.path().join("share").exists());

        Ok(())
    }

    #[test]
    fn dry_run_existing_file_leaves_no_sibling_temp_or_content_change() -> TestResult {
        let dir = tempdir().test_value()?;
        let target = dir.path().join("config.yaml");
        fs::write(&target, "a: 1\n").test_value()?;
        let before = fs::read_dir(dir.path())
            .test_value()?
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .collect::<std::collections::BTreeSet<_>>();

        let result = edit(
            &policy(dir.path()),
            &Map::from_iter([
                ("path".into(), Value::String(target.display().to_string())),
                ("mode".into(), Value::String("write".into())),
                ("new_text".into(), Value::String("a: 2\n".into())),
                ("dry_run".into(), Value::Bool(true)),
                ("diff".into(), Value::Bool(true)),
            ]),
        )
        .test_value()?;

        assert_eq!(result["dry_run"], true);
        assert_eq!(fs::read_to_string(&target).test_value()?, "a: 1\n");

        let after = fs::read_dir(dir.path())
            .test_value()?
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .filter(|name| name != crate::staging::STAGING_DIRNAME)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(after, before);

        Ok(())
    }

    #[test]
    fn missing_target_without_create_leaves_parents_absent() -> TestResult {
        let dir = tempdir().test_value()?;
        let target = dir.path().join("missing").join("x.txt");
        let error = edit(
            &policy(dir.path()),
            &Map::from_iter([
                ("path".into(), Value::String(target.display().to_string())),
                ("mode".into(), Value::String("write".into())),
                ("new_text".into(), Value::String("x\n".into())),
            ]),
        )
        .test_error()?;

        assert_eq!(error.code, "target_not_found");
        assert!(!target.parent().test_value()?.exists());

        Ok(())
    }

    #[test]
    fn yaml_validation_rejects_bad_candidate_without_touching_target() -> TestResult {
        let dir = tempdir().test_value()?;
        let path = dir.path().join("x.yaml");
        fs::write(&path, "ok: true\n").test_value()?;
        let error = edit(
            &policy(dir.path()),
            &Map::from_iter([
                ("path".into(), Value::String(path.display().to_string())),
                ("mode".into(), Value::String("write".into())),
                ("new_text".into(), Value::String("bad: [\n".into())),
                ("validator_preset".into(), Value::String("yaml".into())),
            ]),
        )
        .test_error()?;
        assert_eq!(error.code, "validation_failed");
        assert_eq!(fs::read_to_string(&path).test_value()?, "ok: true\n");
        let staging = dir.path().join(crate::staging::STAGING_DIRNAME);
        let leftovers = fs::read_dir(staging)
            .test_value()?
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .collect::<Vec<_>>();
        assert!(
            leftovers.is_empty(),
            "failed edit leaked staged files: {leftovers:?}"
        );

        Ok(())
    }

    #[test]
    fn systemd_drop_in_is_refused_before_the_target_changes() -> TestResult {
        let dir = tempdir().test_value()?;
        let dropin_dir = dir.path().join("demo.service.d");
        fs::create_dir(&dropin_dir).test_value()?;
        let path = dropin_dir.join("20-demo.conf");
        fs::write(&path, "[Service]\nTasksMax=128\n").test_value()?;

        let error = edit(
            &policy(dir.path()),
            &Map::from_iter([
                ("path".into(), Value::String(path.display().to_string())),
                ("mode".into(), Value::String("write".into())),
                (
                    "new_text".into(),
                    Value::String("[Service]\nTasksMax=256\n".into()),
                ),
                ("validator_preset".into(), Value::String("systemd".into())),
            ]),
        )
        .test_error()?;

        assert_eq!(error.code, "validator_unsupported");
        assert!(error.message.contains("daemon-reload"));
        assert_eq!(
            fs::read_to_string(&path).test_value()?,
            "[Service]\nTasksMax=128\n"
        );
        Ok(())
    }

    #[test]
    fn systemd_unit_is_verified_under_its_real_filename() -> TestResult {
        let dir = tempdir().test_value()?;
        let policy = policy(dir.path());
        if !policy.tooling.command("systemd-analyze").exists() {
            return Ok(());
        }
        let path = dir.path().join("sxtest.service");
        fs::write(
            &path,
            "[Unit]\nDescription=old\n[Service]\nType=oneshot\nExecStart=/bin/true\n",
        )
        .test_value()?;

        let result = edit(
            &policy,
            &Map::from_iter([
                ("path".into(), Value::String(path.display().to_string())),
                ("mode".into(), Value::String("write".into())),
                (
                    "new_text".into(),
                    Value::String(
                        "[Unit]\nDescription=new\n[Service]\nType=oneshot\nExecStart=/bin/true\n"
                            .into(),
                    ),
                ),
                ("validator_preset".into(), Value::String("systemd".into())),
                ("dry_run".into(), Value::Bool(true)),
            ]),
        )
        .test_value()?;

        let validator = result["validator"].as_array().test_value()?;
        assert!(
            validator
                .last()
                .and_then(Value::as_str)
                .is_some_and(|value| value.ends_with("/sxtest.service"))
        );
        assert_eq!(
            fs::read_to_string(&path).test_value()?,
            "[Unit]\nDescription=old\n[Service]\nType=oneshot\nExecStart=/bin/true\n"
        );
        Ok(())
    }
}
