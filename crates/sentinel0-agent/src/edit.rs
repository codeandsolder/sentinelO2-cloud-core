use crate::{
    fsutil::install_file_no_replace,
    handler_error::{HandlerError, HandlerResult, require_str},
    policy::Policy,
    process_runner::{self, ProcessFailure, ProcessGroupKill, ProcessOutcome, RunOptions},
};
use rand::RngExt;
use regex::RegexBuilder;
use serde_json::{Map, Value};
use similar::{ChangeTag, TextDiff};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
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

fn validate_secret_payload(payload: &Map<String, Value>) -> Result<(), HandlerError> {
    let secret = payload
        .get("secret")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let leaky_option = payload
        .get("diff")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || payload
            .get("create")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        || payload.get("backup_dir").is_some();
    if secret && leaky_option {
        return Err(HandlerError::new(
            "invalid_payload",
            "secret edits take no diff, create or backup_dir",
        ));
    }
    Ok(())
}

fn validate_payload(mode: &str, payload: &Map<String, Value>) -> Result<(), HandlerError> {
    if !MODES.contains(&mode) {
        return Err(HandlerError::new(
            "invalid_payload",
            format!("mode must be one of: {}", MODES.join(", ")),
        ));
    }
    validate_secret_payload(payload)?;
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
                "-c".into(),
                "import pathlib,sys; p=sys.argv[1]; compile(pathlib.Path(p).read_bytes(), p, 'exec')".into(),
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

fn process_failure(code: &'static str, context: &str, failure: ProcessFailure) -> HandlerError {
    match failure {
        ProcessFailure::Setup(error) => error,
        ProcessFailure::Spawn(error) => HandlerError::new(code, format!("{context}: {error}")),
        ProcessFailure::Capture {
            error,
            cleanup_error,
        } => {
            let mut details = Map::new();
            if let Some(cleanup_error) = cleanup_error {
                details.insert("cleanup_error".into(), Value::String(cleanup_error));
            }
            HandlerError::with_details(code, format!("{context}: {error}"), details)
        }
    }
}

fn uses_sudo(policy: &Policy, argv: &[String]) -> bool {
    let Some(program) = argv.first() else {
        return false;
    };
    let configured = policy.tooling.command("sudo");
    Path::new(program) == configured
        || (Path::new(program).file_name() == Some(std::ffi::OsStr::new("sudo"))
            && configured.file_name() == Some(std::ffi::OsStr::new("sudo")))
}

fn killer_for_argv(policy: &Policy, argv: &[String]) -> Result<ProcessGroupKill, HandlerError> {
    if uses_sudo(policy, argv) {
        ProcessGroupKill::sudo(policy)
    } else {
        Ok(ProcessGroupKill::Direct)
    }
}

async fn execute_validator(policy: &Policy, argv: &[String]) -> Result<(), HandlerError> {
    let outcome = process_runner::run_argv_with_limits(
        policy,
        argv,
        VALIDATOR_TIMEOUT,
        RunOptions {
            cwd: None,
            env: None,
            sanitize_bash_startup: false,
            stdin: None,
            stdout_limit: VALIDATOR_CAPTURE_BYTES / 2,
            stderr_limit: VALIDATOR_CAPTURE_BYTES / 2,
            killer: killer_for_argv(policy, argv)?,
        },
    )
    .await
    .map_err(|failure| {
        process_failure(
            "validation_failed",
            &format!(
                "failed running validator {:?}",
                argv.first().map_or("", String::as_str)
            ),
            failure,
        )
    })?;

    match outcome {
        ProcessOutcome::Completed { captured, .. } if captured.status.success() => Ok(()),
        ProcessOutcome::Completed { captured, .. } => {
            let tail = [
                captured.stdout.rendered_trimmed_lossy(),
                captured.stderr.rendered_trimmed_lossy(),
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
        ProcessOutcome::TimedOut {
            captured,
            cleanup_error,
            ..
        } => {
            let mut details = Map::new();
            if captured.left_running {
                details.insert("left_running".into(), Value::Bool(true));
            }
            if let Some(cleanup_error) = cleanup_error {
                details.insert("cleanup_error".into(), Value::String(cleanup_error));
            }
            Err(HandlerError::with_details(
                "validation_timeout",
                format!("validator exceeded {} seconds", VALIDATOR_TIMEOUT.as_secs()),
                details,
            ))
        }
    }
}

async fn run_validator(
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
    execute_validator(policy, &argv).await?;
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

fn write_in_place_preserving_metadata(target: &Path, content: &str) -> Result<(), HandlerError> {
    let mut destination = OpenOptions::new()
        .write(true)
        .open(target)
        .map_err(|error| {
            HandlerError::new(
                if error.kind() == std::io::ErrorKind::PermissionDenied {
                    "not_writable"
                } else {
                    "write_failed"
                },
                format!("cannot write target in place while preserving ownership: {error}"),
            )
        })?;
    destination.write_all(content.as_bytes()).map_err(|error| {
        HandlerError::new(
            "write_failed",
            format!("failed writing target in place: {error}"),
        )
    })?;
    destination
        .set_len(u64::try_from(content.len()).unwrap_or(u64::MAX))
        .map_err(|error| {
            HandlerError::new(
                "write_failed",
                format!("failed truncating in-place edit: {error}"),
            )
        })?;
    destination.sync_all().map_err(|error| {
        HandlerError::new(
            "write_failed",
            format!("failed syncing in-place edit: {error}"),
        )
    })?;
    Ok(())
}

#[derive(Debug)]
struct CreatedParentDirs {
    paths: Vec<PathBuf>,
    keep: bool,
}

impl CreatedParentDirs {
    fn keep(&mut self) {
        self.keep = true;
    }
}

impl Drop for CreatedParentDirs {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        for path in self.paths.iter().rev() {
            match fs::remove_dir(path) {
                Ok(()) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
                    ) => {}
                Err(error) => tracing::warn!(
                    path = %path.display(),
                    %error,
                    "failed cleaning parent directory created by failed edit"
                ),
            }
        }
    }
}

fn missing_parent_dirs(parent: &Path) -> Result<Vec<PathBuf>, HandlerError> {
    let mut missing = Vec::new();
    let mut cursor = Some(parent);
    while let Some(path) = cursor {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if !metadata.is_dir() {
                    return Err(HandlerError::new(
                        "write_failed",
                        format!("parent path is not a directory: {}", path.display()),
                    ));
                }
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(path.to_owned());
                cursor = path.parent();
            }
            Err(error) => {
                return Err(HandlerError::new(
                    "write_failed",
                    format!("failed inspecting parent {}: {error}", path.display()),
                ));
            }
        }
    }
    Ok(missing)
}

fn ensure_parent_dirs(parent: &Path) -> Result<CreatedParentDirs, HandlerError> {
    let missing = missing_parent_dirs(parent)?;
    let mut created = CreatedParentDirs {
        paths: Vec::new(),
        keep: false,
    };
    for path in missing.into_iter().rev() {
        match fs::create_dir(&path) {
            Ok(()) => created.paths.push(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists && path.is_dir() => {}
            Err(error) => {
                return Err(HandlerError::new(
                    "write_failed",
                    format!("failed creating parent {}: {error}", path.display()),
                ));
            }
        }
    }
    Ok(created)
}

fn require_recovery_backup(recovery_backup: Option<&Path>) -> Result<&Path, HandlerError> {
    recovery_backup.ok_or_else(|| {
        HandlerError::new(
            "write_failed",
            "cannot preserve target ownership with an atomic replacement, and no recovery backup exists; retry with sudo=true or allow a backup",
        )
    })
}

fn atomic_replace(
    target: &Path,
    content: &str,
    original_meta: Option<&fs::Metadata>,
    recovery_backup: Option<&Path>,
) -> Result<bool, HandlerError> {
    let parent = target
        .parent()
        .ok_or_else(|| HandlerError::new("write_failed", "target has no parent directory"))?;
    let mut created_parents = ensure_parent_dirs(parent)?;
    let prefix = format!(
        ".{}.sentinel0-",
        target
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("file")
    );
    let mut builder = tempfile::Builder::new();
    builder.prefix(&prefix).suffix(".tmp");
    if original_meta.is_none() {
        // Match OpenOptions::create_new's ordinary creation mode for new files;
        // tempfile defaults to 0600 unless told otherwise. The process umask is
        // still applied by tempfile when the file is created.
        builder.permissions(fs::Permissions::from_mode(0o666));
    }
    let mut temp = builder.tempfile_in(parent).map_err(|error| {
        HandlerError::new(
            "write_failed",
            format!("failed creating temp file: {error}"),
        )
    })?;

    temp.write_all(content.as_bytes())
        .map_err(|e| HandlerError::new("write_failed", format!("failed writing temp file: {e}")))?;
    if let Some(meta) = original_meta {
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(meta.mode()))
            .map_err(|e| {
                HandlerError::new(
                    "write_failed",
                    format!("failed preserving permissions: {e}"),
                )
            })?;

        let candidate_meta = temp.as_file().metadata().map_err(|e| {
            HandlerError::new(
                "write_failed",
                format!("failed reading replacement metadata: {e}"),
            )
        })?;
        if candidate_meta.uid() != meta.uid() || candidate_meta.gid() != meta.gid() {
            match nix::unistd::chown(
                temp.path(),
                Some(nix::unistd::Uid::from_raw(meta.uid())),
                Some(nix::unistd::Gid::from_raw(meta.gid())),
            ) {
                Ok(()) => {}
                Err(nix::errno::Errno::EPERM | nix::errno::Errno::EACCES)
                    if target.exists() && !target.is_symlink() =>
                {
                    // Replacing the inode here would hand the file to the agent.
                    // In-place mutation is only safe when a durable recovery copy
                    // already exists: otherwise a short write or crash can corrupt
                    // a secret/no-backup edit irreversibly.
                    let recovery_backup = require_recovery_backup(recovery_backup)?;
                    if let Err(mut write_error) =
                        write_in_place_preserving_metadata(target, content)
                    {
                        let recovery = fs::read_to_string(recovery_backup)
                            .map_err(|error| format!("failed reading recovery backup: {error}"))
                            .and_then(|original| {
                                write_in_place_preserving_metadata(target, &original).map_err(
                                    |error| {
                                        format!(
                                            "failed restoring recovery backup: {}",
                                            error.message
                                        )
                                    },
                                )
                            });
                        match recovery {
                            Ok(()) => write_error
                                .message
                                .push_str("; original content restored from recovery backup"),
                            Err(recovery_error) => {
                                write_error.message.push_str("; recovery also failed: ");
                                write_error.message.push_str(&recovery_error);
                            }
                        }
                        return Err(write_error);
                    }
                    return Ok(true);
                }
                Err(error) => {
                    return Err(HandlerError::new(
                        "write_failed",
                        format!("failed preserving owner/group: {error}"),
                    ));
                }
            }
        }
    }
    temp.as_file()
        .sync_all()
        .map_err(|e| HandlerError::new("write_failed", format!("failed syncing temp file: {e}")))?;
    if original_meta.is_none() {
        install_file_no_replace(temp.path(), target).map_err(|error| {
            HandlerError::new(
                if error.kind() == io::ErrorKind::AlreadyExists {
                    "target_exists"
                } else {
                    "write_failed"
                },
                format!("atomic create failed: {error}"),
            )
        })?;
    } else {
        temp.persist(target).map_err(|error| {
            HandlerError::new(
                "write_failed",
                format!("atomic replace failed: {}", error.error),
            )
        })?;
    }
    created_parents.keep();
    Ok(false)
}

const SUDO_EDIT_TIMEOUT: Duration = Duration::from_secs(60);

async fn run_sudo_edit_step(
    policy: &Policy,
    argv: &[String],
    context: &str,
) -> Result<(), HandlerError> {
    let outcome = process_runner::run_argv(
        policy,
        argv,
        SUDO_EDIT_TIMEOUT,
        None,
        None,
        ProcessGroupKill::sudo(policy)?,
    )
    .await
    .map_err(|failure| process_failure("write_failed", context, failure))?;
    match outcome {
        ProcessOutcome::Completed { captured, .. } if captured.status.success() => Ok(()),
        ProcessOutcome::Completed { captured, .. } => {
            let tail = [
                captured.stdout.rendered_trimmed_lossy(),
                captured.stderr.rendered_trimmed_lossy(),
            ]
            .into_iter()
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>()
            .join(" / ");
            Err(HandlerError::new(
                "write_failed",
                if tail.is_empty() {
                    format!("{context}: {}", captured.status)
                } else {
                    format!("{context}: {}: {tail}", captured.status)
                },
            ))
        }
        ProcessOutcome::TimedOut {
            captured,
            cleanup_error,
            ..
        } => {
            let mut details = Map::new();
            if captured.left_running {
                details.insert("left_running".into(), Value::Bool(true));
            }
            if let Some(cleanup_error) = cleanup_error {
                details.insert("cleanup_error".into(), Value::String(cleanup_error));
            }
            Err(HandlerError::with_details(
                "write_failed",
                format!(
                    "{context}: timed out after {} seconds",
                    SUDO_EDIT_TIMEOUT.as_secs()
                ),
                details,
            ))
        }
    }
}

async fn cleanup_sudo_temp(policy: &Policy, temp: &Path, context: &str) -> Option<String> {
    let argv = vec![
        policy.tooling.command("sudo").display().to_string(),
        "-n".into(),
        "rm".into(),
        "-f".into(),
        "--".into(),
        temp.display().to_string(),
    ];
    run_sudo_edit_step(policy, &argv, context)
        .await
        .err()
        .map(|error| error.message)
}

async fn cleanup_sudo_dirs(policy: &Policy, dirs: &[PathBuf]) {
    for dir in dirs {
        let argv = vec![
            policy.tooling.command("sudo").display().to_string(),
            "-n".into(),
            "rmdir".into(),
            "--".into(),
            dir.display().to_string(),
        ];
        if let Err(error) = run_sudo_edit_step(policy, &argv, "sudo parent cleanup failed").await {
            tracing::debug!(
                path = %dir.display(),
                message = %error.message,
                "leaving parent directory that is no longer safely removable"
            );
        }
    }
}

async fn run_sudo_commit_new(
    policy: &Policy,
    source: &Path,
    target: &Path,
) -> Result<(), HandlerError> {
    let executable = std::env::current_exe().map_err(|error| {
        HandlerError::new(
            "write_failed",
            format!("failed locating agent executable for privileged commit: {error}"),
        )
    })?;
    let argv = vec![
        policy.tooling.command("sudo").display().to_string(),
        "-n".into(),
        executable.display().to_string(),
        "--internal-commit-new".into(),
        source.display().to_string(),
        target.display().to_string(),
    ];
    let outcome = process_runner::run_argv(
        policy,
        &argv,
        SUDO_EDIT_TIMEOUT,
        None,
        None,
        ProcessGroupKill::sudo(policy)?,
    )
    .await
    .map_err(|failure| process_failure("write_failed", "sudo atomic create failed", failure))?;

    match outcome {
        ProcessOutcome::Completed { captured, .. } if captured.status.success() => Ok(()),
        ProcessOutcome::Completed { captured, .. } if captured.status.code() == Some(17) => {
            Err(HandlerError::new(
                "target_exists",
                format!(
                    "{} appeared while the edit was being prepared",
                    target.display()
                ),
            ))
        }
        ProcessOutcome::Completed { captured, .. } => Err(HandlerError::new(
            "write_failed",
            format!("sudo atomic create failed: {}", captured.status),
        )),
        ProcessOutcome::TimedOut {
            captured,
            cleanup_error,
            ..
        } => {
            let mut details = Map::new();
            if captured.left_running {
                details.insert("left_running".into(), Value::Bool(true));
            }
            if let Some(cleanup_error) = cleanup_error {
                details.insert("cleanup_error".into(), Value::String(cleanup_error));
            }
            Err(HandlerError::with_details(
                "write_failed",
                "sudo atomic create timed out",
                details,
            ))
        }
    }
}

async fn sudo_replace(
    policy: &Policy,
    target: &Path,
    staged: &Path,
    original_meta: Option<&fs::Metadata>,
) -> Result<(), HandlerError> {
    let parent = target
        .parent()
        .ok_or_else(|| HandlerError::new("write_failed", "target has no parent directory"))?;
    let new_dirs = if original_meta.is_none() {
        missing_parent_dirs(parent)?
    } else {
        Vec::new()
    };
    let temp = parent.join(format!(
        ".{}.sentinel0-{:016x}.tmp",
        target
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file"),
        rand::rng().random::<u64>()
    ));

    let mut install = vec![
        policy.tooling.command("sudo").display().to_string(),
        "-n".into(),
        "install".into(),
    ];
    if let Some(meta) = original_meta {
        install.extend([
            "-m".into(),
            format!("{:o}", meta.mode() & 0o7777),
            "-o".into(),
            meta.uid().to_string(),
            "-g".into(),
            meta.gid().to_string(),
        ]);
    } else {
        install.extend(["-D".into(), "-m".into(), "600".into()]);
    }
    install.extend([
        "--".into(),
        staged.display().to_string(),
        temp.display().to_string(),
    ]);
    if let Err(error) = run_sudo_edit_step(policy, &install, "sudo install failed").await {
        let cleanup = cleanup_sudo_temp(policy, &temp, "sudo install temp cleanup failed").await;
        cleanup_sudo_dirs(policy, &new_dirs).await;
        let message = error.message;
        return Err(HandlerError::new(
            "write_failed",
            cleanup.map_or_else(
                || message.clone(),
                |cleanup| format!("{message}; {cleanup}"),
            ),
        ));
    }

    if original_meta.is_none() {
        if let Err(error) = run_sudo_commit_new(policy, &temp, target).await {
            let cleanup = cleanup_sudo_temp(policy, &temp, "sudo create temp cleanup failed").await;
            cleanup_sudo_dirs(policy, &new_dirs).await;
            let message = error.message;
            return Err(HandlerError::new(
                error.code,
                cleanup.map_or_else(
                    || message.clone(),
                    |cleanup| format!("{message}; {cleanup}"),
                ),
            ));
        }
        if let Some(cleanup) =
            cleanup_sudo_temp(policy, &temp, "sudo committed-temp cleanup failed").await
        {
            tracing::warn!(%cleanup, "sudo create committed but adjacent temp cleanup failed");
        }
        return Ok(());
    }

    let mv = vec![
        policy.tooling.command("sudo").display().to_string(),
        "-n".into(),
        "mv".into(),
        "-f".into(),
        "--".into(),
        temp.display().to_string(),
        target.display().to_string(),
    ];
    if let Err(error) = run_sudo_edit_step(policy, &mv, "sudo atomic rename failed").await {
        let cleanup = cleanup_sudo_temp(policy, &temp, "sudo rename temp cleanup failed").await;
        let message = error.message;
        return Err(HandlerError::new(
            "write_failed",
            cleanup.map_or_else(
                || message.clone(),
                |cleanup| format!("{message}; {cleanup}"),
            ),
        ));
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

fn stage_edit(
    policy: &Policy,
    target: &Path,
    updated: &str,
) -> Result<tempfile::NamedTempFile, HandlerError> {
    let staging = crate::staging::staging_root(&policy.upload_base)
        .map_err(|e| HandlerError::new("write_failed", e.to_string()))?;
    let prefix = format!(
        "edit-{}-",
        target
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("file")
    );
    let mut staged = tempfile::Builder::new()
        .prefix(&prefix)
        .tempfile_in(staging)
        .map_err(|e| HandlerError::new("write_failed", format!("failed staging edit: {e}")))?;
    staged
        .write_all(updated.as_bytes())
        .map_err(|e| HandlerError::new("write_failed", format!("failed staging edit: {e}")))?;
    Ok(staged)
}

async fn apply_edit(
    policy: &Policy,
    target: &EditTarget,
    staged: &Path,
    updated: &str,
    payload: &Map<String, Value>,
) -> Result<(Option<PathBuf>, bool), HandlerError> {
    if payload
        .get("dry_run")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Ok((None, false));
    }
    let secret = payload
        .get("secret")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let no_backup = payload
        .get("no_backup")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let backup = if target.existed && !secret && !no_backup {
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
    let in_place = if sudo {
        sudo_replace(policy, &target.path, staged, target.metadata.as_ref()).await?;
        false
    } else {
        atomic_replace(
            &target.path,
            updated,
            target.metadata.as_ref(),
            backup.as_deref(),
        )?
    };
    Ok((backup, in_place))
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
    in_place: bool,
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
    if outcome.in_place {
        result.insert("in_place".into(), Value::Bool(true));
        result.insert(
            "metadata".into(),
            Value::String(
                "written in place to keep the file's owner, group and permissions".into(),
            ),
        );
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
pub async fn edit(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
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
    let validator = run_validator(policy, staged.path(), &target.path, payload).await?;
    let diff = payload
        .get("diff")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        .then(|| unified_diff(&target.original, &updated, &target.path));
    let dry_run = payload
        .get("dry_run")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let (backup, in_place) = apply_edit(policy, &target, staged.path(), &updated, payload).await?;
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
        in_place,
        duration,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{FileAccess, FileOpsPath};
    use crate::test_support::{TestError as _, TestResult, TestValue as _};
    use tempfile::tempdir;

    #[test]
    fn create_commit_never_overwrites_a_target_that_appeared_after_validation() -> TestResult {
        let dir = tempdir().test_value()?;
        let target = dir.path().join("new.txt");
        fs::write(&target, "racer won").test_value()?;
        let error = atomic_replace(&target, "our content", None, None).test_error()?;
        assert_eq!(error.code, "target_exists");
        assert_eq!(fs::read_to_string(target).test_value()?, "racer won");
        Ok(())
    }

    #[test]
    fn missing_parent_dirs_are_deepest_first_and_stop_at_existing_parent() -> TestResult {
        let dir = tempdir().test_value()?;
        let existing = dir.path().join("existing");
        fs::create_dir(&existing).test_value()?;
        let a = existing.join("a");
        let b = a.join("b");
        assert_eq!(missing_parent_dirs(&b).test_value()?, vec![b, a]);
        Ok(())
    }

    #[test]
    fn failed_create_removes_only_parent_directories_it_created() -> TestResult {
        let dir = tempdir().test_value()?;
        let preserved = dir.path().join("preserved");
        fs::create_dir(&preserved).test_value()?;
        let created_root = preserved.join("new-a");
        let target = created_root.join("new-b").join("x".repeat(300));
        let error = atomic_replace(&target, "data", None, None).test_error()?;
        assert_eq!(error.code, "write_failed");
        assert!(preserved.exists());
        assert!(!created_root.exists());
        Ok(())
    }

    #[test]
    fn in_place_fallback_requires_a_durable_recovery_copy() -> TestResult {
        let error = require_recovery_backup(None).test_error()?;
        assert_eq!(error.code, "write_failed");
        assert!(error.message.contains("sudo=true"));
        let path = Path::new("/tmp/recovery-copy");
        assert_eq!(require_recovery_backup(Some(path)).test_value()?, path);
        Ok(())
    }

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

    async fn wait_for_path(path: &Path) -> bool {
        for _ in 0..150 {
            if path.exists() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    async fn wait_for_process_exit(pid: i32) -> bool {
        for _ in 0..150 {
            let stat = fs::read_to_string(format!("/proc/{pid}/stat"));
            match stat {
                Err(error) if error.kind() == io::ErrorKind::NotFound => return true,
                Ok(stat) => {
                    if stat
                        .rsplit_once(") ")
                        .is_some_and(|(_, tail)| tail.starts_with('Z'))
                    {
                        return true;
                    }
                }
                Err(_) => {}
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    #[tokio::test]
    async fn cancelling_edit_kills_escaped_validator_descendants_before_any_commit() -> TestResult {
        let dir = tempdir().test_value()?;
        let target = dir.path().join("target.txt");
        fs::write(&target, "old").test_value()?;
        let child_pid = dir.path().join("escaped.pid");
        let validator = dir.path().join("validator.sh");
        fs::write(
            &validator,
            format!(
                "#!/bin/sh\nsetsid sh -c 'echo $$ > {}; sleep 30' &\nwhile [ ! -s {} ]; do sleep 0.01; done\nsleep 30\n",
                child_pid.display(),
                child_pid.display(),
            ),
        )
        .test_value()?;
        fs::set_permissions(&validator, fs::Permissions::from_mode(0o755)).test_value()?;

        let task_policy = policy(dir.path());
        let payload = Map::from_iter([
            ("path".into(), Value::String(target.display().to_string())),
            ("mode".into(), Value::String("write".into())),
            ("new_text".into(), Value::String("new".into())),
            (
                "validator".into(),
                Value::String(validator.display().to_string()),
            ),
        ]);
        let task = tokio::spawn(async move { edit(&task_policy, &payload).await });
        assert!(
            wait_for_path(&child_pid).await,
            "validator descendant never started"
        );
        let pid = fs::read_to_string(&child_pid)
            .test_value()?
            .trim()
            .parse::<i32>()
            .test_value()?;

        task.abort();
        let _ = task.await;
        let exited = wait_for_process_exit(pid).await;
        if !exited {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        assert!(
            exited,
            "escaped validator descendant {pid} survived edit cancellation"
        );
        assert_eq!(fs::read_to_string(&target).test_value()?, "old");
        Ok(())
    }

    #[tokio::test]
    async fn failed_validator_for_create_leaves_no_target_parent_directories() -> TestResult {
        let dir = tempdir().test_value()?;
        let parent = dir.path().join("new-a/new-b");
        let target = parent.join("target.txt");
        let error = edit(
            &policy(dir.path()),
            &Map::from_iter([
                ("path".into(), Value::String(target.display().to_string())),
                ("mode".into(), Value::String("write".into())),
                ("new_text".into(), Value::String("new".into())),
                ("create".into(), Value::Bool(true)),
                ("validator".into(), Value::String("/bin/false".into())),
            ]),
        )
        .await
        .test_error()?;
        assert_eq!(error.code, "validation_failed");
        assert!(!parent.exists());
        assert!(!target.exists());
        Ok(())
    }

    #[tokio::test]
    async fn edit_updates_mtime_instead_of_preserving_stale_source_timestamp() -> TestResult {
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
        .await
        .test_value()?;
        assert_eq!(result["ok"], true);
        assert_eq!(fs::read_to_string(&path).test_value()?, "new");
        let after = fs::metadata(&path).test_value()?.modified().test_value()?;
        assert!(after > before, "successful edit preserved stale mtime");

        Ok(())
    }

    #[tokio::test]
    async fn dry_run_create_leaves_target_tree_absent() -> TestResult {
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
        .await
        .test_value()?;

        assert_eq!(result["dry_run"], true);
        assert!(result["diff"].as_str().test_value()?.contains("+hello"));
        assert!(!target.exists());
        assert!(!target.parent().test_value()?.exists());
        assert!(!dir.path().join("share").exists());

        Ok(())
    }

    #[tokio::test]
    async fn dry_run_existing_file_leaves_no_sibling_temp_or_content_change() -> TestResult {
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
        .await
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

    #[tokio::test]
    async fn missing_target_without_create_leaves_parents_absent() -> TestResult {
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
        .await
        .test_error()?;

        assert_eq!(error.code, "target_not_found");
        assert!(!target.parent().test_value()?.exists());

        Ok(())
    }

    #[tokio::test]
    async fn yaml_validation_rejects_bad_candidate_without_touching_target() -> TestResult {
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
        .await
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
    fn in_place_fallback_keeps_inode_and_metadata() -> TestResult {
        let dir = tempdir().test_value()?;
        let path = dir.path().join("owned.txt");
        fs::write(&path, "old content that is longer\n").test_value()?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).test_value()?;
        let before = fs::metadata(&path).test_value()?;

        write_in_place_preserving_metadata(&path, "new\n").test_value()?;

        let after = fs::metadata(&path).test_value()?;
        assert_eq!(fs::read_to_string(&path).test_value()?, "new\n");
        assert_eq!(after.ino(), before.ino());
        assert_eq!(after.uid(), before.uid());
        assert_eq!(after.gid(), before.gid());
        assert_eq!(after.mode() & 0o7777, before.mode() & 0o7777);
        Ok(())
    }

    #[tokio::test]
    async fn systemd_drop_in_is_refused_before_the_target_changes() -> TestResult {
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
        .await
        .test_error()?;

        assert_eq!(error.code, "validator_unsupported");
        assert!(error.message.contains("daemon-reload"));
        assert_eq!(
            fs::read_to_string(&path).test_value()?,
            "[Service]\nTasksMax=128\n"
        );
        Ok(())
    }

    #[tokio::test]
    async fn systemd_unit_is_verified_under_its_real_filename() -> TestResult {
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
        .await
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

    #[tokio::test]
    async fn secret_edit_writes_without_backup_or_diff_and_rejects_leaky_options() -> TestResult {
        let dir = tempdir().test_value()?;
        let path = dir.path().join("secret.env");
        fs::write(&path, "TOKEN=old\n").test_value()?;
        let result = edit(
            &policy(dir.path()),
            &Map::from_iter([
                ("path".into(), Value::String(path.display().to_string())),
                ("mode".into(), Value::String("write".into())),
                ("new_text".into(), Value::String("TOKEN=new\n".into())),
                ("secret".into(), Value::Bool(true)),
            ]),
        )
        .await
        .test_value()?;
        assert_eq!(fs::read_to_string(&path).test_value()?, "TOKEN=new\n");
        assert!(!result.contains_key("backup"));
        assert!(!result.contains_key("diff"));
        assert_eq!(
            fs::read_dir(dir.path())
                .test_value()?
                .filter_map(Result::ok)
                .filter(|e| e.file_name().to_string_lossy().contains(".bak."))
                .count(),
            0
        );

        for (key, value) in [
            ("diff", Value::Bool(true)),
            ("create", Value::Bool(true)),
            (
                "backup_dir",
                Value::String(dir.path().display().to_string()),
            ),
        ] {
            let error = edit(
                &policy(dir.path()),
                &Map::from_iter([
                    ("path".into(), Value::String(path.display().to_string())),
                    ("mode".into(), Value::String("write".into())),
                    ("new_text".into(), Value::String("TOKEN=x\n".into())),
                    ("secret".into(), Value::Bool(true)),
                    (key.into(), value),
                ]),
            )
            .await
            .test_error()?;
            assert_eq!(error.code, "invalid_payload");
        }
        Ok(())
    }
}
