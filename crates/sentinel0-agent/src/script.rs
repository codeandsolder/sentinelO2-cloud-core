use crate::{
    handler_error::{HandlerError, HandlerResult, require_str},
    jobs::BACKGROUND_TIMEOUT_MAX_SECS,
    policy::Policy,
    process_output::{
        CapturedOutput, TimedOutOutput, add_capture_metadata, add_timeout_metadata,
        combine_cleanup_errors, merged_output, process_result, timeout_output,
    },
    process_runner::{self, ProcessFailure, ProcessGroupKill, ProcessOutcome},
    staging,
};
use serde_json::{Map, Value};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};
use tempfile::TempDir;
use tokio::fs as async_fs;

const TIMEOUT_MIN: u64 = 1;
const TIMEOUT_MAX: u64 = 600;

fn staging_oserror(error: &std::io::Error, path: &Path) -> HandlerError {
    match error.raw_os_error() {
        Some(code) if code == nix::libc::ENOSPC => HandlerError::new(
            "no_space",
            format!(
                "cannot prepare the work area at {:?}: the filesystem is full ([Errno {code}]). This is a host condition, not a policy or allowlist issue. Free space on that filesystem (or point upload_base at one with room) and retry. A full disk also makes the agent itself unstable, so unrelated errors on this host may clear up once space is available.",
                path.display()
            ),
        ),
        Some(code) if matches!(code, nix::libc::EACCES | nix::libc::EPERM) => HandlerError::new(
            "permission_denied",
            format!(
                "cannot prepare the work area at {:?}: the agent OS user lacks write permission ([Errno {code}]). Grant that user write access to the staging directory, or set upload_base to a directory it can write.",
                path.display()
            ),
        ),
        Some(code) if code == nix::libc::EROFS => HandlerError::new(
            "read_only_filesystem",
            format!(
                "cannot prepare the work area at {:?}: the filesystem is mounted read-only ([Errno {code}]). Set upload_base to a writable location.",
                path.display()
            ),
        ),
        _ => HandlerError::new(
            "staging_failed",
            format!(
                "cannot prepare the work area at {:?}: {error}",
                path.display()
            ),
        ),
    }
}

fn with_cleanup_detail(mut error: HandlerError, cleanup: Option<String>) -> HandlerError {
    if let Some(cleanup) = cleanup {
        let existing = error
            .details
            .remove("cleanup_error")
            .and_then(|value| value.as_str().map(str::to_owned));
        if let Some(combined) = combine_cleanup_errors(existing, Some(cleanup)) {
            error
                .details
                .insert("cleanup_error".into(), Value::String(combined));
        }
    }
    error
}

fn safe_filename(filename: Option<&str>, extension: &str) -> String {
    filename
        .and_then(|name| Path::new(name).file_name())
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && !name.starts_with('.'))
        .map_or_else(|| format!("script.{extension}"), str::to_owned)
}

#[derive(Clone, Copy)]
struct ResultMeta<'a> {
    interpreter: &'a str,
    sudo: bool,
    cwd: Option<&'a str>,
    cleanup: bool,
}

fn result(
    meta: ResultMeta<'_>,
    command: Vec<String>,
    output: String,
    duration: f64,
    returncode: i32,
) -> BTreeMap<String, Value> {
    let mut out = process_result(output, duration, returncode);
    out.extend([
        ("interpreter".into(), Value::String(meta.interpreter.into())),
        ("sudo".into(), Value::Bool(meta.sudo)),
        (
            "cwd".into(),
            meta.cwd
                .map_or(Value::Null, |value| Value::String(value.into())),
        ),
        ("cleanup".into(), Value::Bool(meta.cleanup)),
        (
            "command".into(),
            Value::Array(command.into_iter().map(Value::String).collect()),
        ),
    ]);
    out
}

fn build_command(
    policy: &Policy,
    interpreter: &str,
    script: &Path,
    args: &[String],
    env: &Map<String, Value>,
    sudo: bool,
    cwd: Option<&str>,
) -> (Vec<String>, Option<PathBuf>) {
    let mut inner = match interpreter {
        "bash" => vec![
            policy.tooling.command("bash").display().to_string(),
            script.display().to_string(),
        ],
        // Keep the old Hub's interpreter value compatible, but never invoke
        // Python directly. uv owns interpreter selection/install semantics.
        "python3" => vec![
            policy.tooling.command("uv").display().to_string(),
            "run".into(),
            "--no-project".into(),
            "--python".into(),
            policy.tooling.uv_python.clone(),
            "python".into(),
            script.display().to_string(),
        ],
        "pwsh" => vec![
            policy.tooling.command("pwsh").display().to_string(),
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-File".into(),
            script.display().to_string(),
        ],
        "powershell" => vec![
            policy.tooling.command("powershell").display().to_string(),
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-File".into(),
            script.display().to_string(),
        ],
        _ => Vec::new(),
    };
    inner.extend(args.iter().cloned());

    if sudo {
        let sudo = policy.tooling.command("sudo").display().to_string();
        let mut sudo_prefix = vec![sudo, "-n".into()];
        let mut env_names = env.keys().collect::<Vec<_>>();
        env_names.sort_unstable();
        sudo_prefix.extend(
            env_names
                .into_iter()
                .map(|name| format!("--preserve-env={name}")),
        );
        if let Some(cwd) = cwd {
            let mut command_argv = sudo_prefix;
            command_argv.extend([
                policy.tooling.command("bash").display().to_string(),
                "-c".into(),
                "cd \"$1\" || { echo \"sentinelx: cannot enter $1\" >&2; exit 126; }; shift; exec \"$@\"".into(),
                "bash".into(),
                cwd.into(),
            ]);
            command_argv.extend(inner);
            (command_argv, None)
        } else {
            let mut command_argv = sudo_prefix;
            command_argv.extend(inner);
            (command_argv, None)
        }
    } else {
        (inner, cwd.map(PathBuf::from))
    }
}

struct ScriptRequest<'a> {
    interpreter: &'a str,
    content: &'a str,
    args: Vec<String>,
    env: Map<String, Value>,
    timeout_seconds: u64,
    sudo: bool,
    cleanup: bool,
    cwd: Option<&'a str>,
    filename: String,
}

fn parse_script_request(payload: &Map<String, Value>) -> Result<ScriptRequest<'_>, HandlerError> {
    let interpreter = require_str(payload, "interpreter")?;
    if !["bash", "python3", "powershell", "pwsh"].contains(&interpreter) {
        return Err(HandlerError::new(
            "invalid_payload",
            "interpreter must be one of: bash, python3, powershell, pwsh",
        ));
    }
    let content = require_str(payload, "content")?;
    let args = match payload.get("args") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value.as_str().map(str::to_owned).ok_or_else(|| {
                    HandlerError::new("invalid_payload", "'args' must be a list of strings")
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => {
            return Err(HandlerError::new(
                "invalid_payload",
                "'args' must be a list of strings",
            ));
        }
    };
    let env = match payload.get("env") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(values)) if values.values().all(Value::is_string) => values.clone(),
        _ => {
            return Err(HandlerError::new(
                "invalid_payload",
                "'env' must be dict[str, str]",
            ));
        }
    };
    let background = payload
        .get("background")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let max_timeout = if background {
        BACKGROUND_TIMEOUT_MAX_SECS
    } else {
        TIMEOUT_MAX
    };
    let timeout_seconds = payload.get("timeout").and_then(Value::as_u64).unwrap_or(60);
    if !(TIMEOUT_MIN..=max_timeout).contains(&timeout_seconds) {
        return Err(HandlerError::new(
            "invalid_payload",
            format!("timeout must be between {TIMEOUT_MIN} and {max_timeout} seconds"),
        ));
    }
    let sudo = payload
        .get("sudo")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let cleanup = payload
        .get("cleanup")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let cwd = payload.get("cwd").and_then(Value::as_str);
    let extension = match interpreter {
        "bash" => "sh",
        "python3" => "py",
        "powershell" | "pwsh" => "ps1",
        _ => "txt",
    };
    Ok(ScriptRequest {
        interpreter,
        content,
        args,
        env,
        timeout_seconds,
        sudo,
        cleanup,
        cwd,
        filename: safe_filename(payload.get("filename").and_then(Value::as_str), extension),
    })
}

struct StagedScript {
    workdir: TempDir,
    script_path: PathBuf,
}

impl StagedScript {
    fn script_path(&self) -> &Path {
        &self.script_path
    }

    fn finish_error(self, error: HandlerError, cleanup: bool) -> HandlerError {
        if cleanup {
            let cleanup_error = self
                .workdir
                .close()
                .err()
                .map(|error| format!("failed cleaning script workdir after error: {error}"));
            with_cleanup_detail(error, cleanup_error)
        } else {
            let script_path = self.script_path.display().to_string();
            let workdir = self.workdir.keep().display().to_string();
            let mut error = error;
            error
                .details
                .insert("script_path".into(), Value::String(script_path));
            error
                .details
                .insert("workdir".into(), Value::String(workdir));
            error
        }
    }

    fn finalize(
        self,
        mut outcome: BTreeMap<String, Value>,
        cleanup: bool,
    ) -> BTreeMap<String, Value> {
        if cleanup {
            if let Err(error) = self.workdir.close() {
                tracing::warn!(%error, "failed cleaning script workdir");
                let existing = outcome
                    .remove("cleanup_error")
                    .and_then(|value| value.as_str().map(str::to_owned));
                if let Some(combined) = combine_cleanup_errors(
                    existing,
                    Some(format!("failed cleaning script workdir: {error}")),
                ) {
                    outcome.insert("cleanup_error".into(), Value::String(combined));
                }
            }
        } else {
            let script_path = self.script_path.display().to_string();
            let workdir = self.workdir.keep().display().to_string();
            outcome.insert("script_path".into(), Value::String(script_path));
            outcome.insert("workdir".into(), Value::String(workdir));
        }
        outcome
    }
}

async fn prepare_script(
    policy: &Policy,
    request: &ScriptRequest<'_>,
) -> Result<StagedScript, HandlerError> {
    let upload_base = policy.upload_base.clone();
    let upload_base_for_error = upload_base.clone();
    let root = tokio::task::spawn_blocking(move || staging::staging_root(&upload_base))
        .await
        .map_err(|error| {
            HandlerError::new(
                "internal_error",
                format!("staging setup task failed: {error}"),
            )
        })?
        .map_err(|error| staging_oserror(&error, &upload_base_for_error))?;
    let root_for_error = root.clone();
    let workdir = tokio::task::spawn_blocking(move || {
        tempfile::Builder::new()
            .prefix("script_job_")
            .tempdir_in(root)
    })
    .await
    .map_err(|error| {
        HandlerError::new(
            "internal_error",
            format!("temporary script directory task failed: {error}"),
        )
    })?
    .map_err(|error| staging_oserror(&error, &root_for_error))?;
    let script_path = workdir.path().join(&request.filename);
    let staged = StagedScript {
        workdir,
        script_path,
    };

    if let Err(error) = async_fs::write(staged.script_path(), request.content).await {
        let error = staging_oserror(&error, staged.script_path());
        return Err(staged.finish_error(error, request.cleanup));
    }
    if let Err(error) =
        async_fs::set_permissions(staged.script_path(), fs::Permissions::from_mode(0o700)).await
    {
        let error = staging_oserror(&error, staged.script_path());
        return Err(staged.finish_error(error, request.cleanup));
    }
    Ok(staged)
}

fn script_spawn_error(error: &std::io::Error, cwd: Option<&Path>) -> HandlerError {
    if let Some(cwd) = cwd {
        match error.kind() {
            std::io::ErrorKind::PermissionDenied => {
                return HandlerError::new(
                    "permission_denied",
                    format!(
                        "cannot enter cwd {:?}: the agent's OS user lacks permission to change into it. Being inside an rw file_ops path does not grant Unix access. Either run with sudo=true -- the directory is then entered after elevation -- or grant the agent's user execute (+x) on it and its parents.",
                        cwd.display()
                    ),
                );
            }
            std::io::ErrorKind::NotFound if !cwd.exists() => {
                return HandlerError::new(
                    "not_found",
                    format!("cwd {:?} does not exist.", cwd.display()),
                );
            }
            std::io::ErrorKind::NotADirectory if !cwd.is_dir() => {
                return HandlerError::new(
                    "not_a_directory",
                    format!("cwd {:?} is not a directory.", cwd.display()),
                );
            }
            _ => {}
        }
    }
    let code = if error.kind() == std::io::ErrorKind::NotFound {
        "interpreter_missing"
    } else {
        "io_error"
    };
    HandlerError::new(code, format!("failed starting script: {error}"))
}

fn completed_result(
    request: &ScriptRequest<'_>,
    command_argv: Vec<String>,
    duration: f64,
    captured: &CapturedOutput,
) -> BTreeMap<String, Value> {
    let mut outcome = result(
        ResultMeta {
            interpreter: request.interpreter,
            sudo: request.sudo,
            cwd: request.cwd,
            cleanup: request.cleanup,
        },
        command_argv,
        merged_output(captured),
        duration,
        captured.status.code().unwrap_or(-1),
    );
    add_capture_metadata(&mut outcome, &captured.stdout, &captured.stderr);
    outcome
}

fn timed_out_result(
    request: &ScriptRequest<'_>,
    command_argv: Vec<String>,
    duration: f64,
    captured: &TimedOutOutput,
    cleanup_error: Option<String>,
) -> BTreeMap<String, Value> {
    let mut outcome = result(
        ResultMeta {
            interpreter: request.interpreter,
            sudo: request.sudo,
            cwd: request.cwd,
            cleanup: request.cleanup,
        },
        command_argv,
        timeout_output(captured),
        duration,
        -1,
    );
    add_timeout_metadata(&mut outcome, captured, cleanup_error);
    outcome
}

/// # Errors
/// Returns an error when the script request is invalid, disallowed, cannot be staged, or execution fails.
pub async fn handle(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let request = parse_script_request(payload)?;
    let staged = prepare_script(policy, &request).await?;
    let (command_argv, spawn_cwd) = build_command(
        policy,
        request.interpreter,
        staged.script_path(),
        &request.args,
        &request.env,
        request.sudo,
        request.cwd,
    );
    let killer = if request.sudo {
        match ProcessGroupKill::sudo(policy) {
            Ok(killer) => killer,
            Err(error) => return Err(staged.finish_error(error, request.cleanup)),
        }
    } else {
        ProcessGroupKill::Direct
    };

    let outcome = process_runner::run_argv(
        policy,
        &command_argv,
        Duration::from_secs(request.timeout_seconds),
        spawn_cwd.as_deref(),
        Some(&request.env),
        killer,
    )
    .await;

    let outcome = match outcome {
        Ok(ProcessOutcome::Completed { captured, duration }) => {
            completed_result(&request, command_argv, duration, &captured)
        }
        Ok(ProcessOutcome::TimedOut {
            captured,
            duration,
            cleanup_error,
        }) => timed_out_result(&request, command_argv, duration, &captured, cleanup_error),
        Err(ProcessFailure::Setup(error)) => {
            return Err(staged.finish_error(error, request.cleanup));
        }
        Err(ProcessFailure::Spawn(error)) => {
            let error = script_spawn_error(&error, spawn_cwd.as_deref());
            return Err(staged.finish_error(error, request.cleanup));
        }
        Err(ProcessFailure::Capture {
            error,
            cleanup_error,
        }) => {
            let error = with_cleanup_detail(
                HandlerError::new("io_error", format!("script output capture failed: {error}")),
                cleanup_error,
            );
            return Err(staged.finish_error(error, request.cleanup));
        }
    };

    Ok(staged.finalize(outcome, request.cleanup))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TestError as _, TestResult, TestValue as _};
    use tempfile::tempdir;

    #[test]
    fn staging_host_conditions_have_specific_error_codes() {
        let path = Path::new("/var/lib/sentinelx/uploads/.sentinelx_uploads/script_job_x");
        assert_eq!(
            staging_oserror(&std::io::Error::from_raw_os_error(nix::libc::ENOSPC), path).code,
            "no_space"
        );
        for code in [nix::libc::EACCES, nix::libc::EPERM] {
            assert_eq!(
                staging_oserror(&std::io::Error::from_raw_os_error(code), path).code,
                "permission_denied"
            );
        }
        assert_eq!(
            staging_oserror(&std::io::Error::from_raw_os_error(nix::libc::EROFS), path).code,
            "read_only_filesystem"
        );
        assert_eq!(
            staging_oserror(&std::io::Error::from_raw_os_error(nix::libc::EIO), path).code,
            "staging_failed"
        );
        let message =
            staging_oserror(&std::io::Error::from_raw_os_error(nix::libc::ENOSPC), path).message;
        assert!(message.contains("host condition"));
        assert!(message.contains("unstable"));
        assert!(message.contains(&path.display().to_string()));
    }

    #[test]
    fn filename_is_reduced_to_a_safe_basename() {
        assert_eq!(safe_filename(Some("../../kept.sh"), "sh"), "kept.sh");
        assert_eq!(safe_filename(Some(".hidden"), "sh"), "script.sh");
        assert_eq!(safe_filename(Some("../../"), "sh"), "script.sh");
        assert_eq!(safe_filename(None, "py"), "script.py");
    }

    #[test]
    fn sudo_command_preserves_env_names_without_putting_values_in_argv() -> TestResult {
        let policy = Policy::default();
        let script = Path::new("/tmp/script.sh");
        let env = Map::from_iter([
            ("ZED".into(), Value::String("secret $() value".into())),
            ("ALPHA".into(), Value::String("another secret".into())),
        ]);
        let (argv, cwd) = build_command(&policy, "bash", script, &[], &env, true, Some("/tmp/cwd"));

        assert!(cwd.is_none());
        assert_eq!(
            argv[0],
            policy.tooling.command("sudo").display().to_string()
        );
        assert_eq!(argv[1], "-n");
        assert_eq!(argv[2], "--preserve-env=ALPHA");
        assert_eq!(argv[3], "--preserve-env=ZED");
        assert!(!argv.iter().any(|arg| arg.contains("secret")));
        Ok(())
    }

    #[tokio::test]
    async fn bash_script_captures_output_and_exit_code() -> TestResult {
        let dir = tempdir().test_value()?;
        let policy = Policy {
            upload_base: dir.path().to_owned(),
            ..Policy::default()
        };
        let result = handle(
            &policy,
            &Map::from_iter([
                ("interpreter".into(), Value::String("bash".into())),
                (
                    "content".into(),
                    Value::String("echo hello; echo err >&2; exit 7".into()),
                ),
            ]),
        )
        .await
        .test_value()?;
        assert_eq!(result["returncode"], 7);
        assert_eq!(result["ok"], false);
        assert!(result["output"].as_str().test_value()?.contains("hello"));
        assert!(result["output"].as_str().test_value()?.contains("err"));

        Ok(())
    }

    #[tokio::test]
    async fn missing_cwd_is_named_not_found() -> TestResult {
        let dir = tempdir().test_value()?;
        let policy = Policy {
            upload_base: dir.path().to_owned(),
            ..Policy::default()
        };
        let missing = dir.path().join("nope");
        let error = handle(
            &policy,
            &Map::from_iter([
                ("interpreter".into(), Value::String("bash".into())),
                ("content".into(), Value::String("echo hi".into())),
                ("cwd".into(), Value::String(missing.display().to_string())),
            ]),
        )
        .await
        .test_error()?;
        assert_eq!(error.code, "not_found");
        assert!(error.message.contains("cwd"));

        Ok(())
    }

    #[tokio::test]
    async fn file_cwd_is_named_not_a_directory() -> TestResult {
        let dir = tempdir().test_value()?;
        let file = dir.path().join("file");
        fs::write(&file, b"x").test_value()?;
        let policy = Policy {
            upload_base: dir.path().to_owned(),
            ..Policy::default()
        };
        let error = handle(
            &policy,
            &Map::from_iter([
                ("interpreter".into(), Value::String("bash".into())),
                ("content".into(), Value::String("echo hi".into())),
                ("cwd".into(), Value::String(file.display().to_string())),
            ]),
        )
        .await
        .test_error()?;
        assert_eq!(error.code, "not_a_directory");

        Ok(())
    }

    #[tokio::test]
    async fn missing_interpreter_is_not_mistaken_for_missing_cwd() -> TestResult {
        let dir = tempdir().test_value()?;
        let policy = Policy {
            upload_base: dir.path().to_owned(),
            ..Policy::default()
        };
        let error = handle(
            &policy,
            &Map::from_iter([
                ("interpreter".into(), Value::String("powershell".into())),
                ("content".into(), Value::String("Write-Output hi".into())),
                (
                    "cwd".into(),
                    Value::String(dir.path().display().to_string()),
                ),
            ]),
        )
        .await
        .test_error()?;
        assert_eq!(error.code, "interpreter_missing");

        Ok(())
    }

    #[tokio::test]
    async fn timed_out_script_keeps_flushed_output() -> TestResult {
        let dir = tempdir().test_value()?;
        let policy = Policy {
            upload_base: dir.path().to_owned(),
            ..Policy::default()
        };
        let result = handle(
            &policy,
            &Map::from_iter([
                ("interpreter".into(), Value::String("bash".into())),
                (
                    "content".into(),
                    Value::String(
                        "printf 'reached step 1\n'; printf 'err1\n' >&2; sleep 10".into(),
                    ),
                ),
                ("timeout".into(), Value::from(1)),
            ]),
        )
        .await
        .test_value()?;
        let output = result["output"].as_str().test_value()?;
        assert_eq!(result["timed_out"], true);
        assert!(output.starts_with("⏱️ Timeout. Output written before the timeout:"));
        assert!(output.contains("reached step 1"));
        assert!(output.contains("err1"));
        assert!(!result.contains_key("left_running"));

        Ok(())
    }

    #[tokio::test]
    async fn timed_out_script_kills_descendant_tree() -> TestResult {
        let dir = tempdir().test_value()?;
        let marker = dir.path().join("survived");
        let policy = Policy {
            upload_base: dir.path().to_owned(),
            ..Policy::default()
        };
        let result = handle(
            &policy,
            &Map::from_iter([
                ("interpreter".into(), Value::String("bash".into())),
                (
                    "content".into(),
                    Value::String(format!("(sleep 2; touch {}) & wait", marker.display())),
                ),
                ("timeout".into(), Value::from(1)),
            ]),
        )
        .await
        .test_value()?;
        assert_eq!(result["timed_out"], true);
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(!marker.exists());

        Ok(())
    }

    #[tokio::test]
    async fn missing_interpreter_cleans_workdir_by_default() -> TestResult {
        let dir = tempdir().test_value()?;
        let policy = Policy {
            upload_base: dir.path().to_owned(),
            ..Policy::default()
        };
        let error = handle(
            &policy,
            &Map::from_iter([
                ("interpreter".into(), Value::String("powershell".into())),
                ("content".into(), Value::String("Write-Output ok".into())),
                (
                    "env".into(),
                    serde_json::json!({"PATH": "/definitely/not/a/real/bin"}),
                ),
            ]),
        )
        .await
        .test_error()?;
        assert_eq!(error.code, "interpreter_missing");

        let staging = dir.path().join(crate::staging::STAGING_DIRNAME);
        let leftovers = fs::read_dir(staging)
            .test_value()?
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .collect::<Vec<_>>();
        assert!(
            leftovers.is_empty(),
            "failed script launch leaked workdir: {leftovers:?}"
        );

        Ok(())
    }

    #[tokio::test]
    async fn args_and_env_are_data_not_shell_source() -> TestResult {
        let dir = tempdir().test_value()?;
        let marker = dir.path().join("injected");
        let shell_like = format!("$(touch {})", marker.display());
        let env_value = format!("space; $(touch {}) ' \" żółć 🦀", marker.display());
        let policy = Policy {
            upload_base: dir.path().to_owned(),
            ..Policy::default()
        };
        let result = handle(
            &policy,
            &Map::from_iter([
                ("interpreter".into(), Value::String("bash".into())),
                (
                    "content".into(),
                    Value::String(
                        "printf 'ARG=<%s>\\n' \"$@\"; printf 'ENV=<%s>\\n' \"$PAYLOAD\"".into(),
                    ),
                ),
                (
                    "args".into(),
                    Value::Array(
                        [
                            "space arg".to_owned(),
                            shell_like.clone(),
                            "żółć 🦀".to_owned(),
                        ]
                        .into_iter()
                        .map(Value::String)
                        .collect(),
                    ),
                ),
                (
                    "env".into(),
                    serde_json::json!({"PAYLOAD": env_value.clone()}),
                ),
            ]),
        )
        .await
        .test_value()?;

        let output = result["output"].as_str().test_value()?;
        assert!(output.contains("ARG=<space arg>"));
        assert!(output.contains(&format!("ARG=<{shell_like}>")));
        assert!(output.contains("ARG=<żółć 🦀>"));
        assert!(output.contains(&format!("ENV=<{env_value}>")));
        assert!(
            !marker.exists(),
            "shell-looking data was unexpectedly executed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn cleanup_false_success_reports_retained_paths() -> TestResult {
        let dir = tempdir().test_value()?;
        let policy = Policy {
            upload_base: dir.path().to_owned(),
            ..Policy::default()
        };
        let result = handle(
            &policy,
            &Map::from_iter([
                ("interpreter".into(), Value::String("bash".into())),
                ("content".into(), Value::String("printf retained".into())),
                ("cleanup".into(), Value::Bool(false)),
                ("filename".into(), Value::String("../../kept.sh".into())),
            ]),
        )
        .await
        .test_value()?;

        assert_eq!(result["cleanup"], false);
        assert_eq!(result["output"], "retained");
        let workdir = PathBuf::from(result["workdir"].as_str().test_value()?);
        let script_path = PathBuf::from(result["script_path"].as_str().test_value()?);
        assert_eq!(script_path.parent(), Some(workdir.as_path()));
        assert_eq!(
            script_path.file_name().and_then(|name| name.to_str()),
            Some("kept.sh")
        );
        assert_eq!(
            fs::read_to_string(&script_path).test_value()?,
            "printf retained"
        );
        fs::remove_dir_all(workdir).test_value()?;
        Ok(())
    }

    #[tokio::test]
    async fn cleanup_false_launch_error_reports_retained_paths() -> TestResult {
        let dir = tempdir().test_value()?;
        let policy = Policy {
            upload_base: dir.path().to_owned(),
            ..Policy::default()
        };
        let error = handle(
            &policy,
            &Map::from_iter([
                ("interpreter".into(), Value::String("powershell".into())),
                (
                    "content".into(),
                    Value::String("Write-Output retained".into()),
                ),
                ("cleanup".into(), Value::Bool(false)),
                (
                    "env".into(),
                    serde_json::json!({"PATH": "/definitely/not/a/real/bin"}),
                ),
                ("filename".into(), Value::String("debug.ps1".into())),
            ]),
        )
        .await
        .test_error()?;
        assert_eq!(error.code, "interpreter_missing");

        let workdir = PathBuf::from(error.details["workdir"].as_str().test_value()?);
        let script_path = PathBuf::from(error.details["script_path"].as_str().test_value()?);
        assert!(workdir.is_dir());
        assert_eq!(script_path.parent(), Some(workdir.as_path()));
        assert_eq!(
            fs::read_to_string(&script_path).test_value()?,
            "Write-Output retained"
        );
        fs::remove_dir_all(workdir).test_value()?;
        Ok(())
    }

    #[tokio::test]
    async fn cancellation_kills_descendants_and_cleans_staging() -> TestResult {
        let dir = tempdir().test_value()?;
        let started = dir.path().join("started");
        let survived = dir.path().join("survived");
        let policy = Policy {
            upload_base: dir.path().to_owned(),
            ..Policy::default()
        };
        let payload = Map::from_iter([
            ("interpreter".into(), Value::String("bash".into())),
            (
                "content".into(),
                Value::String(format!(
                    "touch {}; (sleep 1; touch {}) >/dev/null 2>&1 & wait",
                    started.display(),
                    survived.display()
                )),
            ),
        ]);
        let task = tokio::spawn(async move { handle(&policy, &payload).await });

        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while !started.exists() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(started.exists(), "script never reached its body");
        task.abort();
        let join_error = task
            .await
            .expect_err("cancelled script unexpectedly completed");
        assert!(join_error.is_cancelled());

        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(
            !survived.exists(),
            "script descendant survived cancellation"
        );
        let staging = dir.path().join(crate::staging::STAGING_DIRNAME);
        let leftovers = fs::read_dir(staging)
            .test_value()?
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .collect::<Vec<_>>();
        assert!(
            leftovers.is_empty(),
            "cancelled script leaked workdir: {leftovers:?}"
        );
        Ok(())
    }
}
