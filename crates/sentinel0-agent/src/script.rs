use crate::{
    handler_error::{HandlerError, HandlerResult, require_str},
    jobs::BACKGROUND_TIMEOUT_MAX_SECS,
    policy::Policy,
    process_output::{CapturedOutput, WaitOutcome, wait_bounded},
    staging,
};
use rand::RngExt;
use serde_json::{Map, Value};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{fs as async_fs, process::Command};

const TIMEOUT_MIN: u64 = 1;
const TIMEOUT_MAX: u64 = 600;

fn staging_oserror(error: std::io::Error, path: &Path) -> HandlerError {
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

async fn cleanup_workdir_error(workdir: &Path) -> Option<String> {
    match async_fs::remove_dir_all(workdir).await {
        Ok(()) => None,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            let message = format!(
                "failed cleaning script workdir {}: {error}",
                workdir.display()
            );
            tracing::warn!(%message);
            Some(message)
        }
    }
}

fn with_cleanup_detail(mut error: HandlerError, cleanup: Option<String>) -> HandlerError {
    if let Some(cleanup) = cleanup {
        error
            .details
            .insert("cleanup_error".into(), Value::String(cleanup));
    }
    error
}

fn safe_filename(filename: Option<&str>, extension: &str) -> String {
    filename
        .and_then(|name| Path::new(name).file_name())
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && !name.starts_with('.'))
        .map(str::to_owned)
        .unwrap_or_else(|| format!("script.{extension}"))
}

fn merged_output(captured: &CapturedOutput) -> String {
    let stdout = captured.stdout.rendered_trimmed_lossy();
    let stderr = captured.stderr.rendered_trimmed_lossy();
    if stdout.is_empty() && stderr.is_empty() {
        "⚠️ Sin salida".into()
    } else if stderr.is_empty() {
        stdout
    } else if stdout.is_empty() {
        stderr
    } else {
        format!("{stdout}\n{stderr}")
    }
}

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
    captured: Option<&CapturedOutput>,
) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::from([
        ("ok".into(), Value::Bool(returncode == 0)),
        ("interpreter".into(), Value::String(meta.interpreter.into())),
        ("sudo".into(), Value::Bool(meta.sudo)),
        (
            "cwd".into(),
            meta.cwd
                .map(|value| Value::String(value.into()))
                .unwrap_or(Value::Null),
        ),
        ("cleanup".into(), Value::Bool(meta.cleanup)),
        (
            "command".into(),
            Value::Array(command.into_iter().map(Value::String).collect()),
        ),
        ("output".into(), Value::String(output)),
        ("duration".into(), Value::from(duration)),
        ("returncode".into(), Value::from(returncode)),
    ]);
    if let Some(captured) = captured
        && (captured.stdout.truncated() || captured.stderr.truncated())
    {
        out.insert("output_truncated".into(), Value::Bool(true));
        out.insert(
            "stdout_bytes".into(),
            Value::from(captured.stdout.total_bytes()),
        );
        out.insert(
            "stderr_bytes".into(),
            Value::from(captured.stderr.total_bytes()),
        );
    }
    out
}

fn build_command(
    policy: &Policy,
    interpreter: &str,
    script: &Path,
    args: &[String],
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
        if let Some(cwd) = cwd {
            let mut argv = vec![
                sudo,
                "-n".into(),
                policy.tooling.command("bash").display().to_string(),
                "-c".into(),
                "cd \"$1\" || { echo \"sentinelx: cannot enter $1\" >&2; exit 126; }; shift; exec \"$@\"" .into(),
                "bash".into(),
                cwd.into(),
            ];
            argv.extend(inner);
            (argv, None)
        } else {
            let mut argv = vec![sudo, "-n".into()];
            argv.extend(inner);
            (argv, None)
        }
    } else {
        (inner, cwd.map(PathBuf::from))
    }
}

pub async fn handle(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
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
    let filename = safe_filename(payload.get("filename").and_then(Value::as_str), extension);

    let upload_base = policy.upload_base.clone();
    let upload_base_for_error = upload_base.clone();
    let root = tokio::task::spawn_blocking(move || staging::staging_root(&upload_base))
        .await
        .map_err(|e| {
            HandlerError::new("internal_error", format!("staging setup task failed: {e}"))
        })?
        .map_err(|e| staging_oserror(e, &upload_base_for_error))?;
    let workdir = root.join(format!("script_job_{:016x}", rand::rng().random::<u64>()));
    async_fs::create_dir_all(&workdir)
        .await
        .map_err(|e| staging_oserror(e, &workdir))?;
    let script_path = workdir.join(filename);
    if let Err(error) = async_fs::write(&script_path, content).await {
        let cleanup_error = if cleanup {
            cleanup_workdir_error(&workdir).await
        } else {
            None
        };
        return Err(with_cleanup_detail(
            staging_oserror(error, &script_path),
            cleanup_error,
        ));
    }
    if let Err(error) =
        async_fs::set_permissions(&script_path, fs::Permissions::from_mode(0o700)).await
    {
        let cleanup_error = if cleanup {
            cleanup_workdir_error(&workdir).await
        } else {
            None
        };
        return Err(with_cleanup_detail(
            staging_oserror(error, &script_path),
            cleanup_error,
        ));
    }

    let (argv, spawn_cwd) = build_command(policy, interpreter, &script_path, &args, sudo, cwd);
    let started = Instant::now();
    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    if let Err(error) = policy.tooling.configure_tokio(&mut command) {
        let cleanup_error = if cleanup {
            cleanup_workdir_error(&workdir).await
        } else {
            None
        };
        return Err(with_cleanup_detail(error, cleanup_error));
    }
    if let Some(cwd) = spawn_cwd.as_ref() {
        command.current_dir(cwd);
    }
    for (key, value) in env {
        if let Some(value) = value.as_str() {
            command.env(key, value);
        }
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let handler_error = if let Some(cwd) = spawn_cwd.as_deref() {
                // With a non-sudo script, Command changes into cwd before exec.
                // Preserve the upstream 0.19.3 diagnostics while still honoring
                // cleanup=true for the staging workdir on every spawn failure.
                match error.kind() {
                    std::io::ErrorKind::PermissionDenied => HandlerError::new(
                        "permission_denied",
                        format!(
                            "cannot enter cwd {:?}: the agent's OS user lacks permission to change into it. Being inside an rw file_ops path does not grant Unix access. Either run with sudo=true -- the directory is then entered after elevation -- or grant the agent's user execute (+x) on it and its parents.",
                            cwd.display()
                        ),
                    ),
                    std::io::ErrorKind::NotFound if !cwd.exists() => HandlerError::new(
                        "not_found",
                        format!("cwd {:?} does not exist.", cwd.display()),
                    ),
                    std::io::ErrorKind::NotADirectory if !cwd.is_dir() => HandlerError::new(
                        "not_a_directory",
                        format!("cwd {:?} is not a directory.", cwd.display()),
                    ),
                    _ => {
                        let code = if error.kind() == std::io::ErrorKind::NotFound {
                            "interpreter_missing"
                        } else {
                            "io_error"
                        };
                        HandlerError::new(code, format!("failed starting script: {error}"))
                    }
                }
            } else {
                let code = if error.kind() == std::io::ErrorKind::NotFound {
                    "interpreter_missing"
                } else {
                    "io_error"
                };
                HandlerError::new(code, format!("failed starting script: {error}"))
            };
            let cleanup_error = if cleanup {
                cleanup_workdir_error(&workdir).await
            } else {
                None
            };
            return Err(with_cleanup_detail(handler_error, cleanup_error));
        }
    };
    let pid = child.id();

    let wait_outcome = match wait_bounded(
        &mut child,
        Duration::from_secs(timeout_seconds),
        policy.exec_capture_max_bytes,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            let mut cleanup_error = None;
            #[cfg(unix)]
            match child.try_wait() {
                Ok(Some(_)) => {}
                Ok(None) => {
                    if let Some(pid) = pid {
                        let pgid = nix::unistd::Pid::from_raw(pid as i32);
                        if let Err(kill_error) =
                            nix::sys::signal::killpg(pgid, nix::sys::signal::Signal::SIGKILL)
                            && kill_error != nix::errno::Errno::ESRCH
                        {
                            let message = format!(
                                "failed killing script after output-capture error: {kill_error}"
                            );
                            tracing::warn!(%message);
                            cleanup_error = Some(message);
                        }
                    }
                }
                Err(state_error) => {
                    let message = format!(
                        "failed checking script state after output-capture error: {state_error}; refusing PID-based group signal"
                    );
                    tracing::warn!(%message);
                    cleanup_error = Some(message);
                }
            }
            if let Err(wait_error) = child.wait().await {
                let message =
                    format!("failed reaping script after output-capture error: {wait_error}");
                tracing::warn!(%message);
                cleanup_error.get_or_insert(message);
            }
            if cleanup && let Some(workdir_error) = cleanup_workdir_error(&workdir).await {
                cleanup_error = Some(match cleanup_error {
                    Some(existing) => format!("{existing}; {workdir_error}"),
                    None => workdir_error,
                });
            }
            let error =
                HandlerError::new("io_error", format!("script output capture failed: {error}"));
            return Err(with_cleanup_detail(error, cleanup_error));
        }
    };

    let outcome = match wait_outcome {
        WaitOutcome::Completed(captured) => {
            let rc = captured.status.code().unwrap_or(-1);
            result(
                ResultMeta {
                    interpreter,
                    sudo,
                    cwd,
                    cleanup,
                },
                argv.clone(),
                merged_output(&captured),
                (started.elapsed().as_secs_f64() * 100.0).round() / 100.0,
                rc,
                Some(&captured),
            )
        }
        WaitOutcome::TimedOut => {
            let mut cleanup_error = None;
            #[cfg(unix)]
            if let Some(pid) = pid {
                let child_is_live = match child.try_wait() {
                    Ok(Some(_)) => false,
                    Ok(None) => true,
                    Err(state_error) => {
                        let message = format!(
                            "failed checking timed-out script state: {state_error}; refusing PID-based group signal"
                        );
                        tracing::warn!(%message);
                        cleanup_error = Some(message);
                        false
                    }
                };
                if child_is_live {
                    let pgid = nix::unistd::Pid::from_raw(pid as i32);
                    if sudo {
                        let status = Command::new(policy.tooling.command("sudo"))
                            .args(["-n", "kill", "-9", "--", &format!("-{}", pgid.as_raw())])
                            .env("PATH", policy.tooling.path_env()?)
                            .status()
                            .await;
                        match status {
                            Ok(status) if status.success() => {}
                            Ok(status) => {
                                let message = format!(
                                    "sudo kill of timed-out process group {} exited with {status}",
                                    pgid.as_raw()
                                );
                                tracing::warn!(%message);
                                cleanup_error = Some(message);
                            }
                            Err(error) => {
                                let message =
                                    format!("failed killing timed-out sudo process group: {error}");
                                tracing::warn!(%message);
                                cleanup_error = Some(message);
                            }
                        }
                    } else if let Err(error) =
                        nix::sys::signal::killpg(pgid, nix::sys::signal::Signal::SIGKILL)
                        && error != nix::errno::Errno::ESRCH
                    {
                        let message = format!("failed killing timed-out process group: {error}");
                        tracing::warn!(%message);
                        cleanup_error = Some(message);
                    }
                }
            }
            if let Err(error) = child.wait().await {
                let message = format!("failed reaping timed-out script: {error}");
                tracing::warn!(%message);
                cleanup_error.get_or_insert(message);
            }
            let mut out = result(
                ResultMeta {
                    interpreter,
                    sudo,
                    cwd,
                    cleanup,
                },
                argv.clone(),
                "⏱️ Timeout".into(),
                (started.elapsed().as_secs_f64() * 100.0).round() / 100.0,
                -1,
                None,
            );
            out.insert("timed_out".into(), Value::Bool(true));
            if let Some(error) = cleanup_error {
                out.insert("cleanup_error".into(), Value::String(error));
            }
            out
        }
    };
    let mut outcome = outcome;
    if !cleanup {
        outcome.insert(
            "script_path".into(),
            Value::String(script_path.display().to_string()),
        );
        outcome.insert(
            "workdir".into(),
            Value::String(workdir.display().to_string()),
        );
    } else if let Err(error) = async_fs::remove_dir_all(&workdir).await {
        tracing::warn!(path = %workdir.display(), %error, "failed cleaning script workdir");
        outcome.insert(
            "cleanup_error".into(),
            Value::String(format!("failed cleaning script workdir: {error}")),
        );
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn staging_host_conditions_have_specific_error_codes() {
        let path = Path::new("/var/lib/sentinelx/uploads/.sentinelx_uploads/script_job_x");
        assert_eq!(
            staging_oserror(std::io::Error::from_raw_os_error(nix::libc::ENOSPC), path).code,
            "no_space"
        );
        for code in [nix::libc::EACCES, nix::libc::EPERM] {
            assert_eq!(
                staging_oserror(std::io::Error::from_raw_os_error(code), path).code,
                "permission_denied"
            );
        }
        assert_eq!(
            staging_oserror(std::io::Error::from_raw_os_error(nix::libc::EROFS), path).code,
            "read_only_filesystem"
        );
        assert_eq!(
            staging_oserror(std::io::Error::from_raw_os_error(nix::libc::EIO), path).code,
            "staging_failed"
        );
        let message =
            staging_oserror(std::io::Error::from_raw_os_error(nix::libc::ENOSPC), path).message;
        assert!(message.contains("host condition"));
        assert!(message.contains("unstable"));
        assert!(message.contains(&path.display().to_string()));
    }

    #[tokio::test]
    async fn bash_script_captures_output_and_exit_code() {
        let dir = tempdir().unwrap();
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
        .unwrap();
        assert_eq!(result["returncode"], 7);
        assert_eq!(result["ok"], false);
        assert!(result["output"].as_str().unwrap().contains("hello"));
        assert!(result["output"].as_str().unwrap().contains("err"));
    }

    #[tokio::test]
    async fn missing_cwd_is_named_not_found() {
        let dir = tempdir().unwrap();
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
        .unwrap_err();
        assert_eq!(error.code, "not_found");
        assert!(error.message.contains("cwd"));
    }

    #[tokio::test]
    async fn file_cwd_is_named_not_a_directory() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("file");
        fs::write(&file, b"x").unwrap();
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
        .unwrap_err();
        assert_eq!(error.code, "not_a_directory");
    }

    #[tokio::test]
    async fn missing_interpreter_is_not_mistaken_for_missing_cwd() {
        let dir = tempdir().unwrap();
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
        .unwrap_err();
        assert_eq!(error.code, "interpreter_missing");
    }

    #[tokio::test]
    async fn timed_out_script_kills_descendant_tree() {
        let dir = tempdir().unwrap();
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
        .unwrap();
        assert_eq!(result["timed_out"], true);
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(!marker.exists());
    }

    #[tokio::test]
    async fn missing_interpreter_cleans_workdir_by_default() {
        let dir = tempdir().unwrap();
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
        .unwrap_err();
        assert_eq!(error.code, "interpreter_missing");

        let staging = dir.path().join(crate::staging::STAGING_DIRNAME);
        let leftovers = fs::read_dir(staging)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .collect::<Vec<_>>();
        assert!(
            leftovers.is_empty(),
            "failed script launch leaked workdir: {leftovers:?}"
        );
    }
}
