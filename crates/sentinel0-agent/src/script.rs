use crate::{
    handler_error::{HandlerError, HandlerResult, require_str},
    jobs::BACKGROUND_TIMEOUT_MAX_SECS,
    policy::Policy,
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
use tokio::{fs as async_fs, process::Command, time::timeout};

const TIMEOUT_MIN: u64 = 1;
const TIMEOUT_MAX: u64 = 600;

fn safe_filename(filename: Option<&str>, extension: &str) -> String {
    filename
        .and_then(|name| Path::new(name).file_name())
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && !name.starts_with('.'))
        .map(str::to_owned)
        .unwrap_or_else(|| format!("script.{extension}"))
}

fn merged_output(stdout: &[u8], stderr: &[u8]) -> String {
    let stdout = String::from_utf8_lossy(stdout).trim().to_owned();
    let stderr = String::from_utf8_lossy(stderr).trim().to_owned();
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
) -> BTreeMap<String, Value> {
    BTreeMap::from([
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
    ])
}

fn build_command(
    interpreter: &str,
    script: &Path,
    args: &[String],
    sudo: bool,
    cwd: Option<&str>,
) -> (Vec<String>, Option<PathBuf>) {
    let mut inner = match interpreter {
        "bash" => vec!["bash".into(), script.display().to_string()],
        "python3" => vec!["python3".into(), script.display().to_string()],
        "pwsh" => vec![
            "pwsh".into(),
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-File".into(),
            script.display().to_string(),
        ],
        "powershell" => vec![
            "powershell".into(),
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-File".into(),
            script.display().to_string(),
        ],
        _ => Vec::new(),
    };
    inner.extend(args.iter().cloned());

    if sudo {
        if let Some(cwd) = cwd {
            let mut argv = vec![
                "sudo".into(),
                "sh".into(),
                "-c".into(),
                "cd \"$1\" || { echo \"sentinelx: cannot enter $1\" >&2; exit 126; }; shift; exec \"$@\"" .into(),
                "sh".into(),
                cwd.into(),
            ];
            argv.extend(inner);
            (argv, None)
        } else {
            let mut argv = vec!["sudo".into()];
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
    let root = tokio::task::spawn_blocking(move || staging::staging_root(&upload_base))
        .await
        .map_err(|e| HandlerError::new("internal_error", format!("staging setup failed: {e}")))?
        .map_err(|e| HandlerError::new("io_error", e.to_string()))?;
    let workdir = root.join(format!("script_job_{:016x}", rand::rng().random::<u64>()));
    async_fs::create_dir_all(&workdir).await.map_err(|e| {
        HandlerError::new("io_error", format!("failed creating script workdir: {e}"))
    })?;
    let script_path = workdir.join(filename);
    async_fs::write(&script_path, content)
        .await
        .map_err(|e| HandlerError::new("io_error", format!("failed writing script: {e}")))?;
    async_fs::set_permissions(&script_path, fs::Permissions::from_mode(0o700))
        .await
        .map_err(|e| HandlerError::new("io_error", format!("failed chmod on script: {e}")))?;

    let (argv, spawn_cwd) = build_command(interpreter, &script_path, &args, sudo, cwd);
    let started = Instant::now();
    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    if let Some(cwd) = spawn_cwd.as_ref() {
        command.current_dir(cwd);
    }
    for (key, value) in env {
        if let Some(value) = value.as_str() {
            command.env(key, value);
        }
    }

    let child = command.spawn().map_err(|e| {
        let code = if e.kind() == std::io::ErrorKind::NotFound {
            "interpreter_missing"
        } else {
            "io_error"
        };
        HandlerError::new(code, format!("failed starting script: {e}"))
    })?;
    let pid = child.id();

    let outcome = match timeout(
        Duration::from_secs(timeout_seconds),
        child.wait_with_output(),
    )
    .await
    {
        Ok(Ok(output)) => {
            let rc = output.status.code().unwrap_or(-1);
            result(
                ResultMeta {
                    interpreter,
                    sudo,
                    cwd,
                    cleanup,
                },
                argv.clone(),
                merged_output(&output.stdout, &output.stderr),
                (started.elapsed().as_secs_f64() * 100.0).round() / 100.0,
                rc,
            )
        }
        Ok(Err(e)) => {
            if cleanup {
                let _ = async_fs::remove_dir_all(&workdir).await;
            }
            return Err(HandlerError::new(
                "io_error",
                format!("script execution failed: {e}"),
            ));
        }
        Err(_) => {
            #[cfg(unix)]
            if let Some(pid) = pid {
                let pgid = nix::unistd::Pid::from_raw(pid as i32);
                if sudo {
                    let _ = Command::new("sudo")
                        .args(["-n", "kill", "-9", "--", &format!("-{}", pgid.as_raw())])
                        .status()
                        .await;
                } else {
                    let _ = nix::sys::signal::killpg(pgid, nix::sys::signal::Signal::SIGKILL);
                }
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
            );
            out.insert("timed_out".into(), Value::Bool(true));
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
    } else {
        let _ = async_fs::remove_dir_all(&workdir).await;
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

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
}
