use serde_json::{Map, Value};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
use tokio::{process::Command, time::timeout};

fn rounded_seconds(start: Instant) -> f64 {
    let secs = start.elapsed().as_secs_f64();
    (secs * 100.0).round() / 100.0
}

fn result(
    output: String,
    duration: f64,
    returncode: i32,
    timed_out: bool,
) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::from([
        ("output".into(), Value::String(output)),
        ("duration".into(), Value::from(duration)),
        ("returncode".into(), Value::from(returncode)),
    ]);
    if timed_out {
        out.insert("timed_out".into(), Value::Bool(true));
    }
    out
}

pub async fn run_shell(
    command: &str,
    timeout_duration: Duration,
    cwd: Option<&str>,
    env: Option<&Map<String, Value>>,
) -> BTreeMap<String, Value> {
    let start = Instant::now();
    let mut cmd = Command::new("bash");
    cmd.arg("-lc")
        .arg(command)
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    #[cfg(unix)]
    cmd.process_group(0);

    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    if let Some(env) = env {
        for (key, value) in env {
            if let Some(value) = value.as_str() {
                cmd.env(key, value);
            }
        }
    }

    let child = match cmd.spawn() {
        Ok(child) => child,
        Err(error) => {
            return result(
                format!("❌ Error: {error}"),
                rounded_seconds(start),
                -1,
                false,
            );
        }
    };

    let pid = child.id();
    match timeout(timeout_duration, child.wait_with_output()).await {
        Ok(Ok(output)) => {
            let rc = output.status.code().unwrap_or(-1);
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            let output = if stdout.is_empty() && stderr.is_empty() {
                "⚠️ Sin salida".into()
            } else if stderr.is_empty() {
                stdout
            } else if stdout.is_empty() {
                stderr
            } else {
                format!("{stdout}\n{stderr}")
            };
            result(output, rounded_seconds(start), rc, false)
        }
        Ok(Err(error)) => result(
            format!("❌ Error: {error}"),
            rounded_seconds(start),
            -1,
            false,
        ),
        Err(_) => {
            #[cfg(unix)]
            if let Some(pid) = pid {
                let pgid = nix::unistd::Pid::from_raw(pid as i32);
                let _ = nix::sys::signal::killpg(pgid, nix::sys::signal::Signal::SIGKILL);
            }
            result("⏱️ Timeout".into(), rounded_seconds(start), -1, true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUCCESS_TEST_TIMEOUT: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn shell_merges_stdout_and_stderr_like_python_core() {
        let result = run_shell(
            "printf out; printf err >&2",
            SUCCESS_TEST_TIMEOUT,
            None,
            None,
        )
        .await;
        assert_eq!(result["returncode"], 0);
        assert_eq!(result["output"], "out\nerr");
    }

    #[tokio::test]
    async fn empty_output_uses_legacy_marker() {
        let result = run_shell("true", SUCCESS_TEST_TIMEOUT, None, None).await;
        assert_eq!(result["output"], "⚠️ Sin salida");
    }

    #[tokio::test]
    async fn timeout_is_structured() {
        let result = run_shell("sleep 10", Duration::from_millis(30), None, None).await;
        assert_eq!(result["returncode"], -1);
        assert_eq!(result["timed_out"], true);
    }

    #[tokio::test]
    async fn timeout_kills_descendants_in_same_process_group() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("survived");
        let command = format!("(sleep 0.15; touch {}) & wait", marker.display());
        let result = run_shell(&command, Duration::from_millis(30), None, None).await;
        assert_eq!(result["timed_out"], true);
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(!marker.exists(), "descendant survived timed-out shell");
    }
}
