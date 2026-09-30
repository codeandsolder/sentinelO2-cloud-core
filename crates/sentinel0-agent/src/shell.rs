use crate::{
    handler_error::{HandlerError, HandlerResult},
    policy::Policy,
    process_output::{CapturedOutput, WaitOutcome, wait_bounded},
};
use serde_json::{Map, Value};
use std::{
    collections::BTreeMap,
    path::Path,
    time::{Duration, Instant},
};
use tokio::process::Command;

fn rounded_seconds(start: Instant) -> f64 {
    let secs = start.elapsed().as_secs_f64();
    (secs * 100.0).round() / 100.0
}

fn result(
    output: String,
    duration: f64,
    returncode: i32,
    timed_out: bool,
    captured: Option<&CapturedOutput>,
    kill_error: Option<String>,
) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::from([
        ("output".into(), Value::String(output)),
        ("duration".into(), Value::from(duration)),
        ("returncode".into(), Value::from(returncode)),
    ]);
    if timed_out {
        out.insert("timed_out".into(), Value::Bool(true));
    }
    if let Some(captured) = captured {
        let truncated = captured.stdout.truncated() || captured.stderr.truncated();
        if truncated {
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
    }
    if let Some(error) = kill_error {
        out.insert("cleanup_error".into(), Value::String(error));
    }
    out
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

#[cfg(unix)]
fn kill_group(pid: Option<u32>) -> Option<String> {
    let Some(pid) = pid else {
        return Some("child PID was unavailable; process group could not be killed".into());
    };
    let process_group = nix::unistd::Pid::from_raw(pid.cast_signed());
    match nix::sys::signal::killpg(process_group, nix::sys::signal::Signal::SIGKILL) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => None,
        Err(error) => {
            let message = format!("failed killing timed-out process group {pid}: {error}");
            tracing::warn!(%message);
            Some(message)
        }
    }
}

#[cfg(not(unix))]
fn kill_group(_pid: Option<u32>) -> Option<String> {
    None
}

#[derive(Debug)]
struct ProcessGroupGuard {
    pid: Option<u32>,
    armed: bool,
}

impl ProcessGroupGuard {
    const fn new(pid: Option<u32>) -> Self {
        Self { pid, armed: true }
    }

    const fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        if self.armed
            && let Some(error) = kill_group(self.pid)
        {
            tracing::warn!(%error, "failed cleaning process group after command cancellation");
        }
    }
}

/// # Errors
/// Returns an error when process setup, execution, timeout handling, or output capture fails.
pub async fn run_argv(
    policy: &Policy,
    argv: &[String],
    timeout_duration: Duration,
    cwd: Option<&Path>,
    env: Option<&Map<String, Value>>,
) -> HandlerResult {
    let Some(program) = argv.first() else {
        return Err(HandlerError::new("invalid_payload", "empty command argv"));
    };
    let start = Instant::now();
    let mut cmd = Command::new(program);
    cmd.args(&argv[1..])
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    #[cfg(unix)]
    cmd.process_group(0);
    policy.tooling.configure_tokio(&mut cmd)?;

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

    let mut child = cmd.spawn().map_err(|error| {
        HandlerError::new(
            "exec_failed",
            format!("failed starting {:?}: {error}", argv.first()),
        )
    })?;
    let pid = child.id();
    let mut process_group_guard = ProcessGroupGuard::new(pid);
    let wait_outcome =
        match wait_bounded(&mut child, timeout_duration, policy.exec_capture_max_bytes).await {
            Ok(outcome) => outcome,
            Err(error) => {
                let kill_error = kill_group(pid);
                process_group_guard.disarm();
                if let Err(wait_error) = child.wait().await {
                    tracing::warn!(%wait_error, "failed reaping child after output-capture error");
                }
                let mut details = Map::new();
                if let Some(kill_error) = kill_error {
                    details.insert("cleanup_error".into(), Value::String(kill_error));
                }
                return Err(HandlerError::with_details(
                    "exec_failed",
                    format!("command output capture failed: {error}"),
                    details,
                ));
            }
        };

    match wait_outcome {
        WaitOutcome::Completed(captured) => {
            process_group_guard.disarm();
            let rc = captured.status.code().unwrap_or(-1);
            Ok(result(
                merged_output(&captured),
                rounded_seconds(start),
                rc,
                false,
                Some(&captured),
                None,
            ))
        }
        WaitOutcome::TimedOut => {
            let kill_error = kill_group(pid);
            process_group_guard.disarm();
            if let Err(error) = child.wait().await {
                tracing::warn!(%error, "failed reaping timed-out child");
            }
            Ok(result(
                "⏱️ Timeout".into(),
                rounded_seconds(start),
                -1,
                true,
                None,
                kill_error,
            ))
        }
    }
}

/// # Errors
/// Returns an error when the shell command is invalid, disallowed, or execution fails.
pub async fn run_shell(
    policy: &Policy,
    command: &str,
    timeout_duration: Duration,
    cwd: Option<&str>,
    env: Option<&Map<String, Value>>,
) -> HandlerResult {
    let bash = policy.tooling.command("bash").display().to_string();
    run_argv(
        policy,
        &[bash, "-lc".into(), command.into()],
        timeout_duration,
        cwd.map(Path::new),
        env,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TestResult, TestValue as _};

    const SUCCESS_TEST_TIMEOUT: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn shell_merges_stdout_and_stderr_like_python_core() -> TestResult {
        let result = run_shell(
            &Policy::default(),
            "printf out; printf err >&2",
            SUCCESS_TEST_TIMEOUT,
            None,
            None,
        )
        .await
        .test_value()?;
        assert_eq!(result["returncode"], 0);
        assert_eq!(result["output"], "out\nerr");

        Ok(())
    }

    #[tokio::test]
    async fn empty_output_uses_legacy_marker() -> TestResult {
        let result = run_shell(&Policy::default(), "true", SUCCESS_TEST_TIMEOUT, None, None)
            .await
            .test_value()?;
        assert_eq!(result["output"], "⚠️ Sin salida");

        Ok(())
    }

    #[tokio::test]
    async fn timeout_is_structured() -> TestResult {
        let result = run_shell(
            &Policy::default(),
            "sleep 10",
            Duration::from_millis(30),
            None,
            None,
        )
        .await
        .test_value()?;
        assert_eq!(result["returncode"], -1);
        assert_eq!(result["timed_out"], true);

        Ok(())
    }

    #[tokio::test]
    async fn huge_output_is_bounded_and_reported() -> TestResult {
        let policy = Policy {
            exec_capture_max_bytes: 64 * 1024,
            ..Policy::default()
        };
        let result = run_shell(
            &policy,
            "yes X | head -c 1000000",
            SUCCESS_TEST_TIMEOUT,
            None,
            None,
        )
        .await
        .test_value()?;
        assert_eq!(result["returncode"], 0);
        assert_eq!(result["output_truncated"], true);
        assert_eq!(result["stdout_bytes"], 1_000_000);
        assert!(result["output"].as_str().test_value()?.len() < 80_000);

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn process_is_alive(pid: u32) -> bool {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            return false;
        };
        stat.rsplit_once(") ")
            .and_then(|(_, rest)| rest.chars().next())
            .is_some_and(|state| state != 'Z')
    }

    #[cfg(target_os = "linux")]
    async fn wait_for_process_exit(pid: u32) -> bool {
        let deadline = Instant::now() + Duration::from_secs(3);
        while process_is_alive(pid) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        !process_is_alive(pid)
    }

    #[cfg(target_os = "linux")]
    async fn child_pid_from(path: &Path) -> TestResult<u32> {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Ok(text) = std::fs::read_to_string(path)
                && let Ok(pid) = text.trim().parse::<u32>()
            {
                return Ok(pid);
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::other("child PID file was not written").into());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn timeout_kills_detached_descendants() -> TestResult {
        let dir = tempfile::tempdir().test_value()?;
        let pidfile = dir.path().join("child.pid");
        let mut env = Map::new();
        env.insert(
            "PIDFILE".into(),
            Value::String(pidfile.display().to_string()),
        );
        let result = run_shell(
            &Policy::default(),
            r#"sleep 60 >/dev/null 2>&1 & echo $! > "$PIDFILE"; wait"#,
            Duration::from_millis(500),
            None,
            Some(&env),
        )
        .await
        .test_value()?;

        assert_eq!(result["returncode"], -1);
        let pid = child_pid_from(&pidfile).await?;
        assert!(
            wait_for_process_exit(pid).await,
            "descendant {pid} survived timeout"
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn timeout_is_not_held_open_by_descendant_pipes() -> TestResult {
        let started = Instant::now();
        let result = run_shell(
            &Policy::default(),
            "sleep 20 & sleep 20 & wait",
            Duration::from_millis(100),
            None,
            None,
        )
        .await
        .test_value()?;

        assert_eq!(result["returncode"], -1);
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "timeout waited for descendant pipes: {:?}",
            started.elapsed()
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cancellation_kills_the_whole_process_group() -> TestResult {
        let dir = tempfile::tempdir().test_value()?;
        let pidfile = dir.path().join("child.pid");
        let pidfile_for_task = pidfile.clone();
        let task = tokio::spawn(async move {
            let mut env = Map::new();
            env.insert(
                "PIDFILE".into(),
                Value::String(pidfile_for_task.display().to_string()),
            );
            run_shell(
                &Policy::default(),
                r#"sleep 60 >/dev/null 2>&1 & echo $! > "$PIDFILE"; wait"#,
                Duration::from_secs(30),
                None,
                Some(&env),
            )
            .await
        });

        let pid = child_pid_from(&pidfile).await?;
        assert!(process_is_alive(pid), "fixture descendant was not alive");
        task.abort();
        let join_error = match task.await {
            Err(error) => error,
            Ok(result) => {
                return Err(std::io::Error::other(format!(
                    "cancelled exec unexpectedly completed: {result:?}"
                ))
                .into());
            }
        };
        assert!(join_error.is_cancelled());
        assert!(
            wait_for_process_exit(pid).await,
            "descendant {pid} survived cancellation"
        );
        Ok(())
    }
}
