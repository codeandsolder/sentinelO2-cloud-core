#[cfg(test)]
use crate::process_output::LEFT_RUNNING_NOTE;
use crate::{
    handler_error::{HandlerError, HandlerResult},
    policy::Policy,
    process_output::{
        add_capture_metadata, add_timeout_metadata, merged_output, process_result, timeout_output,
    },
    process_runner::{self, ProcessFailure, ProcessGroupKill, ProcessOutcome},
};
use serde_json::{Map, Value};
#[cfg(test)]
use std::time::Instant;
use std::{path::Path, time::Duration};

/// # Errors
/// Returns an error when process setup, execution, timeout handling, or output capture fails.
pub async fn run_argv(
    policy: &Policy,
    argv: &[String],
    timeout_duration: Duration,
    cwd: Option<&Path>,
    env: Option<&Map<String, Value>>,
) -> HandlerResult {
    let outcome = process_runner::run_argv(
        policy,
        argv,
        timeout_duration,
        cwd,
        env,
        ProcessGroupKill::Direct,
    )
    .await;

    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(ProcessFailure::Setup(error)) => return Err(error),
        Err(ProcessFailure::Spawn(error)) => {
            return Err(HandlerError::new(
                "exec_failed",
                format!("failed starting {:?}: {error}", argv.first()),
            ));
        }
        Err(ProcessFailure::Capture {
            error,
            cleanup_error,
        }) => {
            let mut details = Map::new();
            if let Some(cleanup_error) = cleanup_error {
                details.insert("cleanup_error".into(), Value::String(cleanup_error));
            }
            return Err(HandlerError::with_details(
                "exec_failed",
                format!("command output capture failed: {error}"),
                details,
            ));
        }
    };

    match outcome {
        ProcessOutcome::Completed { captured, duration } => {
            let rc = captured.status.code().unwrap_or(-1);
            let mut out = process_result(merged_output(&captured), duration, rc);
            add_capture_metadata(&mut out, &captured.stdout, &captured.stderr);
            Ok(out)
        }
        ProcessOutcome::TimedOut {
            captured,
            duration,
            cleanup_error,
        } => {
            let mut out = process_result(timeout_output(&captured), duration, -1);
            add_timeout_metadata(&mut out, &captured, cleanup_error);
            Ok(out)
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
    async fn nonzero_exit_is_not_reported_as_ok() -> TestResult {
        let result = run_shell(
            &Policy::default(),
            "exit 7",
            SUCCESS_TEST_TIMEOUT,
            None,
            None,
        )
        .await
        .test_value()?;
        assert_eq!(result["returncode"], 7);
        assert_eq!(result["ok"], false);

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
        assert_eq!(result["output"], "⏱️ Timeout");
        assert!(!result.contains_key("left_running"));

        Ok(())
    }

    #[tokio::test]
    async fn timeout_keeps_output_written_before_deadline() -> TestResult {
        let result = run_shell(
            &Policy::default(),
            "printf 'step1\n'; printf 'err1\n' >&2; sleep 10",
            Duration::from_secs(1),
            None,
            None,
        )
        .await
        .test_value()?;
        let output = result["output"].as_str().test_value()?;
        assert!(output.starts_with("⏱️ Timeout. Output written before the timeout:"));
        assert!(output.contains("step1"));
        assert!(output.contains("err1"));
        assert!(!result.contains_key("left_running"));

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
    #[derive(Clone, Copy, Debug)]
    struct ProcessStamp {
        pid: u32,
        start_time: u64,
    }

    #[cfg(target_os = "linux")]
    fn parse_process_stat(stat: &str) -> Option<(ProcessStamp, char)> {
        let (pid_and_name, fields) = stat.rsplit_once(") ")?;
        let pid = pid_and_name.split_once(' ')?.0.parse().ok()?;
        let mut fields = fields.split_whitespace();
        let state = fields.next()?.chars().next()?;
        let start_time = fields.nth(18)?.parse().ok()?;
        Some((ProcessStamp { pid, start_time }, state))
    }

    #[cfg(target_os = "linux")]
    fn same_process_is_alive(stamp: ProcessStamp) -> bool {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", stamp.pid)) else {
            return false;
        };
        parse_process_stat(&stat)
            .is_some_and(|(current, state)| current.start_time == stamp.start_time && state != 'Z')
    }

    #[cfg(target_os = "linux")]
    async fn wait_for_process_exit(stamp: ProcessStamp) -> bool {
        let deadline = Instant::now() + Duration::from_secs(3);
        while same_process_is_alive(stamp) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        !same_process_is_alive(stamp)
    }

    #[cfg(target_os = "linux")]
    async fn child_stamp_from(path: &Path) -> TestResult<ProcessStamp> {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Ok(stat) = std::fs::read_to_string(path)
                && let Some((stamp, _)) = parse_process_stat(&stat)
            {
                return Ok(stamp);
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::other("child process stamp was not written").into());
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
            r#"sleep 60 >/dev/null 2>&1 & cat "/proc/$!/stat" > "$PIDFILE"; wait"#,
            Duration::from_millis(500),
            None,
            Some(&env),
        )
        .await
        .test_value()?;

        assert_eq!(result["returncode"], -1);
        let stamp = child_stamp_from(&pidfile).await?;
        assert!(
            wait_for_process_exit(stamp).await,
            "descendant {} survived timeout",
            stamp.pid
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn escaped_descendant_is_reported_without_extending_timeout_indefinitely() -> TestResult {
        let dir = tempfile::tempdir().test_value()?;
        let pidfile = dir.path().join("escaped.pid");
        let mut env = Map::new();
        env.insert(
            "PIDFILE".into(),
            Value::String(pidfile.display().to_string()),
        );
        let started = Instant::now();
        let result = run_shell(
            &Policy::default(),
            r#"setsid sleep 60 & cat "/proc/$!/stat" > "$PIDFILE"; echo started; sleep 60"#,
            Duration::from_secs(1),
            None,
            Some(&env),
        )
        .await
        .test_value()?;

        assert!(
            started.elapsed() < Duration::from_secs(8),
            "escaped descendant extended timeout too far: {:?}",
            started.elapsed()
        );
        assert_eq!(result["timed_out"], true);
        assert_eq!(result["left_running"], true);
        let output = result["output"].as_str().test_value()?;
        assert!(output.starts_with("⏱️ Timeout. Output written before the timeout:"));
        assert!(output.contains("started"));
        assert!(output.contains(LEFT_RUNNING_NOTE));

        let stamp = child_stamp_from(&pidfile).await?;
        let escaped = nix::unistd::Pid::from_raw(stamp.pid.cast_signed());
        match nix::sys::signal::kill(escaped, nix::sys::signal::Signal::SIGKILL) {
            Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
            Err(error) => return Err(error.into()),
        }
        assert!(wait_for_process_exit(stamp).await);
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
                r#"sleep 60 >/dev/null 2>&1 & cat "/proc/$!/stat" > "$PIDFILE"; wait"#,
                Duration::from_secs(30),
                None,
                Some(&env),
            )
            .await
        });

        let stamp = child_stamp_from(&pidfile).await?;
        assert!(
            same_process_is_alive(stamp),
            "fixture descendant was not alive"
        );
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
            wait_for_process_exit(stamp).await,
            "descendant {} survived cancellation",
            stamp.pid
        );
        Ok(())
    }
}
