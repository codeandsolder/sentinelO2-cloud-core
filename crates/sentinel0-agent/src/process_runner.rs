use crate::{
    handler_error::HandlerError,
    policy::Policy,
    process_output::{
        CapturedOutput, POST_TIMEOUT_GRACE, TimedOutOutput, WaitOutcome, wait_bounded_with_limits,
    },
};
use serde_json::{Map, Value};
use std::{
    ffi::OsString,
    io,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{io::AsyncWriteExt as _, process::Command, task::JoinHandle};

#[derive(Clone, Debug)]
pub enum ProcessGroupKill {
    Direct,
    Sudo { command: PathBuf, path: OsString },
}

impl ProcessGroupKill {
    /// # Errors
    /// Returns an error when the configured tool search path cannot be represented safely.
    pub fn sudo(policy: &Policy) -> Result<Self, HandlerError> {
        Ok(Self::Sudo {
            command: policy.tooling.command("sudo"),
            path: policy.tooling.path_env()?,
        })
    }

    #[cfg(unix)]
    fn direct_kill(pid: Option<u32>) -> Option<String> {
        let Some(pid) = pid else {
            return Some("child PID was unavailable; process group could not be killed".into());
        };
        let process_group = nix::unistd::Pid::from_raw(pid.cast_signed());
        match nix::sys::signal::killpg(process_group, nix::sys::signal::Signal::SIGKILL) {
            Ok(()) | Err(nix::errno::Errno::ESRCH) => None,
            Err(error) => Some(format!("failed killing process group {pid}: {error}")),
        }
    }

    #[cfg(not(unix))]
    fn direct_kill(_pid: Option<u32>) -> Option<String> {
        None
    }

    #[cfg(unix)]
    async fn kill(&self, pid: Option<u32>) -> Option<String> {
        match self {
            Self::Direct => Self::direct_kill(pid),
            Self::Sudo { command, path } => {
                let Some(pid) = pid else {
                    return Some(
                        "child PID was unavailable; process group could not be killed".into(),
                    );
                };
                let kill = Command::new(command)
                    .args(["-n", "kill", "-9", "--", &format!("-{pid}")])
                    .env("PATH", path)
                    .status();
                match tokio::time::timeout(POST_TIMEOUT_GRACE, kill).await {
                    Ok(Ok(status)) if status.success() => None,
                    Ok(Ok(status)) => Some(format!(
                        "sudo kill of process group {pid} exited with {status}"
                    )),
                    Ok(Err(error)) => Some(format!(
                        "failed invoking sudo kill for process group {pid}: {error}"
                    )),
                    Err(_) => Some(format!("timed out killing sudo process group {pid}")),
                }
            }
        }
    }

    #[cfg(not(unix))]
    async fn kill(&self, _pid: Option<u32>) -> Option<String> {
        None
    }

    #[cfg(unix)]
    fn kill_blocking(&self, pid: Option<u32>) -> Option<String> {
        match self {
            Self::Direct => Self::direct_kill(pid),
            Self::Sudo { command, path } => {
                let Some(pid) = pid else {
                    return Some(
                        "child PID was unavailable; process group could not be killed".into(),
                    );
                };
                match std::process::Command::new(command)
                    .args(["-n", "kill", "-9", "--", &format!("-{pid}")])
                    .env("PATH", path)
                    .status()
                {
                    Ok(status) if status.success() => None,
                    Ok(status) => Some(format!(
                        "sudo kill of process group {pid} exited with {status}"
                    )),
                    Err(error) => Some(format!(
                        "failed invoking sudo kill for process group {pid}: {error}"
                    )),
                }
            }
        }
    }

    #[cfg(not(unix))]
    fn kill_blocking(&self, _pid: Option<u32>) -> Option<String> {
        None
    }
}

#[derive(Debug)]
pub(crate) struct ProcessGroupGuard {
    pid: Option<u32>,
    killer: ProcessGroupKill,
    armed: bool,
}

impl ProcessGroupGuard {
    pub(crate) const fn new(pid: Option<u32>, killer: ProcessGroupKill) -> Self {
        Self {
            pid,
            killer,
            armed: true,
        }
    }

    pub(crate) const fn disarm(&mut self) {
        self.armed = false;
    }

    pub(crate) async fn kill(&mut self) -> Option<String> {
        let error = self.killer.kill(self.pid).await;
        self.armed = false;
        error
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        if self.armed
            && let Some(error) = self.killer.kill_blocking(self.pid)
        {
            tracing::warn!(%error, "failed cleaning process group after command cancellation");
        }
    }
}

#[derive(Debug)]
pub enum ProcessFailure {
    Setup(HandlerError),
    Spawn(io::Error),
    Capture {
        error: io::Error,
        cleanup_error: Option<String>,
    },
}

#[derive(Debug)]
pub enum ProcessOutcome {
    Completed {
        captured: CapturedOutput,
        duration: f64,
    },
    TimedOut {
        captured: TimedOutOutput,
        duration: f64,
        cleanup_error: Option<String>,
    },
}

fn rounded_seconds(started: Instant) -> f64 {
    let seconds = started.elapsed().as_secs_f64();
    (seconds * 100.0).round() / 100.0
}

async fn finish_stdin_write(task: Option<JoinHandle<io::Result<()>>>) -> io::Result<()> {
    let Some(task) = task else {
        return Ok(());
    };
    task.await
        .map_err(|error| io::Error::other(format!("stdin writer task failed: {error}")))?
}

#[derive(Debug)]
pub struct RunOptions<'a> {
    pub cwd: Option<&'a Path>,
    pub env: Option<&'a Map<String, Value>>,
    pub stdin: Option<&'a [u8]>,
    pub stdout_limit: usize,
    pub stderr_limit: usize,
    pub killer: ProcessGroupKill,
}

fn configure_command(
    policy: &Policy,
    argv: &[String],
    options: &RunOptions<'_>,
) -> Result<Command, ProcessFailure> {
    let Some(program) = argv.first() else {
        return Err(ProcessFailure::Setup(HandlerError::new(
            "invalid_payload",
            "empty command argv",
        )));
    };
    let mut command = Command::new(program);
    command
        .args(&argv[1..])
        .kill_on_drop(true)
        .stdin(if options.stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    command.process_group(0);
    policy
        .tooling
        .configure_tokio(&mut command)
        .map_err(ProcessFailure::Setup)?;
    if let Some(cwd) = options.cwd {
        command.current_dir(cwd);
    }
    if let Some(env) = options.env {
        for (key, value) in env {
            if let Some(value) = value.as_str() {
                command.env(key, value);
            }
        }
    }
    Ok(command)
}

/// # Errors
/// Returns a typed failure for setup, spawn, input/output I/O, or process cleanup failures.
pub async fn run_argv_with_limits(
    policy: &Policy,
    argv: &[String],
    timeout_duration: Duration,
    options: RunOptions<'_>,
) -> Result<ProcessOutcome, ProcessFailure> {
    let mut command = configure_command(policy, argv, &options)?;
    let started = Instant::now();
    let mut child = command.spawn().map_err(ProcessFailure::Spawn)?;
    let mut group = ProcessGroupGuard::new(child.id(), options.killer);
    let stdin_task = if let Some(input) = options.stdin {
        let mut pipe = child.stdin.take().ok_or_else(|| ProcessFailure::Capture {
            error: io::Error::other("child stdin was not piped"),
            cleanup_error: None,
        })?;
        let input = input.to_vec();
        Some(tokio::spawn(async move {
            pipe.write_all(&input).await?;
            drop(pipe);
            Ok(())
        }))
    } else {
        None
    };

    let wait_outcome = match wait_bounded_with_limits(
        &mut child,
        timeout_duration,
        options.stdout_limit,
        options.stderr_limit,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            let kill_error = group.kill().await;
            let _ = finish_stdin_write(stdin_task).await;
            let reap_error = match tokio::time::timeout(POST_TIMEOUT_GRACE, child.wait()).await {
                Ok(Ok(_)) => None,
                Ok(Err(wait_error)) => {
                    tracing::warn!(%wait_error, "failed reaping child after output-capture error");
                    Some(format!(
                        "failed reaping child after output-capture error: {wait_error}"
                    ))
                }
                Err(_) => Some("timed out reaping child after output-capture error".into()),
            };
            return Err(ProcessFailure::Capture {
                error,
                cleanup_error: crate::process_output::combine_cleanup_errors(
                    kill_error, reap_error,
                ),
            });
        }
    };

    match wait_outcome {
        WaitOutcome::Completed(captured) => {
            group.disarm();
            if let Err(error) = finish_stdin_write(stdin_task).await {
                return Err(ProcessFailure::Capture {
                    error,
                    cleanup_error: None,
                });
            }
            Ok(ProcessOutcome::Completed {
                captured,
                duration: rounded_seconds(started),
            })
        }
        WaitOutcome::TimedOut(pending) => {
            let cleanup_started = Instant::now();
            let kill_error = group.kill().await;
            let _ = finish_stdin_write(stdin_task).await;
            let remaining = POST_TIMEOUT_GRACE.saturating_sub(cleanup_started.elapsed());
            let captured = pending.finish_after_kill(&mut child, remaining).await;
            Ok(ProcessOutcome::TimedOut {
                duration: rounded_seconds(started),
                cleanup_error: crate::process_output::combine_cleanup_errors(
                    kill_error,
                    captured.capture_error.clone(),
                ),
                captured,
            })
        }
    }
}

/// # Errors
/// Returns a typed failure for setup, spawn, output capture, or process cleanup failures.
pub async fn run_argv(
    policy: &Policy,
    argv: &[String],
    timeout_duration: Duration,
    cwd: Option<&Path>,
    env: Option<&Map<String, Value>>,
    killer: ProcessGroupKill,
) -> Result<ProcessOutcome, ProcessFailure> {
    let per_stream = (policy.exec_capture_max_bytes / 2).max(1024);
    run_argv_with_limits(
        policy,
        argv,
        timeout_duration,
        RunOptions {
            cwd,
            env,
            stdin: None,
            stdout_limit: per_stream,
            stderr_limit: per_stream,
            killer,
        },
    )
    .await
}
