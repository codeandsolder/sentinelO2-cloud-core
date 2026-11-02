use crate::{
    handler_error::HandlerError,
    policy::Policy,
    process_output::{
        CapturedOutput, POST_TIMEOUT_GRACE, TimedOutOutput, WaitOutcome, wait_bounded_with_limits,
    },
};
use serde_json::{Map, Value};
use std::{
    collections::{HashSet, VecDeque},
    env,
    ffi::OsString,
    fmt::Write as _,
    io,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{io::AsyncWriteExt as _, process::Command, task::JoinHandle};

#[cfg(unix)]
use wait_timeout::ChildExt as _;

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
struct ProcessIdentity {
    pid: u32,
    start_time: u64,
}

#[cfg(target_os = "linux")]
fn process_identity(pid: u32) -> Option<ProcessIdentity> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, fields) = stat.rsplit_once(") ")?;
    let mut fields = fields.split_whitespace();
    let _state = fields.next()?;
    let start_time = fields.nth(18)?.parse().ok()?;
    Some(ProcessIdentity { pid, start_time })
}

#[cfg(target_os = "linux")]
fn child_pids(pid: u32) -> Vec<u32> {
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for task in tasks.flatten() {
        let children = task.path().join("children");
        let Ok(raw) = std::fs::read_to_string(children) else {
            continue;
        };
        out.extend(
            raw.split_whitespace()
                .filter_map(|value| value.parse::<u32>().ok()),
        );
    }
    out
}

#[cfg(target_os = "linux")]
fn descendant_snapshot(root: Option<u32>) -> Vec<ProcessIdentity> {
    let Some(root) = root else {
        return Vec::new();
    };
    let mut seen = HashSet::from([root]);
    let mut queue = VecDeque::from([root]);
    let mut out = Vec::new();
    while let Some(parent) = queue.pop_front() {
        for pid in child_pids(parent) {
            if !seen.insert(pid) {
                continue;
            }
            if let Some(identity) = process_identity(pid) {
                out.push(identity);
                queue.push_back(pid);
            }
        }
    }
    out
}

#[cfg(not(target_os = "linux"))]
#[derive(Clone, Copy, Debug)]
struct ProcessIdentity {
    pid: u32,
}

#[cfg(not(target_os = "linux"))]
fn descendant_snapshot(_root: Option<u32>) -> Vec<ProcessIdentity> {
    Vec::new()
}

#[cfg(target_os = "linux")]
fn identity_is_current(identity: ProcessIdentity) -> bool {
    process_identity(identity.pid).is_some_and(|current| current.start_time == identity.start_time)
}

#[cfg(not(target_os = "linux"))]
const fn identity_is_current(_identity: ProcessIdentity) -> bool {
    false
}

fn combine_messages(left: Option<String>, right: Option<String>) -> Option<String> {
    match (left, right) {
        (None, None) => None,
        (Some(value), None) | (None, Some(value)) => Some(value),
        (Some(left), Some(right)) => Some(format!("{left}; {right}")),
    }
}

fn fallback_result(
    primary_error: Option<String>,
    fallback_error: Option<String>,
) -> Option<String> {
    if primary_error.is_none() || fallback_error.is_none() {
        None
    } else {
        combine_messages(primary_error, fallback_error)
    }
}

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
    fn direct_kill_group(pid: Option<u32>) -> Option<String> {
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
    fn direct_kill_group(_pid: Option<u32>) -> Option<String> {
        None
    }

    #[cfg(unix)]
    fn direct_kill_descendants(descendants: &[ProcessIdentity]) -> Option<String> {
        let mut errors = Vec::new();
        for identity in descendants.iter().copied() {
            if !identity_is_current(identity) {
                continue;
            }
            let pid = nix::unistd::Pid::from_raw(identity.pid.cast_signed());
            if let Err(error) = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL)
                && error != nix::errno::Errno::ESRCH
            {
                errors.push(format!("{}: {error}", identity.pid));
            }
        }
        (!errors.is_empty())
            .then(|| format!("failed killing descendant PIDs: {}", errors.join(", ")))
    }

    #[cfg(not(unix))]
    fn direct_kill_descendants(_descendants: &[ProcessIdentity]) -> Option<String> {
        None
    }

    #[cfg(unix)]
    async fn sudo_kill(
        command: &Path,
        path: &std::ffi::OsStr,
        targets: &[String],
    ) -> Option<String> {
        if targets.is_empty() {
            return None;
        }
        let mut kill = Command::new(command);
        kill.args(["-n", "kill", "-9", "--"])
            .args(targets)
            .env("PATH", path);
        match tokio::time::timeout(POST_TIMEOUT_GRACE, kill.status()).await {
            Ok(Ok(status)) if status.success() => None,
            Ok(Ok(status)) => Some(format!("sudo kill exited with {status}")),
            Ok(Err(error)) => Some(format!("failed invoking sudo kill: {error}")),
            Err(_) => Some("timed out invoking sudo kill".into()),
        }
    }

    #[cfg(unix)]
    fn sudo_kill_blocking(
        command: &Path,
        path: &std::ffi::OsStr,
        targets: &[String],
    ) -> Option<String> {
        if targets.is_empty() {
            return None;
        }
        let mut child = match std::process::Command::new(command)
            .args(["-n", "kill", "-9", "--"])
            .args(targets)
            .env("PATH", path)
            .spawn()
        {
            Ok(child) => child,
            Err(error) => return Some(format!("failed invoking sudo kill: {error}")),
        };
        match child.wait_timeout(POST_TIMEOUT_GRACE) {
            Ok(Some(status)) if status.success() => None,
            Ok(Some(status)) => Some(format!("sudo kill exited with {status}")),
            Ok(None) => {
                let kill_error = child.kill().err();
                let wait_error = child.wait().err();
                let mut message = "timed out invoking sudo kill".to_owned();
                if let Some(error) = kill_error {
                    let _ = write!(message, "; failed killing sudo helper: {error}");
                }
                if let Some(error) = wait_error {
                    let _ = write!(message, "; failed reaping sudo helper: {error}");
                }
                Some(message)
            }
            Err(error) => Some(format!("failed waiting for sudo kill: {error}")),
        }
    }

    #[cfg(unix)]
    async fn kill(&self, pid: Option<u32>) -> Option<String> {
        // Snapshot first: a child may call setsid(2) and escape the process group,
        // but it is still visible through /proc while its ancestor is alive.
        let descendants = descendant_snapshot(pid);
        match self {
            Self::Direct => combine_messages(
                Self::direct_kill_group(pid),
                Self::direct_kill_descendants(&descendants),
            ),
            Self::Sudo { command, path } => {
                let group_target = pid.map(|pid| format!("-{pid}"));
                let group_error = if let Some(target) = group_target {
                    let sudo_error = Self::sudo_kill(command, path, &[target]).await;
                    if sudo_error.is_some() {
                        // A sudo failure is not proof that cleanup failed: the
                        // process may still belong to the agent user.
                        fallback_result(sudo_error, Self::direct_kill_group(pid))
                    } else {
                        None
                    }
                } else {
                    Some("child PID was unavailable; process group could not be killed".into())
                };

                let targets = descendants
                    .iter()
                    .copied()
                    .filter(|identity| identity_is_current(*identity))
                    .map(|identity| identity.pid.to_string())
                    .collect::<Vec<_>>();
                let descendant_error = if targets.is_empty() {
                    None
                } else {
                    let sudo_error = Self::sudo_kill(command, path, &targets).await;
                    if sudo_error.is_some() {
                        fallback_result(sudo_error, Self::direct_kill_descendants(&descendants))
                    } else {
                        None
                    }
                };
                combine_messages(group_error, descendant_error)
            }
        }
    }

    #[cfg(not(unix))]
    async fn kill(&self, _pid: Option<u32>) -> Option<String> {
        None
    }

    #[cfg(unix)]
    fn sudo_kill_group_blocking(
        command: &Path,
        path: &std::ffi::OsStr,
        pid: Option<u32>,
    ) -> Option<String> {
        let Some(pid) = pid else {
            return Some("child PID was unavailable; process group could not be killed".into());
        };
        let target = format!("-{pid}");
        let sudo_error = Self::sudo_kill_blocking(command, path, &[target]);
        if sudo_error.is_some() {
            fallback_result(sudo_error, Self::direct_kill_group(Some(pid)))
        } else {
            None
        }
    }

    #[cfg(unix)]
    fn kill_blocking(&self, pid: Option<u32>) -> Option<String> {
        let descendants = descendant_snapshot(pid);
        match self {
            Self::Direct => combine_messages(
                Self::direct_kill_group(pid),
                Self::direct_kill_descendants(&descendants),
            ),
            Self::Sudo { command, path } => {
                let group_error = Self::sudo_kill_group_blocking(command, path, pid);
                let targets = descendants
                    .iter()
                    .copied()
                    .filter(|identity| identity_is_current(*identity))
                    .map(|identity| identity.pid.to_string())
                    .collect::<Vec<_>>();
                let descendant_error = if targets.is_empty() {
                    None
                } else {
                    let sudo_error = Self::sudo_kill_blocking(command, path, &targets);
                    if sudo_error.is_some() {
                        fallback_result(sudo_error, Self::direct_kill_descendants(&descendants))
                    } else {
                        None
                    }
                };
                combine_messages(group_error, descendant_error)
            }
        }
    }

    #[cfg(not(unix))]
    fn kill_blocking(&self, _pid: Option<u32>) -> Option<String> {
        None
    }
}

#[derive(Debug)]
pub struct ProcessGroupGuard {
    pid: Option<u32>,
    killer: ProcessGroupKill,
    armed: bool,
}

impl ProcessGroupGuard {
    pub const fn new(pid: Option<u32>, killer: ProcessGroupKill) -> Self {
        Self {
            pid,
            killer,
            armed: true,
        }
    }

    pub const fn disarm(&mut self) {
        self.armed = false;
    }

    pub async fn kill(&mut self) -> Option<String> {
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
    pub sanitize_bash_startup: bool,
    pub stdin: Option<&'a [u8]>,
    pub stdout_limit: usize,
    pub stderr_limit: usize,
    pub killer: ProcessGroupKill,
}

const BASH_STARTUP_ENV: &[&str] = &[
    "BASH_ENV",
    "ENV",
    "SHELLOPTS",
    "BASHOPTS",
    "PS0",
    "PS1",
    "PS2",
    "PS3",
    "PS4",
    "PROMPT_COMMAND",
    "GLOBIGNORE",
    "EXECIGNORE",
    "IFS",
    "CDPATH",
    "BASH_XTRACEFD",
    "BASH_COMPAT",
    "POSIXLY_CORRECT",
    "BASH_LOADABLES_PATH",
    "INPUTRC",
    "HISTFILE",
];

fn sanitize_bash_startup(command: &mut Command, supplied_env: Option<&Map<String, Value>>) {
    for name in BASH_STARTUP_ENV {
        command.env_remove(name);
    }
    for (name, _) in env::vars_os() {
        if name.to_string_lossy().starts_with("BASH_FUNC_") {
            command.env_remove(name);
        }
    }
    if let Some(supplied_env) = supplied_env {
        for name in supplied_env.keys() {
            if name.starts_with("BASH_FUNC_") {
                command.env_remove(name);
            }
        }
    }
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
    if options.sanitize_bash_startup {
        sanitize_bash_startup(&mut command, options.env);
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
            sanitize_bash_startup: false,
            stdin: None,
            stdout_limit: per_stream,
            stderr_limit: per_stream,
            killer,
        },
    )
    .await
}

/// Runs a Bash argv with startup hooks and exported functions removed from its environment.
///
/// # Errors
/// Returns a typed failure for setup, spawn, input/output I/O, or process cleanup failures.
pub async fn run_bash_argv(
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
            sanitize_bash_startup: true,
            stdin: None,
            stdout_limit: per_stream,
            stderr_limit: per_stream,
            killer,
        },
    )
    .await
}
