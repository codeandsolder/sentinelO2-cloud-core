use serde_json::Value;
use std::{
    collections::{BTreeMap, VecDeque},
    io::{self, Read},
    process::ExitStatus,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _},
    process::Child,
    task::JoinHandle,
    time::timeout,
};

const READ_CHUNK: usize = 16 * 1024;
pub(crate) const POST_TIMEOUT_GRACE: Duration = Duration::from_secs(5);
pub(crate) const LEFT_RUNNING_NOTE: &str = "A process this command started didn't stop when asked (for example one running as root through sudo) and is still running on the host.";

#[derive(Clone, Debug)]
pub struct CapturedStream {
    head: Vec<u8>,
    tail: VecDeque<Vec<u8>>,
    tail_bytes: usize,
    total_bytes: u64,
    limit: usize,
}

impl CapturedStream {
    fn new(limit: usize) -> Self {
        Self {
            head: Vec::with_capacity(limit / 2),
            tail: VecDeque::new(),
            tail_bytes: 0,
            total_bytes: 0,
            limit,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        self.total_bytes = self.total_bytes.saturating_add(bytes.len() as u64);
        let head_limit = self.limit / 2;
        let missing_head = head_limit.saturating_sub(self.head.len());
        let to_head = missing_head.min(bytes.len());
        self.head.extend_from_slice(&bytes[..to_head]);

        let tail_limit = self.limit.saturating_sub(head_limit);
        if tail_limit == 0 || to_head == bytes.len() {
            return;
        }
        let remainder = &bytes[to_head..];
        if remainder.len() >= tail_limit {
            self.tail.clear();
            self.tail
                .push_back(remainder[remainder.len() - tail_limit..].to_vec());
            self.tail_bytes = tail_limit;
            return;
        }
        self.tail.push_back(remainder.to_vec());
        self.tail_bytes += remainder.len();
        while self.tail_bytes > tail_limit {
            let excess = self.tail_bytes - tail_limit;
            let Some(front) = self.tail.front_mut() else {
                break;
            };
            if front.len() <= excess {
                self.tail_bytes -= front.len();
                self.tail.pop_front();
            } else {
                front.drain(..excess);
                self.tail_bytes -= excess;
            }
        }
    }

    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.total_bytes > self.limit as u64
    }

    #[must_use]
    pub fn rendered(&self) -> Vec<u8> {
        let retained = self.head.len() + self.tail_bytes;
        let mut out = Vec::with_capacity(retained + 96);
        out.extend_from_slice(&self.head);
        if self.truncated() {
            let omitted = self.total_bytes.saturating_sub(retained as u64);
            out.extend_from_slice(
                format!("\n… [{omitted} bytes omitted by SentinelO2] …\n").as_bytes(),
            );
        }
        for chunk in &self.tail {
            out.extend_from_slice(chunk);
        }
        out
    }

    #[must_use]
    pub fn rendered_trimmed_lossy(&self) -> String {
        String::from_utf8_lossy(&self.rendered()).trim().to_owned()
    }
}

#[derive(Debug)]
pub struct CapturedOutput {
    pub status: ExitStatus,
    pub stdout: CapturedStream,
    pub stderr: CapturedStream,
}

type SharedCapturedStream = Arc<Mutex<CapturedStream>>;

#[derive(Debug)]
pub struct TimedOutCapture {
    stdout: SharedCapturedStream,
    stderr: SharedCapturedStream,
    stdout_task: JoinHandle<io::Result<()>>,
    stderr_task: JoinHandle<io::Result<()>>,
}

#[derive(Debug)]
pub struct TimedOutOutput {
    pub stdout: CapturedStream,
    pub stderr: CapturedStream,
    pub left_running: bool,
    pub capture_error: Option<String>,
}

#[derive(Debug)]
pub enum WaitOutcome {
    Completed(CapturedOutput),
    TimedOut(TimedOutCapture),
}

fn snapshot(capture: &SharedCapturedStream) -> CapturedStream {
    match capture.lock() {
        Ok(guard) => guard.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

fn join_error(error: &tokio::task::JoinError) -> io::Error {
    io::Error::other(format!("output reader task failed: {error}"))
}

async fn read_bounded_shared<R>(mut reader: R, capture: SharedCapturedStream) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = vec![0_u8; READ_CHUNK];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        match capture.lock() {
            Ok(mut guard) => guard.push(&buffer[..read]),
            Err(mut poisoned) => poisoned.get_mut().push(&buffer[..read]),
        }
    }
}

impl TimedOutCapture {
    fn new(
        stdout: impl AsyncRead + Unpin + Send + 'static,
        stderr: impl AsyncRead + Unpin + Send + 'static,
        stdout_limit: usize,
        stderr_limit: usize,
    ) -> Self {
        let stdout_capture = Arc::new(Mutex::new(CapturedStream::new(stdout_limit)));
        let stderr_capture = Arc::new(Mutex::new(CapturedStream::new(stderr_limit)));
        Self {
            stdout: Arc::clone(&stdout_capture),
            stderr: Arc::clone(&stderr_capture),
            stdout_task: tokio::spawn(read_bounded_shared(stdout, stdout_capture)),
            stderr_task: tokio::spawn(read_bounded_shared(stderr, stderr_capture)),
        }
    }

    async fn wait_until_drained(&mut self, child: &mut Child) -> io::Result<ExitStatus> {
        let (status, stdout, stderr) =
            tokio::join!(child.wait(), &mut self.stdout_task, &mut self.stderr_task);
        let status = status?;
        stdout.map_err(|error| join_error(&error))??;
        stderr.map_err(|error| join_error(&error))??;
        Ok(status)
    }

    async fn abort_readers(&mut self) {
        self.stdout_task.abort();
        self.stderr_task.abort();
        let _ = (&mut self.stdout_task).await;
        let _ = (&mut self.stderr_task).await;
    }

    #[must_use]
    fn output(&self, left_running: bool, capture_error: Option<String>) -> TimedOutOutput {
        TimedOutOutput {
            stdout: snapshot(&self.stdout),
            stderr: snapshot(&self.stderr),
            left_running,
            capture_error,
        }
    }

    /// Waits only `grace` for a killed process and inherited output pipes to close.
    pub async fn finish_after_kill(mut self, child: &mut Child, grace: Duration) -> TimedOutOutput {
        match timeout(grace, self.wait_until_drained(child)).await {
            Ok(Ok(_)) => self.output(false, None),
            Ok(Err(error)) => {
                self.abort_readers().await;
                let left_running = child.try_wait().map_or(true, |status| status.is_none());
                self.output(left_running, Some(error.to_string()))
            }
            Err(_) => {
                self.abort_readers().await;
                self.output(true, None)
            }
        }
    }
}

impl Drop for TimedOutCapture {
    fn drop(&mut self) {
        self.stdout_task.abort();
        self.stderr_task.abort();
    }
}

#[must_use]
pub(crate) fn merge_streams(stdout: &CapturedStream, stderr: &CapturedStream) -> String {
    let stdout = stdout.rendered_trimmed_lossy();
    let stderr = stderr.rendered_trimmed_lossy();
    if stderr.is_empty() {
        stdout
    } else if stdout.is_empty() {
        stderr
    } else {
        format!("{stdout}\n{stderr}")
    }
}

#[must_use]
pub(crate) fn merged_output(captured: &CapturedOutput) -> String {
    let output = merge_streams(&captured.stdout, &captured.stderr);
    if output.is_empty() {
        "⚠️ Sin salida".into()
    } else {
        output
    }
}

#[must_use]
pub(crate) fn timeout_output(captured: &TimedOutOutput) -> String {
    let partial = merge_streams(&captured.stdout, &captured.stderr);
    let mut output = if partial.is_empty() {
        "⏱️ Timeout".to_owned()
    } else {
        format!("⏱️ Timeout. Output written before the timeout:\n{partial}")
    };
    if captured.left_running {
        output.push('\n');
        output.push_str(LEFT_RUNNING_NOTE);
    }
    output
}

#[must_use]
pub(crate) fn process_result(
    output: String,
    duration: f64,
    returncode: i32,
) -> BTreeMap<String, Value> {
    BTreeMap::from([
        ("ok".into(), Value::Bool(returncode == 0)),
        ("output".into(), Value::String(output)),
        ("duration".into(), Value::from(duration)),
        ("returncode".into(), Value::from(returncode)),
    ])
}

pub(crate) fn add_capture_metadata(
    out: &mut BTreeMap<String, Value>,
    stdout: &CapturedStream,
    stderr: &CapturedStream,
) {
    if stdout.truncated() || stderr.truncated() {
        out.insert("output_truncated".into(), Value::Bool(true));
        out.insert("stdout_bytes".into(), Value::from(stdout.total_bytes()));
        out.insert("stderr_bytes".into(), Value::from(stderr.total_bytes()));
    }
}

pub(crate) fn add_timeout_metadata(
    out: &mut BTreeMap<String, Value>,
    captured: &TimedOutOutput,
    cleanup_error: Option<String>,
) {
    out.insert("timed_out".into(), Value::Bool(true));
    add_capture_metadata(out, &captured.stdout, &captured.stderr);
    if captured.left_running {
        out.insert("left_running".into(), Value::Bool(true));
    }
    if let Some(error) = cleanup_error {
        out.insert("cleanup_error".into(), Value::String(error));
    }
}

#[must_use]
pub(crate) fn combine_cleanup_errors(
    first: Option<String>,
    second: Option<String>,
) -> Option<String> {
    match (first, second) {
        (Some(first), Some(second)) => Some(format!("{first}; {second}")),
        (Some(error), None) | (None, Some(error)) => Some(error),
        (None, None) => None,
    }
}

pub(crate) async fn wait_bounded_with_limits(
    child: &mut Child,
    timeout_duration: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
) -> io::Result<WaitOutcome> {
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("child stdout was not piped"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("child stderr was not piped"))?;
    let mut pending = TimedOutCapture::new(stdout, stderr, stdout_limit, stderr_limit);

    match timeout(timeout_duration, pending.wait_until_drained(child)).await {
        Ok(status) => {
            let status = status?;
            Ok(WaitOutcome::Completed(CapturedOutput {
                status,
                stdout: snapshot(&pending.stdout),
                stderr: snapshot(&pending.stderr),
            }))
        }
        Err(_) => Ok(WaitOutcome::TimedOut(pending)),
    }
}

/// # Errors
/// Returns an I/O error when waiting for the child or capturing its output fails.
pub async fn wait_bounded(
    child: &mut Child,
    timeout_duration: Duration,
    capture_limit: usize,
) -> io::Result<WaitOutcome> {
    let per_stream = (capture_limit / 2).max(1024);
    wait_bounded_with_limits(child, timeout_duration, per_stream, per_stream).await
}

/// # Errors
/// Returns an I/O error when reading from the supplied stream fails.
pub fn read_bounded_sync<R: Read>(mut reader: R, limit: usize) -> io::Result<CapturedStream> {
    let mut capture = CapturedStream::new(limit);
    let mut buffer = vec![0_u8; READ_CHUNK];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(capture);
        }
        capture.push(&buffer[..read]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TestResult, TestValue as _};

    #[test]
    fn bounded_capture_keeps_head_and_tail_and_counts_every_byte() -> TestResult {
        let mut capture = CapturedStream::new(10);
        capture.push(b"01234");
        capture.push(b"56789");
        capture.push(b"abcdef");
        assert_eq!(capture.total_bytes(), 16);
        assert!(capture.truncated());
        let rendered = String::from_utf8(capture.rendered()).test_value()?;
        assert!(rendered.starts_with("01234"));
        assert!(rendered.ends_with("bcdef"));
        assert!(rendered.contains("6 bytes omitted"));

        Ok(())
    }
}
