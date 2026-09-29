use std::{
    collections::VecDeque,
    io::{self, Read},
    process::ExitStatus,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Child,
    time::timeout,
};

const READ_CHUNK: usize = 16 * 1024;

#[derive(Debug)]
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

#[derive(Debug)]
pub enum WaitOutcome {
    Completed(CapturedOutput),
    TimedOut,
}

pub(crate) async fn capture_bounded(
    child: &mut Child,
    stdout_limit: usize,
    stderr_limit: usize,
) -> io::Result<CapturedOutput> {
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("child stdout was not piped"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("child stderr was not piped"))?;
    let (stdout, stderr, status) = tokio::try_join!(
        read_bounded_async(stdout, stdout_limit),
        read_bounded_async(stderr, stderr_limit),
        child.wait(),
    )?;
    Ok(CapturedOutput {
        status,
        stdout,
        stderr,
    })
}

pub(crate) async fn wait_bounded_with_limits(
    child: &mut Child,
    timeout_duration: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
) -> io::Result<WaitOutcome> {
    match timeout(
        timeout_duration,
        capture_bounded(child, stdout_limit, stderr_limit),
    )
    .await
    {
        Ok(result) => result.map(WaitOutcome::Completed),
        Err(_) => Ok(WaitOutcome::TimedOut),
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

async fn read_bounded_async<R>(mut reader: R, limit: usize) -> io::Result<CapturedStream>
where
    R: AsyncRead + Unpin,
{
    let mut capture = CapturedStream::new(limit);
    let mut buffer = vec![0_u8; READ_CHUNK];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            return Ok(capture);
        }
        capture.push(&buffer[..read]);
    }
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

    #[test]
    fn bounded_capture_keeps_head_and_tail_and_counts_every_byte() {
        let mut capture = CapturedStream::new(10);
        capture.push(b"01234");
        capture.push(b"56789");
        capture.push(b"abcdef");
        assert_eq!(capture.total_bytes(), 16);
        assert!(capture.truncated());
        let rendered = String::from_utf8(capture.rendered()).unwrap();
        assert!(rendered.starts_with("01234"));
        assert!(rendered.ends_with("bcdef"));
        assert!(rendered.contains("6 bytes omitted"));
    }
}
