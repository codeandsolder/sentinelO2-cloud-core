use chrono::{SecondsFormat, Utc};
use serde_json::{Map, Value, json};
use std::{
    collections::VecDeque,
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

pub const MAX_LINES: usize = 5000;
const TRIM_TRIGGER: usize = 5500;
const RETENTION_CHECK_EVERY: usize = 100;
const TAIL_BLOCK: usize = 64 * 1024;

fn looks_tokenish(text: &str) -> bool {
    text.split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|part| {
            part.len() >= 24
                && part.bytes().any(|byte| byte.is_ascii_alphabetic())
                && part.bytes().any(|byte| byte.is_ascii_digit())
        })
}

fn audit_value(value: &Value) -> Value {
    match value {
        Value::String(text) if looks_tokenish(text) => Value::String("[redacted-tokenish]".into()),
        Value::Array(items) => Value::Array(items.iter().map(audit_value).collect()),
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(key, value)| (key.clone(), audit_value(value)))
                .collect(),
        ),
        _ => value.clone(),
    }
}

/// Preserve the request that was actually made. The only generic failsafe is
/// deliberately cheap: long mixed alphanumeric chunks look more like opaque
/// keys/tokens than prose, so strings containing one are replaced.
#[must_use]
pub fn summarize_payload(payload: &Map<String, Value>) -> Map<String, Value> {
    payload
        .iter()
        .map(|(key, value)| (key.clone(), audit_value(value)))
        .collect()
}

#[derive(Debug, Default)]
struct RetentionState {
    checked_once: bool,
    writes_since_check: usize,
}

fn retention_state() -> &'static Mutex<RetentionState> {
    static STATE: OnceLock<Mutex<RetentionState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(RetentionState::default()))
}

fn audit_io_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[must_use]
pub fn audit_path() -> PathBuf {
    std::env::var_os("SENTINELX_AUDIT_PATH").map_or_else(
        || PathBuf::from("/var/lib/sentinelx/audit.jsonl"),
        PathBuf::from,
    )
}

fn should_check_retention() -> bool {
    let mut state = retention_state()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !state.checked_once {
        state.checked_once = true;
        state.writes_since_check = 0;
        return true;
    }
    state.writes_since_check += 1;
    if state.writes_since_check >= RETENTION_CHECK_EVERY {
        state.writes_since_check = 0;
        true
    } else {
        false
    }
}

fn has_more_than_lines(path: &Path, limit: usize) -> std::io::Result<bool> {
    let mut reader = BufReader::new(fs::File::open(path)?);
    let mut line = Vec::new();
    for _ in 0..=limit {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            return Ok(false);
        }
    }
    Ok(true)
}

fn maybe_trim(path: &Path) -> std::io::Result<()> {
    if !has_more_than_lines(path, TRIM_TRIGGER)? {
        return Ok(());
    }

    let mut reader = BufReader::new(fs::File::open(path)?);
    let mut retained = VecDeque::with_capacity(MAX_LINES);
    loop {
        let mut line = Vec::new();
        if reader.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        if retained.len() == MAX_LINES {
            retained.pop_front();
        }
        retained.push_back(line);
    }

    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let temp = parent.join(format!(".audit-{:016x}.tmp", rand::random::<u64>()));
    let replace = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        for line in retained {
            file.write_all(&line)?;
        }
        file.sync_all()?;
        fs::rename(&temp, path)
    })();
    if replace.is_err()
        && let Err(cleanup) = fs::remove_file(&temp)
        && cleanup.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(
            path = %temp.display(),
            %cleanup,
            "failed cleaning audit trim temp file"
        );
    }
    replace
}

pub fn record(
    op: &str,
    payload: &Map<String, Value>,
    dispatch_ok: bool,
    error: Option<&str>,
    duration_ms: u64,
    result_ok: Option<bool>,
    result_returncode: Option<i64>,
) {
    if matches!(op, "read_audit" | "ping") {
        return;
    }
    let path = audit_path();
    let attempt = (|| -> Result<(), Box<dyn std::error::Error>> {
        // Rust dispatches operations concurrently and records them from
        // spawn_blocking workers. The Python implementation's append-then-
        // trim sequence was effectively serialized by its event-loop call
        // site; without a lock a trim rename can race a concurrent append to
        // the old inode and silently lose a row.
        let _io_guard = audit_io_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut entry = json!({
            "timestamp": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            "op": op,
            "payload": payload,
            "ok": dispatch_ok,
            "error": error,
            "duration_ms": duration_ms,
        });
        if let Some(map) = entry.as_object_mut() {
            if let Some(value) = result_ok {
                map.insert("result_ok".into(), Value::Bool(value));
            }
            if let Some(value) = result_returncode {
                map.insert("result_returncode".into(), Value::from(value));
            }
        }
        let line = serde_json::to_vec(&entry)?;
        let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
        file.write_all(&line)?;
        file.write_all(b"\n")?;
        if should_check_retention() {
            maybe_trim(&path)?;
        }
        Ok(())
    })();
    if let Err(error) = attempt {
        tracing::warn!(%error, "local audit write failed");
    }
}

fn tail_lines(path: &Path, limit: usize) -> std::io::Result<Vec<Vec<u8>>> {
    let mut file = fs::File::open(path)?;
    let mut position = file.seek(SeekFrom::End(0))?;
    let mut buffer = Vec::new();
    let mut newline_count = 0;
    while position > 0 && newline_count <= limit {
        let tail_block = u64::try_from(TAIL_BLOCK).unwrap_or(u64::MAX);
        let step_u64 = position.min(tail_block);
        let step = usize::try_from(step_u64).unwrap_or(TAIL_BLOCK);
        position -= step_u64;
        file.seek(SeekFrom::Start(position))?;
        let mut chunk = vec![0_u8; step];
        file.read_exact(&mut chunk)?;
        newline_count += chunk.iter().filter(|byte| **byte == b'\n').count();
        chunk.extend(buffer);
        buffer = chunk;
    }
    let mut lines = buffer
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    if lines.len() > limit {
        lines.drain(..lines.len() - limit);
    }
    Ok(lines)
}

fn read_recent_from(path: &Path, limit: usize) -> Vec<Value> {
    let limit = limit.clamp(1, MAX_LINES);
    let lines = match tail_lines(path, limit) {
        Ok(lines) => lines,
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                %error,
                "failed reading local audit log"
            );
            return Vec::new();
        }
    };

    let mut malformed = 0_u64;
    let mut rows = Vec::new();
    for line in lines.into_iter().rev() {
        match serde_json::from_slice::<Value>(&line) {
            Ok(row) => rows.push(row),
            Err(_) => malformed = malformed.saturating_add(1),
        }
    }
    if malformed != 0 {
        tracing::warn!(
            path = %path.display(),
            malformed,
            "skipped malformed local audit rows"
        );
    }
    rows
}

#[must_use]
pub fn read_recent(limit: usize) -> Vec<Value> {
    let _io_guard = audit_io_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    read_recent_from(&audit_path(), limit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn read_recent_is_newest_first_and_malformed_rows_are_skipped() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        fs::write(&path, b"{\"n\":1}\nnot-json\n{\"n\":2}\n").unwrap();
        let rows = read_recent_from(&path, 3);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["n"], 2);
        assert_eq!(rows[1]["n"], 1);
    }

    #[test]
    fn payload_summary_keeps_useful_values_and_redacts_tokenish_strings() {
        let payload = Map::from_iter([
            (
                "path".into(),
                Value::String("/tmp/example-2026/foo.rs".into()),
            ),
            (
                "command".into(),
                Value::String("cargo test -p sentinel0-agent local_audit".into()),
            ),
            (
                "message".into(),
                Value::String("this is ordinary written text and should stay".into()),
            ),
            (
                "env".into(),
                json!({"TOKEN": "A1b2C3d4E5f6G7h8I9j0K1l2", "MODE": "debug"}),
            ),
        ]);

        let summary = summarize_payload(&payload);
        assert_eq!(summary["path"], "/tmp/example-2026/foo.rs");
        assert_eq!(
            summary["command"],
            "cargo test -p sentinel0-agent local_audit"
        );
        assert_eq!(
            summary["message"],
            "this is ordinary written text and should stay"
        );
        assert_eq!(summary["env"]["MODE"], "debug");
        assert_eq!(summary["env"]["TOKEN"], "[redacted-tokenish]");
    }

    #[test]
    fn tokenish_classifier_is_intentionally_simple() {
        assert!(looks_tokenish("prefix=A1b2C3d4E5f6G7h8I9j0K1l2;suffix"));
        assert!(looks_tokenish(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
        assert!(!looks_tokenish("ordinary-written-text-without-digits"));
        assert!(!looks_tokenish("123456789012345678901234567890"));
        assert!(!looks_tokenish("550e8400-e29b-41d4-a716-446655440000"));
    }

    #[test]
    fn trim_keeps_exactly_the_newest_rows() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut input = Vec::new();
        for n in 1..=(TRIM_TRIGGER + 1) {
            writeln!(&mut input, "{{\"n\":{n}}}").unwrap();
        }
        fs::write(&path, input).unwrap();

        maybe_trim(&path).unwrap();

        let rows = read_recent_from(&path, MAX_LINES);
        assert_eq!(rows.len(), MAX_LINES);
        assert_eq!(rows[0]["n"], TRIM_TRIGGER + 1);
        assert_eq!(rows[MAX_LINES - 1]["n"], TRIM_TRIGGER + 2 - MAX_LINES);
    }

    #[test]
    fn retention_probe_stops_at_the_requested_line_limit() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        fs::write(&path, b"one\ntwo\nthree\n").unwrap();
        assert!(!has_more_than_lines(&path, 3).unwrap());
        assert!(has_more_than_lines(&path, 2).unwrap());
    }
}
