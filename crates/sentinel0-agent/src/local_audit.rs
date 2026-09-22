use chrono::{SecondsFormat, Utc};
use serde_json::{Map, Value, json};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
    sync::{Mutex, OnceLock},
};

pub const MAX_LINES: usize = 5000;
const TRIM_TRIGGER: usize = 5500;
const RETENTION_CHECK_EVERY: usize = 100;
const TAIL_BLOCK: usize = 64 * 1024;

#[derive(Debug, Default)]
struct RetentionState {
    checked_once: bool,
    writes_since_check: usize,
}

fn retention_state() -> &'static Mutex<RetentionState> {
    static STATE: OnceLock<Mutex<RetentionState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(RetentionState::default()))
}

#[must_use]
pub fn audit_path() -> PathBuf {
    std::env::var_os("SENTINELX_AUDIT_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/sentinelx/audit.jsonl"))
}

fn should_check_retention() -> bool {
    let Ok(mut state) = retention_state().lock() else {
        return false;
    };
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

fn maybe_trim(path: &PathBuf) -> std::io::Result<()> {
    let bytes = fs::read(path)?;
    let mut lines = bytes
        .split_inclusive(|byte| *byte == b'\n')
        .collect::<Vec<_>>();
    if lines.len() <= TRIM_TRIGGER {
        return Ok(());
    }
    let keep_from = lines.len().saturating_sub(MAX_LINES);
    let retained = lines.split_off(keep_from).concat();
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let temp = parent.join(format!(".audit-{:016x}.tmp", rand::random::<u64>()));
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(&retained)?;
        file.sync_all()?;
    }
    fs::rename(temp, path)?;
    Ok(())
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

fn tail_lines(path: &PathBuf, limit: usize) -> std::io::Result<Vec<Vec<u8>>> {
    let mut file = fs::File::open(path)?;
    let mut position = file.seek(SeekFrom::End(0))?;
    let mut buffer = Vec::new();
    while position > 0 && buffer.iter().filter(|byte| **byte == b'\n').count() <= limit {
        let step = position.min(TAIL_BLOCK as u64) as usize;
        position -= step as u64;
        file.seek(SeekFrom::Start(position))?;
        let mut chunk = vec![0_u8; step];
        file.read_exact(&mut chunk)?;
        chunk.extend(buffer);
        buffer = chunk;
    }
    let mut lines = buffer
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| line.to_vec())
        .collect::<Vec<_>>();
    if lines.len() > limit {
        lines.drain(..lines.len() - limit);
    }
    Ok(lines)
}

fn read_recent_from(path: &PathBuf, limit: usize) -> Vec<Value> {
    let limit = limit.clamp(1, MAX_LINES);
    let Ok(lines) = tail_lines(path, limit) else {
        return Vec::new();
    };
    lines
        .into_iter()
        .rev()
        .filter_map(|line| serde_json::from_slice::<Value>(&line).ok())
        .collect()
}

#[must_use]
pub fn read_recent(limit: usize) -> Vec<Value> {
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
}
