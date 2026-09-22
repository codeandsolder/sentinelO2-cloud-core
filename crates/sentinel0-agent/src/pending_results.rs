use rand::RngCore;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, Weak},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const PENDING_TTL: Duration = Duration::from_secs(24 * 60 * 60);
pub const MAX_PENDING_FILES: usize = 500;

fn store_lock(dir: &Path) -> Arc<Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<PathBuf, Weak<Mutex<()>>>>> = OnceLock::new();
    let locks = LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut locks = locks
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(dir).and_then(Weak::upgrade) {
        return lock;
    }

    let lock = Arc::new(Mutex::new(()));
    locks.insert(dir.to_owned(), Arc::downgrade(&lock));
    lock
}

pub fn pending_dir(upload_base: &Path) -> PathBuf {
    upload_base
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("pending-results")
}

fn safe_name(job_id: &str) -> String {
    let mut kept = String::with_capacity(job_id.len().min(64));
    for ch in job_id.chars() {
        if ch.is_alphanumeric() || matches!(ch, '-' | '_') {
            kept.push(ch);
            if kept.chars().count() == 64 {
                break;
            }
        }
    }
    if kept.is_empty() {
        "unnamed".into()
    } else {
        kept
    }
}

fn unix_seconds_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs_f64()
}

fn json_files(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            out.push(path);
        }
    }
    out.sort_by(|left, right| {
        let left_time = fs::metadata(left)
            .and_then(|meta| meta.modified())
            .unwrap_or(UNIX_EPOCH);
        let right_time = fs::metadata(right)
            .and_then(|meta| meta.modified())
            .unwrap_or(UNIX_EPOCH);
        left_time.cmp(&right_time).then_with(|| left.cmp(right))
    });
    Ok(out)
}

pub fn record(upload_base: &Path, job_id: &str, event: &Value) -> Option<PathBuf> {
    match record_at_result(upload_base, job_id, event, unix_seconds_now()) {
        Ok(path) => Some(path),
        Err(error) => {
            tracing::warn!(%job_id, ?error, "pending result could not be persisted");
            None
        }
    }
}

fn record_at_result(
    upload_base: &Path,
    job_id: &str,
    event: &Value,
    at: f64,
) -> std::io::Result<PathBuf> {
    record_at_result_with_limit(upload_base, job_id, event, at, MAX_PENDING_FILES, true)
}

fn record_at_result_with_limit(
    upload_base: &Path,
    job_id: &str,
    event: &Value,
    at: f64,
    max_pending_files: usize,
    durable: bool,
) -> std::io::Result<PathBuf> {
    let dir = pending_dir(upload_base);
    let store = store_lock(&dir);
    let _guard = store
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    fs::create_dir_all(&dir)?;

    let path = dir.join(format!("{}.json", safe_name(job_id)));
    let wrapped = json!({"at": at, "event": event});
    let bytes = serde_json::to_vec(&wrapped).map_err(std::io::Error::other)?;

    let mut rng = rand::rng();
    let temp = loop {
        let candidate = dir.join(format!(".pending-{:016x}.tmp", rng.next_u64()));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(mut file) => {
                if let Err(error) = file.write_all(&bytes) {
                    let _ = fs::remove_file(&candidate);
                    return Err(error);
                }
                if durable {
                    // Best-effort durability: if the connection dies after the
                    // job completes, replay data should already be on stable
                    // storage before we consider the result persisted.
                    let _ = file.sync_all();
                }
                break candidate;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    };

    if let Err(error) = fs::rename(&temp, &path) {
        let _ = fs::remove_file(&temp);
        return Err(error);
    }

    let existing = json_files(&dir)?;
    if existing.len() > max_pending_files {
        let remove = existing.len() - max_pending_files;
        for stale in existing.into_iter().take(remove) {
            let _ = fs::remove_file(stale);
        }
    }

    Ok(path)
}

pub fn clear(path: Option<&Path>) {
    let Some(path) = path else {
        return;
    };
    let Some(dir) = path.parent() else {
        let _ = fs::remove_file(path);
        return;
    };
    let store = store_lock(dir);
    let _guard = store
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _ = fs::remove_file(path);
}

pub fn drain(upload_base: &Path) -> Vec<(PathBuf, Value)> {
    let dir = pending_dir(upload_base);
    let store = store_lock(&dir);
    let _guard = store
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    drain_at(upload_base, unix_seconds_now())
}

fn drain_at(upload_base: &Path, now: f64) -> Vec<(PathBuf, Value)> {
    let dir = pending_dir(upload_base);
    let Ok(paths) = json_files(&dir) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for path in paths {
        let parsed = fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str::<Value>(&text).ok());

        let Some(data) = parsed else {
            let _ = fs::remove_file(&path);
            continue;
        };
        let Some(event) = data.get("event").filter(|event| event.is_object()).cloned() else {
            let _ = fs::remove_file(&path);
            continue;
        };
        let at = data.get("at").and_then(Value::as_f64).unwrap_or(0.0);
        if now - at > PENDING_TTL.as_secs_f64() {
            let _ = fs::remove_file(&path);
            continue;
        }
        out.push((path, event));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn base() -> (tempfile::TempDir, PathBuf) {
        let dir = tempdir().unwrap();
        let upload = dir.path().join("uploads");
        fs::create_dir(&upload).unwrap();
        (dir, upload)
    }

    fn event(job: &str) -> Value {
        json!({"kind":"job_completed","data":{"job_id":job,"status":"failed"}})
    }

    #[test]
    fn recorded_result_is_returned_and_clear_removes_it() {
        let (_tmp, upload) = base();
        let path = record(&upload, "job_abc", &event("job_abc")).unwrap();
        let waiting = drain(&upload);
        assert_eq!(waiting.len(), 1);
        assert_eq!(waiting[0].1, event("job_abc"));
        clear(Some(&path));
        assert!(drain(&upload).is_empty());
    }

    #[test]
    fn pending_store_is_sibling_of_user_uploads() {
        let (_tmp, upload) = base();
        record(&upload, "job_abc", &event("job_abc")).unwrap();
        assert!(fs::read_dir(&upload).unwrap().next().is_none());
        assert!(pending_dir(&upload).is_dir());
    }

    #[test]
    fn expired_and_corrupt_entries_are_removed() {
        let (_tmp, upload) = base();
        let expired = record_at_result(
            &upload,
            "job_old",
            &event("job_old"),
            unix_seconds_now() - PENDING_TTL.as_secs_f64() - 10.0,
        )
        .unwrap();

        let bad = pending_dir(&upload).join("job_bad.json");
        fs::write(&bad, "{ not json").unwrap();

        assert!(drain(&upload).is_empty());
        assert!(!expired.exists());
        assert!(!bad.exists());
    }

    #[test]
    fn job_id_cannot_escape_pending_directory() {
        let (_tmp, upload) = base();
        record(&upload, "../../etc/passwd", &event("job")).unwrap();
        let files = json_files(&pending_dir(&upload)).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].parent(), Some(pending_dir(&upload).as_path()));
        assert!(
            !files[0]
                .file_name()
                .unwrap()
                .to_string_lossy()
                .contains("..")
        );
    }

    #[test]
    fn backlog_is_capped_and_newest_name_survives() {
        let (_tmp, upload) = base();
        let max = 5;
        for i in 0..(max + 5) {
            record_at_result_with_limit(
                &upload,
                &format!("job_{i:04}"),
                &event(&format!("job_{i:04}")),
                unix_seconds_now(),
                max,
                false,
            )
            .unwrap_or_else(|error| panic!("record {i} failed: {error}"));
        }
        let files = json_files(&pending_dir(&upload)).unwrap();
        assert!(files.len() <= max);
        assert!(
            files
                .iter()
                .any(|path| path.file_stem().unwrap() == "job_0009")
        );
    }

    #[test]
    fn recording_same_job_twice_replaces_instead_of_duplicates() {
        let (_tmp, upload) = base();
        record(&upload, "job_abc", &event("first")).unwrap();
        record(&upload, "job_abc", &event("second")).unwrap();
        let waiting = drain(&upload);
        assert_eq!(waiting.len(), 1);
        assert_eq!(waiting[0].1["data"]["job_id"], "second");
    }

    #[test]
    fn failed_record_is_non_fatal_and_clear_none_is_safe() {
        assert!(
            record(
                Path::new("/proc/nonexistent/deep"),
                "job_abc",
                &event("job_abc")
            )
            .is_none()
        );
        clear(None);
    }

    #[test]
    fn backlog_evicts_oldest_file_not_lexicographically_first_job_id() {
        let (_tmp, upload) = base();
        let max = 5;
        record_at_result_with_limit(
            &upload,
            "zzz_oldest",
            &event("zzz_oldest"),
            unix_seconds_now(),
            max,
            false,
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(20));

        for i in 0..max {
            record_at_result_with_limit(
                &upload,
                &format!("aaa_new_{i:04}"),
                &event(&format!("aaa_new_{i:04}")),
                unix_seconds_now(),
                max,
                false,
            )
            .unwrap_or_else(|error| panic!("record {i} failed: {error}"));
        }

        let names: Vec<_> = json_files(&pending_dir(&upload))
            .unwrap()
            .into_iter()
            .filter_map(|path| {
                path.file_stem()
                    .map(|name| name.to_string_lossy().into_owned())
            })
            .collect();
        assert_eq!(names.len(), max);
        assert!(!names.iter().any(|name| name == "zzz_oldest"));
        assert!(names.iter().any(|name| name == "aaa_new_0000"));
    }

    #[test]
    fn replacing_existing_job_at_capacity_does_not_evict_another_job() {
        let (_tmp, upload) = base();
        let max = 3;
        for job in ["job_a", "job_b", "job_c"] {
            record_at_result_with_limit(&upload, job, &event(job), unix_seconds_now(), max, false)
                .unwrap();
        }

        record_at_result_with_limit(
            &upload,
            "job_b",
            &event("job_b_replaced"),
            unix_seconds_now(),
            max,
            false,
        )
        .unwrap();

        let names = json_files(&pending_dir(&upload))
            .unwrap()
            .into_iter()
            .filter_map(|path| {
                path.file_stem()
                    .map(|name| name.to_string_lossy().into_owned())
            })
            .collect::<Vec<_>>();
        assert_eq!(names.len(), max);
        for job in ["job_a", "job_b", "job_c"] {
            assert!(names.iter().any(|name| name == job), "missing {job}");
        }
    }

    #[test]
    fn atomic_record_leaves_no_temp_files() {
        let (_tmp, upload) = base();
        record(&upload, "job_abc", &event("job_abc")).unwrap();
        let temps: Vec<_> = fs::read_dir(pending_dir(&upload))
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "tmp"))
            .collect();
        assert!(temps.is_empty());
    }
}
