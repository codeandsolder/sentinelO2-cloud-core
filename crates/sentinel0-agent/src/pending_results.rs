use serde_json::{Value, json};
use sha2::{Digest, Sha256};
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

#[must_use]
pub fn pending_dir(upload_base: &Path) -> PathBuf {
    upload_base
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("pending-results")
}

fn safe_name(job_id: &str) -> String {
    // Preserve every filename the old scheme represented losslessly, so an
    // upgrade does not create a second path for an already-pending ordinary
    // Hub job ID. Inputs that previously needed sanitizing or truncation get a
    // digest suffix so distinct IDs cannot collapse onto one pending result.
    if !job_id.is_empty()
        && job_id.len() <= 64
        && job_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return job_id.to_owned();
    }

    // '~' is outside the preserved safe-ID alphabet, so hashed names cannot
    // collide with any literal safe ID. '~' + 30-byte prefix + '-' + 32 hex = 64 bytes.
    let mut prefix = String::with_capacity(30);
    for byte in job_id.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') {
            if prefix.len() == 30 {
                break;
            }
            prefix.push(char::from(byte));
        }
    }
    if prefix.is_empty() {
        prefix.push_str("unnamed");
    }

    let digest = Sha256::digest(job_id.as_bytes());
    let suffix = crate::hex_lower(&digest[..16]);
    format!("~{prefix}-{suffix}")
}

fn unix_seconds_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs_f64()
}

fn json_files(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            let modified = entry.metadata()?.modified()?;
            out.push((path, modified));
        }
    }
    out.sort_by(|(left_path, left_time), (right_path, right_time)| {
        left_time
            .cmp(right_time)
            .then_with(|| left_path.cmp(right_path))
    });
    Ok(out.into_iter().map(|(path, _)| path).collect())
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

    let temp = loop {
        let candidate = dir.join(format!(".pending-{:016x}.tmp", rand::random::<u64>()));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(mut file) => {
                if let Err(error) = file.write_all(&bytes) {
                    if let Err(cleanup) = fs::remove_file(&candidate)
                        && cleanup.kind() != std::io::ErrorKind::NotFound
                    {
                        tracing::warn!(path = %candidate.display(), %cleanup, "failed cleaning partial pending-result file");
                    }
                    return Err(error);
                }
                if durable && let Err(error) = file.sync_all() {
                    drop(file);
                    if let Err(cleanup) = fs::remove_file(&candidate)
                        && cleanup.kind() != std::io::ErrorKind::NotFound
                    {
                        tracing::warn!(
                            path = %candidate.display(),
                            %cleanup,
                            "failed cleaning pending-result temp after fsync failure"
                        );
                    }
                    return Err(error);
                }
                break candidate;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    };

    if let Err(error) = fs::rename(&temp, &path) {
        if let Err(cleanup) = fs::remove_file(&temp)
            && cleanup.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(path = %temp.display(), %cleanup, "failed cleaning pending-result temp after rename failure");
        }
        return Err(error);
    }
    if durable && let Err(error) = fs::File::open(&dir).and_then(|directory| directory.sync_all()) {
        tracing::warn!(
            path = %dir.display(),
            %error,
            "pending result was renamed, but directory fsync failed; crash durability is not guaranteed"
        );
    }

    match json_files(&dir) {
        Ok(existing) if existing.len() > max_pending_files => {
            let remove = existing.len() - max_pending_files;
            let mut removed_any = false;
            for stale in existing.into_iter().take(remove) {
                match fs::remove_file(&stale) {
                    Ok(()) => removed_any = true,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        tracing::warn!(path = %stale.display(), %error, "failed pruning stale pending-result file");
                    }
                }
            }
            if durable
                && removed_any
                && let Err(error) = fs::File::open(&dir).and_then(|directory| directory.sync_all())
            {
                tracing::warn!(
                    path = %dir.display(),
                    %error,
                    "pending-result prune directory fsync failed"
                );
            }
        }
        Ok(_) => {}
        Err(error) => {
            tracing::warn!(
                path = %dir.display(),
                %error,
                "pending result was committed, but backlog pruning could not enumerate the store"
            );
        }
    }

    Ok(path)
}

pub fn clear(path: Option<&Path>) {
    let Some(path) = path else {
        return;
    };
    let Some(dir) = path.parent() else {
        if let Err(error) = fs::remove_file(path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(path = %path.display(), %error, "failed clearing pending result");
        }
        return;
    };
    let store = store_lock(dir);
    let _guard = store
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Err(error) = fs::remove_file(path)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(path = %path.display(), %error, "failed clearing pending result");
    }
}

pub fn drain(upload_base: &Path) -> Vec<(PathBuf, Value)> {
    let dir = pending_dir(upload_base);
    let store = store_lock(&dir);
    let _guard = store
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match drain_at(upload_base, unix_seconds_now()) {
        Ok(entries) => entries,
        Err(error) => {
            tracing::warn!(
                path = %dir.display(),
                %error,
                "could not enumerate pending results; leaving them in place for a later retry"
            );
            Vec::new()
        }
    }
}

fn remove_pending_best_effort(path: &Path, reason: &'static str) {
    if let Err(error) = fs::remove_file(path)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(
            path = %path.display(),
            %error,
            reason,
            "failed removing unusable pending-result file"
        );
    }
}

fn drain_at(upload_base: &Path, now: f64) -> std::io::Result<Vec<(PathBuf, Value)>> {
    let dir = pending_dir(upload_base);
    let paths = json_files(&dir)?;

    let mut out = Vec::new();
    for path in paths {
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                tracing::warn!(
                    path = %path.display(),
                    %error,
                    "could not read pending-result file; preserving it for a later retry"
                );
                continue;
            }
        };
        let data = match serde_json::from_str::<Value>(&text) {
            Ok(data) => data,
            Err(error) => {
                tracing::warn!(
                    path = %path.display(),
                    %error,
                    "pending-result file contains invalid JSON; removing corrupt entry"
                );
                remove_pending_best_effort(&path, "invalid_json");
                continue;
            }
        };
        let Some(event) = data.get("event").filter(|event| event.is_object()).cloned() else {
            tracing::warn!(
                path = %path.display(),
                "pending-result file is missing an event object; removing corrupt entry"
            );
            remove_pending_best_effort(&path, "missing_event");
            continue;
        };
        let Some(at) = data
            .get("at")
            .and_then(Value::as_f64)
            .filter(|at| at.is_finite())
        else {
            tracing::warn!(
                path = %path.display(),
                "pending-result file has no valid timestamp; removing corrupt entry"
            );
            remove_pending_best_effort(&path, "invalid_timestamp");
            continue;
        };
        if now - at > PENDING_TTL.as_secs_f64() {
            remove_pending_best_effort(&path, "expired");
            continue;
        }
        out.push((path, event));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TestResult, TestValue as _};
    use tempfile::tempdir;

    fn base() -> TestResult<(tempfile::TempDir, PathBuf)> {
        let dir = tempdir().test_value()?;
        let upload = dir.path().join("uploads");
        fs::create_dir(&upload).test_value()?;
        Ok((dir, upload))
    }

    fn event(job: &str) -> Value {
        json!({"kind":"job_completed","data":{"job_id":job,"status":"failed"}})
    }

    #[test]
    fn recorded_result_is_returned_and_clear_removes_it() -> TestResult {
        let (_tmp, upload) = base()?;
        let path = record(&upload, "job_abc", &event("job_abc")).test_value()?;
        let waiting = drain(&upload);
        assert_eq!(waiting.len(), 1);
        assert_eq!(waiting[0].1, event("job_abc"));
        clear(Some(&path));
        assert!(drain(&upload).is_empty());

        Ok(())
    }

    #[test]
    fn pending_store_is_sibling_of_user_uploads() -> TestResult {
        let (_tmp, upload) = base()?;
        record(&upload, "job_abc", &event("job_abc")).test_value()?;
        assert!(fs::read_dir(&upload).test_value()?.next().is_none());
        assert!(pending_dir(&upload).is_dir());

        Ok(())
    }

    #[test]
    fn expired_and_corrupt_entries_are_removed() -> TestResult {
        let (_tmp, upload) = base()?;
        let expired = record_at_result(
            &upload,
            "job_old",
            &event("job_old"),
            unix_seconds_now() - PENDING_TTL.as_secs_f64() - 10.0,
        )
        .test_value()?;

        let bad = pending_dir(&upload).join("job_bad.json");
        fs::write(&bad, "{ not json").test_value()?;

        assert!(drain(&upload).is_empty());
        assert!(!expired.exists());
        assert!(!bad.exists());

        Ok(())
    }

    #[test]
    fn job_id_cannot_escape_pending_directory() -> TestResult {
        let (_tmp, upload) = base()?;
        record(&upload, "../../etc/passwd", &event("job")).test_value()?;
        let files = json_files(&pending_dir(&upload)).test_value()?;
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].parent(), Some(pending_dir(&upload).as_path()));
        assert!(
            !files[0]
                .file_name()
                .test_value()?
                .to_string_lossy()
                .contains("..")
        );

        Ok(())
    }

    #[test]
    fn backlog_is_capped_and_newest_name_survives() -> TestResult {
        let (_tmp, upload) = base()?;
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
            .test_value()?;
        }
        let files = json_files(&pending_dir(&upload)).test_value()?;
        assert!(files.len() <= max);
        let newest_survives = files
            .iter()
            .filter_map(|path| path.file_stem())
            .any(|stem| stem == "job_0009");
        assert!(newest_survives);

        Ok(())
    }

    #[test]
    fn recording_same_job_twice_replaces_instead_of_duplicates() -> TestResult {
        let (_tmp, upload) = base()?;
        record(&upload, "job_abc", &event("first")).test_value()?;
        record(&upload, "job_abc", &event("second")).test_value()?;
        let waiting = drain(&upload);
        assert_eq!(waiting.len(), 1);
        assert_eq!(waiting[0].1["data"]["job_id"], "second");

        Ok(())
    }

    #[test]
    fn failed_record_is_non_fatal_and_clear_none_is_safe() -> TestResult {
        assert!(
            record(
                Path::new("/proc/nonexistent/deep"),
                "job_abc",
                &event("job_abc")
            )
            .is_none()
        );
        clear(None);

        Ok(())
    }

    #[test]
    fn backlog_evicts_oldest_file_not_lexicographically_first_job_id() -> TestResult {
        let (_tmp, upload) = base()?;
        let max = 5;
        record_at_result_with_limit(
            &upload,
            "zzz_oldest",
            &event("zzz_oldest"),
            unix_seconds_now(),
            max,
            false,
        )
        .test_value()?;
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
            .test_value()?;
        }

        let names: Vec<_> = json_files(&pending_dir(&upload))
            .test_value()?
            .into_iter()
            .filter_map(|path| {
                path.file_stem()
                    .map(|name| name.to_string_lossy().into_owned())
            })
            .collect();
        assert_eq!(names.len(), max);
        assert!(!names.iter().any(|name| name == "zzz_oldest"));
        assert!(names.iter().any(|name| name == "aaa_new_0000"));

        Ok(())
    }

    #[test]
    fn replacing_existing_job_at_capacity_does_not_evict_another_job() -> TestResult {
        let (_tmp, upload) = base()?;
        let max = 3;
        for job in ["job_a", "job_b", "job_c"] {
            record_at_result_with_limit(&upload, job, &event(job), unix_seconds_now(), max, false)
                .test_value()?;
        }

        record_at_result_with_limit(
            &upload,
            "job_b",
            &event("job_b_replaced"),
            unix_seconds_now(),
            max,
            false,
        )
        .test_value()?;

        let names = json_files(&pending_dir(&upload))
            .test_value()?
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

        Ok(())
    }

    #[test]
    fn atomic_record_leaves_no_temp_files() -> TestResult {
        let (_tmp, upload) = base()?;
        record(&upload, "job_abc", &event("job_abc")).test_value()?;
        let temps: Vec<_> = fs::read_dir(pending_dir(&upload))
            .test_value()?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "tmp"))
            .collect();
        assert!(temps.is_empty());

        Ok(())
    }

    #[test]
    fn sanitized_job_ids_do_not_alias_pending_paths() -> TestResult {
        assert_ne!(safe_name("job/a"), safe_name("joba"));
        assert_ne!(
            safe_name(&format!("{}x", "a".repeat(64))),
            safe_name(&format!("{}y", "a".repeat(64)))
        );
        assert_eq!(safe_name("job_0123-abcd"), "job_0123-abcd");
        let safe_64 = "a".repeat(64);
        assert_eq!(safe_name(&safe_64), safe_64);

        Ok(())
    }

    #[test]
    fn unicode_job_id_stays_within_safe_ascii_filename_shape() -> TestResult {
        let name = safe_name(&"ą".repeat(100));
        assert!(name.is_ascii());
        assert!(name.len() < 100);
        assert!(!name.contains('/'));

        Ok(())
    }
}
