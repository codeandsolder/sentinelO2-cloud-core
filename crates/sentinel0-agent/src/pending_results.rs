use rand::RngCore;
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const PENDING_TTL: Duration = Duration::from_secs(24 * 60 * 60);
pub const MAX_PENDING_FILES: usize = 500;

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
    out.sort();
    Ok(out)
}

pub fn record(upload_base: &Path, job_id: &str, event: &Value) -> Option<PathBuf> {
    record_at(upload_base, job_id, event, unix_seconds_now())
}

fn record_at(upload_base: &Path, job_id: &str, event: &Value, at: f64) -> Option<PathBuf> {
    let result = (|| -> std::io::Result<PathBuf> {
        let dir = pending_dir(upload_base);
        fs::create_dir_all(&dir)?;

        let existing = json_files(&dir)?;
        if existing.len() >= MAX_PENDING_FILES {
            let remove = existing.len() - MAX_PENDING_FILES + 1;
            for stale in existing.into_iter().take(remove) {
                let _ = fs::remove_file(stale);
            }
        }

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
        Ok(path)
    })();

    result.ok()
}

pub fn clear(path: Option<&Path>) {
    if let Some(path) = path {
        let _ = fs::remove_file(path);
    }
}

pub fn drain(upload_base: &Path) -> Vec<(PathBuf, Value)> {
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
        let expired = record_at(
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
        for i in 0..(MAX_PENDING_FILES + 5) {
            record(
                &upload,
                &format!("job_{i:04}"),
                &event(&format!("job_{i:04}")),
            )
            .unwrap();
        }
        let files = json_files(&pending_dir(&upload)).unwrap();
        assert!(files.len() <= MAX_PENDING_FILES);
        assert!(
            files
                .iter()
                .any(|path| path.file_stem().unwrap() == "job_0504")
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
