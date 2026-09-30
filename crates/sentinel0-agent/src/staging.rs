use std::{
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
};
use tracing::warn;

pub const STAGING_DIRNAME: &str = ".sentinelx_uploads";

fn writable_dir(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)?;
    let probe = path.join(format!(
        ".write-probe-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)?;
    drop(file);
    fs::remove_file(probe)?;
    Ok(())
}

#[must_use]
pub fn fallback_root() -> PathBuf {
    std::env::temp_dir()
        .join("sentinelx-staging")
        .join(STAGING_DIRNAME)
}

/// # Errors
/// Returns an I/O error when a usable staging directory cannot be created or resolved.
pub fn staging_root(upload_base: &Path) -> std::io::Result<PathBuf> {
    let primary = upload_base.join(STAGING_DIRNAME);
    match writable_dir(&primary) {
        Ok(()) => Ok(primary),
        Err(primary_error) => {
            let fallback = fallback_root();
            writable_dir(&fallback).map_err(|fallback_error| {
                std::io::Error::other(format!(
                    "no writable staging directory: {} ({primary_error}) and {} ({fallback_error})",
                    primary.display(),
                    fallback.display()
                ))
            })?;
            warn!(
                primary = %primary.display(),
                fallback = %fallback.display(),
                error = %primary_error,
                "configured staging root is unusable; using temporary fallback"
            );
            Ok(fallback)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TestError as _, TestResult, TestValue as _};
    use tempfile::tempdir;

    #[test]
    fn configured_upload_base_gets_hidden_staging_child() -> TestResult {
        let dir = tempdir().test_value()?;
        let root = staging_root(dir.path()).test_value()?;
        assert_eq!(root, dir.path().join(STAGING_DIRNAME));
        assert!(root.is_dir());

        Ok(())
    }
}
