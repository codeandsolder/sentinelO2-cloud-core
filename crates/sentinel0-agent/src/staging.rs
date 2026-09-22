use std::{
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
};
use tracing::warn;

pub const STAGING_DIRNAME: &str = ".sentinelx_uploads";

fn writable_dir(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)?;
    let probe = path.join(format!(".write-probe-{}", std::process::id()));
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
    use tempfile::tempdir;

    #[test]
    fn configured_upload_base_gets_hidden_staging_child() {
        let dir = tempdir().unwrap();
        let root = staging_root(dir.path()).unwrap();
        assert_eq!(root, dir.path().join(STAGING_DIRNAME));
        assert!(root.is_dir());
    }
}
