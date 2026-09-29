use std::{io, path::Path};

#[cfg(all(target_os = "linux", target_env = "gnu"))]
/// # Errors
/// Returns an I/O error when the source cannot be renamed to the destination without replacement.
pub fn rename_no_replace(src: &Path, dst: &Path) -> io::Result<()> {
    use nix::fcntl::{AT_FDCWD, RenameFlags, renameat2};

    renameat2(AT_FDCWD, src, AT_FDCWD, dst, RenameFlags::RENAME_NOREPLACE)
        .map_err(|error| io::Error::from_raw_os_error(error as i32))
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
/// # Errors
/// Returns an I/O error when the source cannot be renamed to the destination without replacement.
pub fn rename_no_replace(src: &Path, dst: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(dst) {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("destination already exists: {}", dst.display()),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    std::fs::rename(src, dst)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn no_replace_preserves_existing_destination() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        std::fs::write(&src, "source").unwrap();
        std::fs::write(&dst, "destination").unwrap();

        let error = rename_no_replace(&src, &dst).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read_to_string(&src).unwrap(), "source");
        assert_eq!(std::fs::read_to_string(&dst).unwrap(), "destination");
    }
}
