#[cfg(unix)]
use std::fs;
use std::{io, path::Path};

/// Atomically move a file or directory without clobbering an existing
/// destination, on every platform with native exclusive-rename support.
///
/// # Errors
/// Returns a filesystem error for an occupied destination, unsupported
/// filesystems or inaccessible paths.
pub fn rename_no_replace(src: &Path, dst: &Path) -> io::Result<()> {
    renamest::rename_exclusive(src, dst)
}

#[cfg(unix)]
fn same_empty_file(path: &Path, expected: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    fs::symlink_metadata(path).is_ok_and(|current| {
        current.dev() == expected.dev()
            && current.ino() == expected.ino()
            && current.len() == 0
            && current.file_type().is_file()
    })
}

#[cfg(unix)]
fn replace_reserved_file(src: &Path, dst: &Path) -> io::Result<()> {
    use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt as _};
    let reservation = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dst)?;
    let identity = reservation.metadata()?;
    drop(reservation);

    match fs::rename(src, dst) {
        Ok(()) => Ok(()),
        Err(error) => {
            if same_empty_file(dst, &identity) {
                let _ = fs::remove_file(dst);
            }
            Err(error)
        }
    }
}

/// Installs a regular file at `dst` only if that path is still free.
///
/// The hard-link fast path is an atomic create-if-absent operation. Filesystems
/// without hard-link support fall back to an `O_EXCL` reservation followed by
/// replacement of that reservation. A reservation is cleaned up after a failed
/// replacement only when its device/inode identity still proves it is ours.
///
/// # Errors
/// Returns `AlreadyExists` if the destination is occupied, `CrossesDevices` if
/// the source must first be copied beside the destination, or the underlying I/O
/// error when the commit cannot be completed.
#[cfg(unix)]
pub fn install_file_no_replace(src: &Path, dst: &Path) -> io::Result<()> {
    match fs::hard_link(src, dst) {
        Ok(()) => {
            // The destination is already committed. Failure to remove the staging
            // name must not turn a successful state change into a reported failure;
            // callers also own broader staging cleanup.
            if let Err(error) = fs::remove_file(src) {
                tracing::warn!(
                    source = %src.display(),
                    destination = %dst.display(),
                    %error,
                    "no-clobber file commit succeeded but source cleanup failed"
                );
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Err(error),
        Err(error) if error.kind() == io::ErrorKind::CrossesDevices => Err(error),
        Err(_) => replace_reserved_file(src, dst),
    }
}

#[cfg(windows)]
/// Installs a regular file with a native no-replace rename.
///
/// A single exclusive move works on Windows filesystems without hard-link
/// support and never exposes a destination containing partial bytes.
///
/// # Errors
/// Returns an I/O error if the destination already exists or the filesystem
/// cannot atomically move the staged file into place.
pub fn install_file_no_replace(src: &Path, dst: &Path) -> io::Result<()> {
    rename_no_replace(src, dst)
}

/// Returns the normal regular-file creation mode after the current process umask.
///
/// This probes the kernel rather than reading/changing the process-wide umask,
/// which avoids a race with other threads in the agent.
///
/// # Errors
/// Returns an I/O error if the temporary mode probe cannot be created or inspected.
#[cfg(unix)]
pub fn regular_create_mode(parent: &Path) -> io::Result<u32> {
    use std::os::unix::fs::PermissionsExt as _;

    let probe = tempfile::Builder::new()
        .prefix(".sentinel0-mode-probe-")
        .permissions(fs::Permissions::from_mode(0o666))
        .tempfile_in(parent)?;
    Ok(probe.as_file().metadata()?.permissions().mode() & 0o777)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TestError as _, TestResult, TestValue as _};
    use tempfile::tempdir;

    #[test]
    fn no_replace_preserves_existing_destination() -> TestResult {
        let dir = tempdir().test_value()?;
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        std::fs::write(&src, "source").test_value()?;
        std::fs::write(&dst, "destination").test_value()?;

        let error = rename_no_replace(&src, &dst).test_error()?;
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read_to_string(&src).test_value()?, "source");
        assert_eq!(std::fs::read_to_string(&dst).test_value()?, "destination");

        Ok(())
    }
    #[test]
    fn regular_file_no_replace_preserves_existing_destination() -> TestResult {
        let dir = tempdir().test_value()?;
        let src = dir.path().join("src2");
        let dst = dir.path().join("dst2");
        std::fs::write(&src, "source").test_value()?;
        std::fs::write(&dst, "destination").test_value()?;
        let error = install_file_no_replace(&src, &dst).test_error()?;
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read_to_string(src).test_value()?, "source");
        assert_eq!(std::fs::read_to_string(dst).test_value()?, "destination");
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_install_moves_without_leaving_source() -> TestResult {
        let dir = tempdir().test_value()?;
        let src = dir.path().join("pending");
        let dst = dir.path().join("committed");
        std::fs::write(&src, b"payload").test_value()?;
        install_file_no_replace(&src, &dst).test_value()?;
        assert!(!src.exists());
        assert_eq!(std::fs::read(dst).test_value()?, b"payload");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn reservation_failure_removes_only_its_own_empty_placeholder() -> TestResult {
        let dir = tempdir().test_value()?;
        let missing = dir.path().join("missing-source");
        let dst = dir.path().join("reserved");
        let error = replace_reserved_file(&missing, &dst).test_error()?;
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(!dst.exists());
        Ok(())
    }

    #[test]
    fn regular_create_mode_matches_kernel_umask_application() -> TestResult {
        let dir = tempdir().test_value()?;
        let mode = regular_create_mode(dir.path()).test_value()?;
        assert_eq!(mode & !0o666, 0);
        assert_ne!(mode, 0);
        Ok(())
    }
}

#[cfg(windows)]
/// Windows files do not have POSIX create modes.
/// # Errors
/// This never fails.
pub fn regular_create_mode(_parent: &Path) -> io::Result<u32> {
    Ok(0o666)
}
