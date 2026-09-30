use crate::rotation;
use nix::{
    errno::Errno,
    fcntl::{Flock, FlockArg},
};
use std::{
    fs::{File, OpenOptions},
    io::{self, Seek as _, SeekFrom, Write as _},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

pub const EXIT_ALREADY_RUNNING: i32 = 3;

#[derive(Debug)]
pub struct InstanceLock {
    _file: Flock<File>,
}

#[derive(Debug, thiserror::Error)]
pub enum InstanceLockError {
    #[error("another agent already holds {path}")]
    AlreadyRunning { path: PathBuf, holder: Option<u32> },
    #[error("failed opening agent lock {path}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed locking agent lock {path}: {errno}")]
    Lock { path: PathBuf, errno: Errno },
    #[error("failed recording holder PID in agent lock {path}: {source}")]
    Record {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

fn safe_host_id(host_id: &str) -> String {
    let host_id = if host_id.is_empty() {
        "unknown"
    } else {
        host_id
    };
    host_id
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn lock_path_for_state(state_dir: &Path, host_id: &str) -> PathBuf {
    state_dir.join(format!("agent-{}.lock", safe_host_id(host_id)))
}

#[must_use]
pub fn lock_path(identity_path: &Path, host_id: &str) -> Option<PathBuf> {
    rotation::state_dir(identity_path).map(|state_dir| lock_path_for_state(&state_dir, host_id))
}

fn holder_pid(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn acquire_path(path: PathBuf) -> Result<InstanceLock, InstanceLockError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .open(&path)
        .map_err(|source| InstanceLockError::Open {
            path: path.clone(),
            source,
        })?;

    let mut locked = match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
        Ok(locked) => locked,
        Err((file, errno)) => {
            drop(file);
            if errno == Errno::EWOULDBLOCK {
                return Err(InstanceLockError::AlreadyRunning {
                    holder: holder_pid(&path),
                    path,
                });
            }
            return Err(InstanceLockError::Lock { path, errno });
        }
    };

    let record_pid = (|| -> io::Result<()> {
        locked.set_len(0)?;
        locked.seek(SeekFrom::Start(0))?;
        write!(locked, "{}", std::process::id())?;
        locked.flush()
    })();
    if let Err(source) = record_pid {
        return Err(InstanceLockError::Record { path, source });
    }

    Ok(InstanceLock { _file: locked })
}

/// # Errors
/// Returns an error if the lock file cannot be opened or locked, or when another
/// process already holds the per-host lock.
pub fn acquire(
    identity_path: &Path,
    host_id: &str,
) -> Result<Option<InstanceLock>, InstanceLockError> {
    let Some(path) = lock_path(identity_path, host_id) else {
        return Ok(None);
    };
    acquire_path(path).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TestResult, TestValue as _};

    #[test]
    fn lock_name_sanitizes_host_id() {
        let path = lock_path_for_state(Path::new("/state"), "host_d08a │ x/y");
        assert_eq!(path, Path::new("/state/agent-host_d08a___x_y.lock"));
    }

    #[test]
    fn first_lock_records_pid_and_second_is_refused() -> TestResult {
        let dir = tempfile::tempdir().test_value()?;
        let path = lock_path_for_state(dir.path(), "host_a");
        let held = acquire_path(path.clone()).test_value()?;
        assert_eq!(
            std::fs::read_to_string(&path).test_value()?,
            std::process::id().to_string()
        );

        match acquire_path(path.clone()) {
            Err(InstanceLockError::AlreadyRunning { holder, .. }) => {
                assert_eq!(holder, Some(std::process::id()));
            }
            other => {
                return Err(std::io::Error::other(format!(
                    "second lock unexpectedly returned {other:?}"
                ))
                .into());
            }
        }
        drop(held);
        Ok(())
    }

    #[test]
    fn dropping_holder_releases_lock() -> TestResult {
        let dir = tempfile::tempdir().test_value()?;
        let path = lock_path_for_state(dir.path(), "host_a");
        let held = acquire_path(path.clone()).test_value()?;
        drop(held);
        let reacquired = acquire_path(path).test_value()?;
        drop(reacquired);
        Ok(())
    }

    #[test]
    fn different_hosts_do_not_block_each_other() -> TestResult {
        let dir = tempfile::tempdir().test_value()?;
        let prod = acquire_path(lock_path_for_state(dir.path(), "host_prod")).test_value()?;
        let dev =
            acquire_path(lock_path_for_state(dir.path(), "dev-orion-b3d403faf023")).test_value()?;
        drop((prod, dev));
        Ok(())
    }
}
