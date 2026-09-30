use crate::{
    fsutil::rename_no_replace,
    handler_error::{HandlerError, HandlerResult, require_str},
    policy::Policy,
};
use chrono::Utc;
use flate2::{Compression, write::GzEncoder};
use rand::RngExt;
use serde_json::{Map, Value};
use std::{
    collections::BTreeMap,
    fs, io,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
};

fn resolve_rw(policy: &Policy, raw: &str, label: &str) -> Result<PathBuf, HandlerError> {
    policy.resolve_path(raw, true).ok_or_else(|| {
        HandlerError::with_details(
            "path_not_allowed",
            format!("{label} {raw:?} is outside the file_ops rw allowlist"),
            Map::from_iter([(
                "writable_paths".into(),
                Value::Array(
                    policy
                        .file_ops_paths
                        .iter()
                        .filter(|entry| entry.access == crate::policy::FileAccess::ReadWrite)
                        .map(|entry| Value::String(entry.path.display().to_string()))
                        .collect(),
                ),
            )]),
        )
    })
}

fn resolve_leaf_rw(policy: &Policy, raw: &str, label: &str) -> Result<PathBuf, HandlerError> {
    policy
        .resolve_path_no_follow_leaf(raw, true)
        .ok_or_else(|| {
            HandlerError::with_details(
                "path_not_allowed",
                format!("{label} {raw:?} is outside the file_ops rw allowlist"),
                Map::from_iter([(
                    "writable_paths".into(),
                    Value::Array(
                        policy
                            .file_ops_paths
                            .iter()
                            .filter(|entry| entry.access == crate::policy::FileAccess::ReadWrite)
                            .map(|entry| Value::String(entry.path.display().to_string()))
                            .collect(),
                    ),
                )]),
            )
        })
}

fn entry_metadata(path: &Path) -> io::Result<fs::Metadata> {
    fs::symlink_metadata(path)
}

fn entry_exists(path: &Path) -> io::Result<bool> {
    match entry_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn checked_entry_exists(
    path: &Path,
    code: &'static str,
    context: &str,
) -> Result<bool, HandlerError> {
    entry_exists(path)
        .map_err(|error| HandlerError::new(code, format!("{context} {}: {error}", path.display())))
}

fn backup_file(path: &Path) -> Result<PathBuf, HandlerError> {
    let backup = path.with_file_name(format!(
        "{}.bak.{}-{:016x}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("file"),
        Utc::now().format("%Y%m%d-%H%M%S%.6f"),
        rand::rng().random::<u64>()
    ));
    let result = (|| -> std::io::Result<()> {
        copy_entry(path, &backup)?;
        sync_parent(&backup)
    })();
    if let Err(error) = result {
        let cleanup = match fs::remove_file(&backup) {
            Ok(()) => None,
            Err(cleanup) if cleanup.kind() == io::ErrorKind::NotFound => None,
            Err(cleanup) => Some(cleanup),
        };
        return Err(HandlerError::new(
            "backup_failed",
            cleanup.map_or_else(
                || format!("backup failed: {error}"),
                |cleanup| {
                    format!("backup failed: {error}; partial backup cleanup also failed: {cleanup}")
                },
            ),
        ));
    }
    Ok(backup)
}

fn backup_dir(path: &Path) -> Result<PathBuf, HandlerError> {
    let archive = path.with_file_name(format!(
        "{}.bak.{}-{:016x}.tar.gz",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("dir"),
        Utc::now().format("%Y%m%d-%H%M%S%.6f"),
        rand::rng().random::<u64>()
    ));

    let result = (|| -> Result<(), HandlerError> {
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&archive)
            .map_err(|e| HandlerError::new("backup_failed", format!("backup failed: {e}")))?;
        let encoder = GzEncoder::new(file, Compression::default());
        let mut tar = tar::Builder::new(encoder);
        tar.follow_symlinks(false);
        let name = path.file_name().unwrap_or_default();
        tar.append_dir_all(name, path)
            .map_err(|e| HandlerError::new("backup_failed", format!("backup failed: {e}")))?;
        let encoder = tar
            .into_inner()
            .map_err(|e| HandlerError::new("backup_failed", format!("backup failed: {e}")))?;
        let file = encoder
            .finish()
            .map_err(|e| HandlerError::new("backup_failed", format!("backup failed: {e}")))?;
        file.sync_all()
            .map_err(|e| HandlerError::new("backup_failed", format!("backup failed: {e}")))?;
        sync_parent(&archive)
            .map_err(|e| HandlerError::new("backup_failed", format!("backup failed: {e}")))
    })();

    if let Err(mut error) = result {
        if let Err(cleanup) = fs::remove_file(&archive)
            && cleanup.kind() != io::ErrorKind::NotFound
        {
            error
                .message
                .push_str("; partial archive cleanup also failed: ");
            error.message.push_str(&cleanup.to_string());
        }
        return Err(error);
    }
    Ok(archive)
}

fn is_own_backup(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let Some((_, suffix)) = name.rsplit_once(".bak.") else {
        return false;
    };
    let stamp = suffix.strip_suffix(".tar.gz").unwrap_or(suffix);

    // Legacy SentinelX backups were timestamp-only. Hardened backups append a
    // 16-hex random nonce so create_new() can guarantee collision safety.
    let timestamp = if stamp.len() >= 17 {
        let split = stamp.len() - 17;
        let bytes = stamp.as_bytes();
        if bytes[split] == b'-' && bytes[split + 1..].iter().all(u8::is_ascii_hexdigit) {
            &stamp[..split]
        } else {
            stamp
        }
    } else {
        stamp
    };
    let bytes = timestamp.as_bytes();

    if bytes.len() != 15 && bytes.len() != 22 {
        return false;
    }
    if bytes[8] != b'-' {
        return false;
    }
    if bytes.len() == 22 && bytes[15] != b'.' {
        return false;
    }

    bytes.iter().enumerate().all(|(index, byte)| {
        index == 8 || (bytes.len() == 22 && index == 15) || byte.is_ascii_digit()
    })
}

fn remove_existing(path: &Path) -> io::Result<()> {
    let metadata = entry_metadata(path)?;
    if metadata.file_type().is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    }
}

fn sync_parent(path: &Path) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::File::open(parent)?.sync_all()
}

fn copy_entry(src: &Path, dst: &Path) -> io::Result<()> {
    let metadata = entry_metadata(src)?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        let target = fs::read_link(src)?;
        symlink(target, dst)?;
        return Ok(());
    }
    if file_type.is_dir() {
        fs::create_dir(dst)?;
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            copy_entry(&entry.path(), &dst.join(entry.file_name()))?;
        }
        fs::set_permissions(dst, metadata.permissions())?;
        fs::File::open(dst)?.sync_all()?;
        return Ok(());
    }
    if file_type.is_file() {
        let mut source = fs::File::open(src)?;
        let mut destination = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dst)?;
        io::copy(&mut source, &mut destination)?;
        destination.set_permissions(metadata.permissions())?;
        destination.sync_all()?;
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("unsupported filesystem entry type: {}", src.display()),
    ))
}

fn sibling_temp(dst: &Path, role: &str) -> PathBuf {
    let parent = dst.parent().unwrap_or_else(|| Path::new("."));
    let name = dst
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("entry");
    parent.join(format!(
        ".{name}.sentinel0-{role}-{:016x}",
        rand::rng().random::<u64>()
    ))
}

fn cleanup_entry(path: &Path, context: &str) -> Option<String> {
    match entry_exists(path) {
        Ok(false) => return None,
        Ok(true) => {}
        Err(error) => {
            let message = format!(
                "{context}: failed inspecting {} before cleanup: {error}",
                path.display()
            );
            tracing::warn!(%message);
            return Some(message);
        }
    }
    match remove_existing(path) {
        Ok(()) => None,
        Err(error) => {
            let message = format!("{context}: failed cleaning {}: {error}", path.display());
            tracing::warn!(%message);
            Some(message)
        }
    }
}

fn commit_staged(dst: &Path, staged: &Path, overwrite: bool) -> io::Result<Option<String>> {
    if !overwrite {
        rename_no_replace(staged, dst)?;
        sync_parent(dst)?;
        return Ok(None);
    }
    if !entry_exists(dst)? {
        fs::rename(staged, dst)?;
        sync_parent(dst)?;
        return Ok(None);
    }

    let staged_is_dir = entry_metadata(staged)?.file_type().is_dir();
    let dst_is_dir = entry_metadata(dst)?.file_type().is_dir();

    // POSIX rename atomically replaces non-directories. Use that when it can
    // express the replacement without first removing the destination.
    if !staged_is_dir && !dst_is_dir {
        fs::rename(staged, dst)?;
        sync_parent(dst)?;
        return Ok(None);
    }

    let old = sibling_temp(dst, "old");
    rename_no_replace(dst, &old)?;
    if let Err(commit_error) = fs::rename(staged, dst) {
        let rollback = rename_no_replace(&old, dst);
        return match rollback {
            Ok(()) => Err(commit_error),
            Err(rollback_error) => Err(io::Error::other(format!(
                "replacement failed: {commit_error}; rollback also failed: {rollback_error}; old destination remains at {}",
                old.display()
            ))),
        };
    }
    sync_parent(dst)?;
    Ok(cleanup_entry(
        &old,
        "replacement committed but old destination cleanup failed",
    ))
}

fn staged_copy(src: &Path, dst: &Path, overwrite: bool) -> io::Result<Option<String>> {
    let staged = sibling_temp(dst, "copy");
    let copy_result = copy_entry(src, &staged);
    if let Err(error) = copy_result {
        let cleanup = cleanup_entry(&staged, "copy failed");
        return Err(io::Error::other(cleanup.map_or_else(
            || error.to_string(),
            |cleanup| format!("{error}; {cleanup}"),
        )));
    }
    match commit_staged(dst, &staged, overwrite) {
        Ok(warning) => Ok(warning),
        Err(error) => {
            let cleanup = cleanup_entry(&staged, "commit failed");
            Err(io::Error::other(cleanup.map_or_else(
                || error.to_string(),
                |cleanup| format!("{error}; {cleanup}"),
            )))
        }
    }
}

fn sync_move_parents(src: &Path, dst: &Path) -> io::Result<()> {
    sync_parent(dst)?;
    if src.parent() != dst.parent() {
        sync_parent(src)?;
    }
    Ok(())
}

fn move_response(src: &Path, dst: &Path, warning: Option<String>) -> BTreeMap<String, Value> {
    let mut result = BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("op".into(), Value::String("move".into())),
        ("src".into(), Value::String(src.display().to_string())),
        ("dst".into(), Value::String(dst.display().to_string())),
    ]);
    if let Some(warning) = warning {
        result.insert("cleanup_warning".into(), Value::String(warning));
    }
    result
}

fn try_direct_move(src: &Path, dst: &Path, overwrite: bool) -> Result<bool, HandlerError> {
    let rename_result = if overwrite {
        fs::rename(src, dst)
    } else {
        rename_no_replace(src, dst)
    };
    match rename_result {
        Ok(()) => {
            sync_move_parents(src, dst).map_err(|error| {
                HandlerError::new("move_failed", format!("move sync failed: {error}"))
            })?;
            Ok(true)
        }
        Err(error) => {
            let destination_exists = overwrite
                && checked_entry_exists(
                    dst,
                    "move_failed",
                    "cannot inspect destination after rename failure",
                )?;
            if error.kind() != io::ErrorKind::CrossesDevices && !destination_exists {
                return Err(HandlerError::new(
                    if error.kind() == io::ErrorKind::PermissionDenied {
                        "permission_denied"
                    } else {
                        "move_failed"
                    },
                    format!("move failed: {error}"),
                ));
            }
            Ok(false)
        }
    }
}

fn try_move_over_existing(
    src: &Path,
    dst: &Path,
) -> Result<Option<BTreeMap<String, Value>>, HandlerError> {
    let old = sibling_temp(dst, "old");
    rename_no_replace(dst, &old).map_err(|error| {
        HandlerError::new(
            "move_failed",
            format!("could not stage old destination: {error}"),
        )
    })?;
    match fs::rename(src, dst) {
        Ok(()) => {
            sync_move_parents(src, dst).map_err(|error| {
                HandlerError::new("move_failed", format!("move sync failed: {error}"))
            })?;
            let warning = cleanup_entry(&old, "move committed but old destination cleanup failed");
            Ok(Some(move_response(src, dst, warning)))
        }
        Err(error) if error.kind() == io::ErrorKind::CrossesDevices => {
            if let Err(rollback) = rename_no_replace(&old, dst) {
                return Err(HandlerError::new(
                    "move_failed",
                    format!(
                        "cross-filesystem move detected after staging destination, and rollback failed: {rollback}; old destination remains at {}",
                        old.display()
                    ),
                ));
            }
            Ok(None)
        }
        Err(error) => {
            let rollback = rename_no_replace(&old, dst);
            Err(HandlerError::new(
                "move_failed",
                rollback.map_or_else(
                    |rollback| {
                        format!(
                            "move failed: {error}; rollback failed: {rollback}; old destination remains at {}",
                            old.display()
                        )
                    },
                    |()| format!("move failed: {error}"),
                ),
            ))
        }
    }
}

/// # Errors
/// Returns an error when the move is invalid, disallowed, or cannot be completed safely.
pub fn move_path(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let src_raw = require_str(payload, "src")?;
    let dst_raw = require_str(payload, "dst")?;
    let src = resolve_leaf_rw(policy, src_raw, "src")?;
    let dst = resolve_leaf_rw(policy, dst_raw, "dst")?;
    let overwrite = payload
        .get("overwrite")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    if !checked_entry_exists(&src, "move_failed", "cannot inspect source")? {
        return Err(HandlerError::new(
            "not_found",
            format!("src does not exist: {src_raw:?}"),
        ));
    }
    if src == dst {
        return Ok(move_response(&src, &dst, None));
    }
    let dst_exists = checked_entry_exists(&dst, "move_failed", "cannot inspect destination")?;
    if dst_exists && !overwrite {
        return Err(HandlerError::new(
            "exists",
            format!("dst already exists: {dst_raw:?}"),
        ));
    }

    if try_direct_move(&src, &dst, overwrite)? {
        return Ok(move_response(&src, &dst, None));
    }

    let dst_exists = checked_entry_exists(&dst, "move_failed", "cannot inspect destination")?;
    if dst_exists && let Some(result) = try_move_over_existing(&src, &dst)? {
        return Ok(result);
    }

    let warning = staged_copy(&src, &dst, overwrite).map_err(|error| {
        HandlerError::new(
            "move_failed",
            format!("cross-filesystem move failed: {error}"),
        )
    })?;
    if let Err(error) = remove_existing(&src) {
        return Err(HandlerError::with_details(
            "move_source_cleanup_failed",
            format!("destination was committed, but source cleanup failed: {error}"),
            Map::from_iter([
                ("destination_committed".into(), Value::Bool(true)),
                ("src".into(), Value::String(src.display().to_string())),
                ("dst".into(), Value::String(dst.display().to_string())),
            ]),
        ));
    }
    sync_move_parents(&src, &dst)
        .map_err(|error| HandlerError::new("move_failed", format!("move sync failed: {error}")))?;
    Ok(move_response(&src, &dst, warning))
}

/// # Errors
/// Returns an error when the copy is invalid, disallowed, or cannot be completed safely.
pub fn copy_path(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let src_raw = require_str(payload, "src")?;
    let dst_raw = require_str(payload, "dst")?;
    let src = resolve_leaf_rw(policy, src_raw, "src")?;
    let dst = resolve_leaf_rw(policy, dst_raw, "dst")?;
    let overwrite = payload
        .get("overwrite")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let metadata = entry_metadata(&src).map_err(|error| {
        HandlerError::new(
            if error.kind() == io::ErrorKind::NotFound {
                "not_found"
            } else {
                "copy_failed"
            },
            format!("cannot inspect source {src_raw:?}: {error}"),
        )
    })?;

    if src == dst {
        return Err(HandlerError::new(
            "invalid_payload",
            "src and dst refer to the same filesystem entry",
        ));
    }

    if metadata.file_type().is_dir() && dst.starts_with(&src) {
        return Err(HandlerError::new(
            "invalid_payload",
            "cannot copy a directory into itself or one of its descendants",
        ));
    }
    if checked_entry_exists(&dst, "copy_failed", "cannot inspect destination")? && !overwrite {
        return Err(HandlerError::new(
            "exists",
            format!("dst already exists: {dst_raw:?}"),
        ));
    }

    let warning = staged_copy(&src, &dst, overwrite)
        .map_err(|error| HandlerError::new("copy_failed", format!("copy failed: {error}")))?;
    let kind = if metadata.file_type().is_dir() {
        "dir"
    } else if metadata.file_type().is_symlink() {
        "symlink"
    } else {
        "file"
    };
    let mut result = BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("op".into(), Value::String("copy".into())),
        ("src".into(), Value::String(src.display().to_string())),
        ("dst".into(), Value::String(dst.display().to_string())),
        ("kind".into(), Value::String(kind.into())),
    ]);
    if let Some(warning) = warning {
        result.insert("cleanup_warning".into(), Value::String(warning));
    }
    Ok(result)
}

/// # Errors
/// Returns an error when deletion is invalid, disallowed, or cannot be completed safely.
pub fn delete(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let raw = require_str(payload, "path")?;
    let target = resolve_leaf_rw(policy, raw, "path")?;
    if !checked_entry_exists(&target, "delete_failed", "cannot inspect target")? {
        return Err(HandlerError::new(
            "not_found",
            format!("path does not exist: {raw:?}"),
        ));
    }
    let is_dir = target.is_dir() && !target.is_symlink();
    if is_dir
        && !payload
            .get("recursive")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        return Err(HandlerError::new(
            "is_directory",
            format!("{raw:?} is a directory; pass recursive=true to delete it"),
        ));
    }
    let own_backup = is_own_backup(&target);
    let backup = if own_backup {
        None
    } else if is_dir {
        Some(backup_dir(&target)?)
    } else {
        Some(backup_file(&target)?)
    };

    remove_existing(&target)
        .map_err(|e| HandlerError::new("delete_failed", format!("delete failed: {e}")))?;

    let mut result = BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("op".into(), Value::String("delete".into())),
        ("path".into(), Value::String(target.display().to_string())),
        (
            "kind".into(),
            Value::String(if is_dir { "dir" } else { "file" }.into()),
        ),
        (
            "backup".into(),
            backup.as_ref().map_or(Value::Null, |path| {
                Value::String(path.display().to_string())
            }),
        ),
    ]);

    if own_backup {
        result.insert("terminal".into(), Value::Bool(true));
        result.insert(
            "note".into(),
            Value::String(
                "This was a SentinelX backup artifact, so it was deleted permanently without making a backup of the backup. Space is reclaimed; there is no recovery copy."
                    .into(),
            ),
        );
    }

    Ok(result)
}

/// # Errors
/// Returns an error when the mode change is invalid, disallowed, or fails.
pub fn chmod(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let raw = require_str(payload, "path")?;
    let mode_raw = require_str(payload, "mode")?;
    let mode = u32::from_str_radix(mode_raw.trim_start_matches("0o"), 8).map_err(|_| {
        HandlerError::new(
            "invalid_payload",
            format!("mode must be octal: {mode_raw:?}"),
        )
    })?;
    let target = resolve_rw(policy, raw, "path")?;
    if !target.exists() {
        return Err(HandlerError::new(
            "not_found",
            format!("path does not exist: {raw:?}"),
        ));
    }
    fs::set_permissions(&target, fs::Permissions::from_mode(mode))
        .map_err(|e| HandlerError::new("chmod_failed", format!("chmod failed: {e}")))?;
    Ok(BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("op".into(), Value::String("chmod".into())),
        ("path".into(), Value::String(target.display().to_string())),
        ("mode".into(), Value::String(format!("0o{mode:o}"))),
    ]))
}

/// # Errors
/// Returns an error when the ownership change is invalid, disallowed, or fails.
pub fn chown(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    use nix::unistd::{Gid, Group, Uid, User};

    let raw = require_str(payload, "path")?;
    let owner = payload
        .get("owner")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty());
    let group = payload
        .get("group")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty());
    if owner.is_none() && group.is_none() {
        return Err(HandlerError::new(
            "invalid_payload",
            "at least one of 'owner' or 'group' is required",
        ));
    }
    let target = resolve_rw(policy, raw, "path")?;
    if !target.exists() {
        return Err(HandlerError::new(
            "not_found",
            format!("path does not exist: {raw:?}"),
        ));
    }

    let uid = match owner {
        Some(value) => Some(if let Ok(id) = value.parse::<u32>() {
            Uid::from_raw(id)
        } else {
            User::from_name(value)
                .map_err(|error| {
                    HandlerError::new("chown_failed", format!("user lookup failed: {error}"))
                })?
                .ok_or_else(|| HandlerError::new("chown_failed", format!("unknown user: {value}")))?
                .uid
        }),
        None => None,
    };
    let gid = match group {
        Some(value) => Some(if let Ok(id) = value.parse::<u32>() {
            Gid::from_raw(id)
        } else {
            Group::from_name(value)
                .map_err(|error| {
                    HandlerError::new("chown_failed", format!("group lookup failed: {error}"))
                })?
                .ok_or_else(|| {
                    HandlerError::new("chown_failed", format!("unknown group: {value}"))
                })?
                .gid
        }),
        None => None,
    };

    nix::unistd::chown(&target, uid, gid).map_err(|error| {
        HandlerError::new(
            if matches!(error, nix::errno::Errno::EPERM | nix::errno::Errno::EACCES) {
                "permission_denied"
            } else {
                "chown_failed"
            },
            format!("chown failed: {error}"),
        )
    })?;

    Ok(BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("op".into(), Value::String("chown".into())),
        ("path".into(), Value::String(target.display().to_string())),
        ("owner".into(), owner.map_or(Value::Null, Value::from)),
        ("group".into(), group.map_or(Value::Null, Value::from)),
    ]))
}

/// # Errors
/// Returns an error when the requested filesystem mutation is invalid, disallowed, or fails.
pub fn handle(
    policy: &Policy,
    op: sentinel0_proto::Op,
    payload: &Map<String, Value>,
) -> HandlerResult {
    match op {
        sentinel0_proto::Op::Move => move_path(policy, payload),
        sentinel0_proto::Op::Copy => copy_path(policy, payload),
        sentinel0_proto::Op::Delete => delete(policy, payload),
        sentinel0_proto::Op::Chmod => chmod(policy, payload),
        sentinel0_proto::Op::Chown => chown(policy, payload),
        _ => Err(HandlerError::new(
            "unsupported_op",
            "not a filesystem mutation op",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{FileAccess, FileOpsPath};
    use crate::test_support::{TestError as _, TestResult, TestValue as _};
    use tempfile::tempdir;

    fn policy(root: &Path) -> Policy {
        Policy {
            file_ops_paths: vec![FileOpsPath {
                path: root.to_owned(),
                access: FileAccess::ReadWrite,
            }],
            ..Policy::default()
        }
    }

    #[test]
    fn delete_requires_explicit_recursive_and_creates_backup() -> TestResult {
        let dir = tempdir().test_value()?;
        let victim = dir.path().join("victim");
        fs::create_dir_all(&victim).test_value()?;
        fs::write(victim.join("x"), "x").test_value()?;

        let err = delete(
            &policy(dir.path()),
            &Map::from_iter([("path".into(), Value::String(victim.display().to_string()))]),
        )
        .test_error()?;
        assert_eq!(err.code, "is_directory");

        let result = delete(
            &policy(dir.path()),
            &Map::from_iter([
                ("path".into(), Value::String(victim.display().to_string())),
                ("recursive".into(), Value::Bool(true)),
            ]),
        )
        .test_value()?;
        assert!(!victim.exists());
        assert!(Path::new(result["backup"].as_str().test_value()?).exists());

        Ok(())
    }

    #[test]
    fn recognizes_only_our_timestamped_backup_names() -> TestResult {
        for name in [
            "model.gguf.bak.20260924-142530.123456",
            "project.bak.20260924-142530.123456.tar.gz",
            "legacy.bak.20260924-142530",
            "hardened.bak.20260924-142530.123456-a1b2c3d4e5f60718",
            "hardened-dir.bak.20260924-142530.123456-a1b2c3d4e5f60718.tar.gz",
        ] {
            assert!(is_own_backup(Path::new(name)), "{name}");
        }

        for name in [
            "config.bak",
            "notes.bak.txt",
            "backup.tar.gz",
            "model.gguf",
            "db.bak.2026",
            "x.bak.20260924",
            "x.bak.20260924-142530-not-ours",
        ] {
            assert!(!is_own_backup(Path::new(name)), "{name}");
        }

        Ok(())
    }

    #[test]
    fn generated_backups_are_recognized_as_ours() -> TestResult {
        let dir = tempdir().test_value()?;
        let file = dir.path().join("important.txt");
        fs::write(&file, "precious").test_value()?;
        let backup = backup_file(&file).test_value()?;
        assert!(is_own_backup(&backup));

        Ok(())
    }

    #[test]
    fn deleting_our_backup_is_terminal() -> TestResult {
        let dir = tempdir().test_value()?;
        let backup = dir.path().join("model.gguf.bak.20260924-142530.123456");
        fs::write(&backup, "backup bytes").test_value()?;

        let result = delete(
            &policy(dir.path()),
            &Map::from_iter([("path".into(), Value::String(backup.display().to_string()))]),
        )
        .test_value()?;

        assert!(!backup.exists());
        assert!(result["backup"].is_null());
        assert_eq!(result["terminal"], Value::Bool(true));
        assert_eq!(
            fs::read_dir(dir.path())
                .test_value()?
                .filter_map(Result::ok)
                .count(),
            0
        );

        Ok(())
    }

    #[test]
    fn deleting_user_bak_file_still_creates_backup() -> TestResult {
        let dir = tempdir().test_value()?;
        let file = dir.path().join("config.bak");
        fs::write(&file, "user data").test_value()?;

        let result = delete(
            &policy(dir.path()),
            &Map::from_iter([("path".into(), Value::String(file.display().to_string()))]),
        )
        .test_value()?;

        assert!(!file.exists());
        let backup = Path::new(result["backup"].as_str().test_value()?);
        assert!(backup.exists());
        assert!(!result.contains_key("terminal"));

        Ok(())
    }

    #[test]
    fn both_move_endpoints_require_rw() -> TestResult {
        let dir = tempdir().test_value()?;
        let source = dir.path().join("a");
        fs::write(&source, "x").test_value()?;
        let err = move_path(
            &policy(dir.path()),
            &Map::from_iter([
                ("src".into(), Value::String(source.display().to_string())),
                ("dst".into(), Value::String("/tmp/outside".into())),
            ]),
        )
        .test_error()?;
        assert_eq!(err.code, "path_not_allowed");

        Ok(())
    }

    #[test]
    fn directory_backup_preserves_nested_symlinks_without_reading_targets() -> TestResult {
        use flate2::read::GzDecoder;
        use std::os::unix::fs::symlink;

        let root = tempdir().test_value()?;
        let outside = tempdir().test_value()?;
        let victim = root.path().join("victim");
        fs::create_dir(&victim).test_value()?;
        let secret = outside.path().join("secret.txt");
        fs::write(&secret, "outside secret").test_value()?;
        symlink(&secret, victim.join("link")).test_value()?;

        let archive_path = backup_dir(&victim).test_value()?;
        let decoder = GzDecoder::new(fs::File::open(archive_path).test_value()?);
        let mut archive = tar::Archive::new(decoder);
        let mut saw_link = false;
        for entry in archive.entries().test_value()? {
            let entry = entry.test_value()?;
            if entry.path().test_value()?.ends_with("link") {
                assert!(entry.header().entry_type().is_symlink());
                saw_link = true;
            }
        }
        assert!(saw_link);

        Ok(())
    }

    #[test]
    fn copy_preserves_top_level_symlink_without_reading_its_target() -> TestResult {
        let root = tempdir().test_value()?;
        let outside = tempdir().test_value()?;
        let secret = outside.path().join("secret");
        fs::write(&secret, "do not read me").test_value()?;
        let source = root.path().join("source-link");
        let destination = root.path().join("copied-link");
        symlink(&secret, &source).test_value()?;

        let result = copy_path(
            &policy(root.path()),
            &Map::from_iter([
                ("src".into(), Value::String(source.display().to_string())),
                (
                    "dst".into(),
                    Value::String(destination.display().to_string()),
                ),
            ]),
        )
        .test_value()?;

        assert_eq!(result["kind"], "symlink");
        assert_eq!(fs::read_link(&destination).test_value()?, secret);
        assert_eq!(fs::read_to_string(&secret).test_value()?, "do not read me");

        Ok(())
    }

    #[test]
    fn failed_staged_copy_does_not_destroy_existing_destination() -> TestResult {
        use std::os::unix::net::UnixListener;

        let root = tempdir().test_value()?;
        let source = root.path().join("socket");
        let _listener = UnixListener::bind(&source).test_value()?;
        let destination = root.path().join("destination");
        fs::write(&destination, "keep me").test_value()?;

        let error = copy_path(
            &policy(root.path()),
            &Map::from_iter([
                ("src".into(), Value::String(source.display().to_string())),
                (
                    "dst".into(),
                    Value::String(destination.display().to_string()),
                ),
                ("overwrite".into(), Value::Bool(true)),
            ]),
        )
        .test_error()?;

        assert_eq!(error.code, "copy_failed");
        assert_eq!(fs::read_to_string(destination).test_value()?, "keep me");

        Ok(())
    }

    #[test]
    fn deleting_symlink_backs_up_link_not_target() -> TestResult {
        let root = tempdir().test_value()?;
        let outside = tempdir().test_value()?;
        let target = outside.path().join("target");
        fs::write(&target, "still here").test_value()?;
        let link = root.path().join("link");
        symlink(&target, &link).test_value()?;

        let result = delete(
            &policy(root.path()),
            &Map::from_iter([("path".into(), Value::String(link.display().to_string()))]),
        )
        .test_value()?;

        assert!(!entry_exists(&link).test_value()?);
        assert_eq!(fs::read_to_string(&target).test_value()?, "still here");
        let backup = PathBuf::from(result["backup"].as_str().test_value()?);
        assert!(
            fs::symlink_metadata(&backup)
                .test_value()?
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_link(backup).test_value()?, target);

        Ok(())
    }

    #[test]
    fn copy_to_same_entry_is_rejected_without_touching_source() -> TestResult {
        let root = tempdir().test_value()?;
        let source = root.path().join("same");
        fs::write(&source, "keep me").test_value()?;

        let error = copy_path(
            &policy(root.path()),
            &Map::from_iter([
                ("src".into(), Value::String(source.display().to_string())),
                ("dst".into(), Value::String(source.display().to_string())),
                ("overwrite".into(), Value::Bool(true)),
            ]),
        )
        .test_error()?;

        assert_eq!(error.code, "invalid_payload");
        assert_eq!(fs::read_to_string(source).test_value()?, "keep me");

        Ok(())
    }
    #[test]
    fn directory_copy_preserves_nested_symlink_without_reading_target() -> TestResult {
        let root = tempdir().test_value()?;
        let outside = tempdir().test_value()?;
        let source = root.path().join("source");
        let destination = root.path().join("destination");
        fs::create_dir(&source).test_value()?;
        let secret = outside.path().join("secret");
        fs::write(&secret, "outside").test_value()?;
        symlink(&secret, source.join("nested-link")).test_value()?;

        let result = copy_path(
            &policy(root.path()),
            &Map::from_iter([
                ("src".into(), Value::String(source.display().to_string())),
                (
                    "dst".into(),
                    Value::String(destination.display().to_string()),
                ),
            ]),
        )
        .test_value()?;

        assert_eq!(result["kind"], "dir");
        let copied_link = destination.join("nested-link");
        assert!(
            fs::symlink_metadata(&copied_link)
                .test_value()?
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_link(copied_link).test_value()?, secret);
        Ok(())
    }
}
