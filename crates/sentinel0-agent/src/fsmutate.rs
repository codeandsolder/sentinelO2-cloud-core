use crate::{
    handler_error::{HandlerError, HandlerResult, require_str},
    policy::Policy,
};
use chrono::Utc;
use flate2::{Compression, write::GzEncoder};
use serde_json::{Map, Value};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
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

fn backup_file(path: &Path) -> Result<PathBuf, HandlerError> {
    let backup = path.with_file_name(format!(
        "{}.bak.{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("file"),
        Utc::now().format("%Y%m%d-%H%M%S%.6f")
    ));
    let result = (|| -> std::io::Result<()> {
        fs::copy(path, &backup)?;
        fs::File::open(&backup)?.sync_all()
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&backup);
        return Err(HandlerError::new(
            "backup_failed",
            format!("backup failed: {error}"),
        ));
    }
    Ok(backup)
}

fn backup_dir(path: &Path) -> Result<PathBuf, HandlerError> {
    let archive = path.with_file_name(format!(
        "{}.bak.{}.tar.gz",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("dir"),
        Utc::now().format("%Y%m%d-%H%M%S%.6f")
    ));

    let result = (|| -> Result<(), HandlerError> {
        let file = fs::File::create(&archive)
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
            .map_err(|e| HandlerError::new("backup_failed", format!("backup failed: {e}")))
    })();

    if let Err(error) = result {
        let _ = fs::remove_file(&archive);
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
    let bytes = stamp.as_bytes();

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

fn remove_existing(path: &Path) -> std::io::Result<()> {
    if path.is_dir() && !path.is_symlink() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    }
}

fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let source = entry.path();
        let target = dst.join(entry.file_name());
        if source.is_dir() && !source.is_symlink() {
            copy_tree(&source, &target)?;
        } else {
            fs::copy(&source, &target)?;
        }
    }
    Ok(())
}

pub fn move_path(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let src_raw = require_str(payload, "src")?;
    let dst_raw = require_str(payload, "dst")?;
    let src = resolve_rw(policy, src_raw, "src")?;
    let dst = resolve_rw(policy, dst_raw, "dst")?;
    let overwrite = payload
        .get("overwrite")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !src.exists() {
        return Err(HandlerError::new(
            "not_found",
            format!("src does not exist: {src_raw:?}"),
        ));
    }
    if dst.exists() {
        if !overwrite {
            return Err(HandlerError::new(
                "exists",
                format!("dst already exists: {dst_raw:?}"),
            ));
        }
        remove_existing(&dst).map_err(|e| HandlerError::new("move_failed", e.to_string()))?;
    }
    fs::rename(&src, &dst)
        .or_else(|_| {
            if src.is_dir() {
                copy_tree(&src, &dst)?;
                fs::remove_dir_all(&src)
            } else {
                fs::copy(&src, &dst)?;
                fs::remove_file(&src)
            }
        })
        .map_err(|e| {
            HandlerError::new(
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    "permission_denied"
                } else {
                    "move_failed"
                },
                format!("move failed: {e}"),
            )
        })?;
    Ok(BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("op".into(), Value::String("move".into())),
        ("src".into(), Value::String(src.display().to_string())),
        ("dst".into(), Value::String(dst.display().to_string())),
    ]))
}

pub fn copy_path(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let src_raw = require_str(payload, "src")?;
    let dst_raw = require_str(payload, "dst")?;
    let src = resolve_rw(policy, src_raw, "src")?;
    let dst = resolve_rw(policy, dst_raw, "dst")?;
    let overwrite = payload
        .get("overwrite")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !src.exists() {
        return Err(HandlerError::new(
            "not_found",
            format!("src does not exist: {src_raw:?}"),
        ));
    }
    if dst.exists() {
        if !overwrite {
            return Err(HandlerError::new(
                "exists",
                format!("dst already exists: {dst_raw:?}"),
            ));
        }
        remove_existing(&dst).map_err(|e| HandlerError::new("copy_failed", e.to_string()))?;
    }
    let kind = if src.is_dir() && !src.is_symlink() {
        copy_tree(&src, &dst)
            .map_err(|e| HandlerError::new("copy_failed", format!("copy failed: {e}")))?;
        "dir"
    } else {
        fs::copy(&src, &dst)
            .map_err(|e| HandlerError::new("copy_failed", format!("copy failed: {e}")))?;
        "file"
    };
    Ok(BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("op".into(), Value::String("copy".into())),
        ("src".into(), Value::String(src.display().to_string())),
        ("dst".into(), Value::String(dst.display().to_string())),
        ("kind".into(), Value::String(kind.into())),
    ]))
}

pub fn delete(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let raw = require_str(payload, "path")?;
    let target = resolve_rw(policy, raw, "path")?;
    if !target.exists() && !target.is_symlink() {
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
            backup
                .as_ref()
                .map(|path| Value::String(path.display().to_string()))
                .unwrap_or(Value::Null),
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

pub fn chown(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
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
    let spec = match (owner, group) {
        (Some(owner), Some(group)) => format!("{owner}:{group}"),
        (Some(owner), None) => owner.to_owned(),
        (None, Some(group)) => format!(":{group}"),
        (None, None) => unreachable!(),
    };
    let output = Command::new("chown")
        .arg(&spec)
        .arg(&target)
        .output()
        .map_err(|e| HandlerError::new("chown_failed", format!("chown failed: {e}")))?;
    if !output.status.success() {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(HandlerError::new(
            if message.to_lowercase().contains("operation not permitted")
                || message.to_lowercase().contains("permission denied")
            {
                "permission_denied"
            } else {
                "chown_failed"
            },
            if message.is_empty() {
                "chown failed".into()
            } else {
                message
            },
        ));
    }
    Ok(BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("op".into(), Value::String("chown".into())),
        ("path".into(), Value::String(target.display().to_string())),
        (
            "owner".into(),
            owner.map(Value::from).unwrap_or(Value::Null),
        ),
        (
            "group".into(),
            group.map(Value::from).unwrap_or(Value::Null),
        ),
    ]))
}

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
    fn delete_requires_explicit_recursive_and_creates_backup() {
        let dir = tempdir().unwrap();
        let victim = dir.path().join("victim");
        fs::create_dir_all(&victim).unwrap();
        fs::write(victim.join("x"), "x").unwrap();

        let err = delete(
            &policy(dir.path()),
            &Map::from_iter([("path".into(), Value::String(victim.display().to_string()))]),
        )
        .unwrap_err();
        assert_eq!(err.code, "is_directory");

        let result = delete(
            &policy(dir.path()),
            &Map::from_iter([
                ("path".into(), Value::String(victim.display().to_string())),
                ("recursive".into(), Value::Bool(true)),
            ]),
        )
        .unwrap();
        assert!(!victim.exists());
        assert!(Path::new(result["backup"].as_str().unwrap()).exists());
    }

    #[test]
    fn recognizes_only_our_timestamped_backup_names() {
        for name in [
            "model.gguf.bak.20260924-142530.123456",
            "project.bak.20260924-142530.123456.tar.gz",
            "legacy.bak.20260924-142530",
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
    }

    #[test]
    fn generated_backups_are_recognized_as_ours() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("important.txt");
        fs::write(&file, "precious").unwrap();
        let backup = backup_file(&file).unwrap();
        assert!(is_own_backup(&backup));
    }

    #[test]
    fn deleting_our_backup_is_terminal() {
        let dir = tempdir().unwrap();
        let backup = dir
            .path()
            .join("model.gguf.bak.20260924-142530.123456");
        fs::write(&backup, "backup bytes").unwrap();

        let result = delete(
            &policy(dir.path()),
            &Map::from_iter([(
                "path".into(),
                Value::String(backup.display().to_string()),
            )]),
        )
        .unwrap();

        assert!(!backup.exists());
        assert!(result["backup"].is_null());
        assert_eq!(result["terminal"], Value::Bool(true));
        assert_eq!(
            fs::read_dir(dir.path())
                .unwrap()
                .filter_map(Result::ok)
                .count(),
            0
        );
    }

    #[test]
    fn deleting_user_bak_file_still_creates_backup() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("config.bak");
        fs::write(&file, "user data").unwrap();

        let result = delete(
            &policy(dir.path()),
            &Map::from_iter([(
                "path".into(),
                Value::String(file.display().to_string()),
            )]),
        )
        .unwrap();

        assert!(!file.exists());
        let backup = Path::new(result["backup"].as_str().unwrap());
        assert!(backup.exists());
        assert!(!result.contains_key("terminal"));
    }

    #[test]
    fn both_move_endpoints_require_rw() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("a");
        fs::write(&source, "x").unwrap();
        let err = move_path(
            &policy(dir.path()),
            &Map::from_iter([
                ("src".into(), Value::String(source.display().to_string())),
                ("dst".into(), Value::String("/tmp/outside".into())),
            ]),
        )
        .unwrap_err();
        assert_eq!(err.code, "path_not_allowed");
    }

    #[test]
    fn directory_backup_preserves_nested_symlinks_without_reading_targets() {
        use flate2::read::GzDecoder;
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let victim = root.path().join("victim");
        fs::create_dir(&victim).unwrap();
        let secret = outside.path().join("secret.txt");
        fs::write(&secret, "outside secret").unwrap();
        symlink(&secret, victim.join("link")).unwrap();

        let archive_path = backup_dir(&victim).unwrap();
        let decoder = GzDecoder::new(fs::File::open(archive_path).unwrap());
        let mut archive = tar::Archive::new(decoder);
        let mut saw_link = false;
        for entry in archive.entries().unwrap() {
            let entry = entry.unwrap();
            if entry.path().unwrap().ends_with("link") {
                assert!(entry.header().entry_type().is_symlink());
                saw_link = true;
            }
        }
        assert!(saw_link);
    }
}
