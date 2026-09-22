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
    fs::copy(path, &backup)
        .map_err(|e| HandlerError::new("backup_failed", format!("backup failed: {e}")))?;
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
    let file = fs::File::create(&archive)
        .map_err(|e| HandlerError::new("backup_failed", format!("backup failed: {e}")))?;
    let encoder = GzEncoder::new(file, Compression::default());
    let mut tar = tar::Builder::new(encoder);
    let name = path.file_name().unwrap_or_default();
    tar.append_dir_all(name, path)
        .map_err(|e| HandlerError::new("backup_failed", format!("backup failed: {e}")))?;
    tar.finish()
        .map_err(|e| HandlerError::new("backup_failed", format!("backup failed: {e}")))?;
    Ok(archive)
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
    let backup = if is_dir {
        backup_dir(&target)?
    } else {
        backup_file(&target)?
    };
    remove_existing(&target)
        .map_err(|e| HandlerError::new("delete_failed", format!("delete failed: {e}")))?;
    Ok(BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("op".into(), Value::String("delete".into())),
        ("path".into(), Value::String(target.display().to_string())),
        (
            "kind".into(),
            Value::String(if is_dir { "dir" } else { "file" }.into()),
        ),
        ("backup".into(), Value::String(backup.display().to_string())),
    ]))
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
}
