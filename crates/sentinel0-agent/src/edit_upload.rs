use crate::{
    edit,
    handler_error::{HandlerError, HandlerResult, require_str},
    policy::Policy,
    staging,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand::RngExt;
use serde_json::{Map, Value};
use std::{collections::BTreeMap, fs, path::PathBuf};

fn safe_id(value: &str) -> Result<&str, HandlerError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(HandlerError::new("invalid_payload", "invalid upload_id"));
    }
    Ok(value)
}

fn upload_dir(policy: &Policy, upload_id: &str) -> Result<PathBuf, HandlerError> {
    let root = staging::staging_root(&policy.upload_base)
        .map_err(|e| HandlerError::new("io_error", e.to_string()))?;
    let dir = root.join(format!("edit_{}", safe_id(upload_id)?));
    fs::create_dir_all(&dir)
        .map_err(|e| HandlerError::new("io_error", format!("failed creating upload dir: {e}")))?;
    Ok(dir)
}

pub fn init(policy: &Policy) -> HandlerResult {
    let upload_id = format!(
        "{:016x}{:016x}",
        rand::rng().random::<u64>(),
        rand::rng().random::<u64>()
    );
    let dir = upload_dir(policy, &upload_id)?;
    Ok(BTreeMap::from([
        ("upload_id".into(), Value::String(upload_id)),
        (
            "upload_dir".into(),
            Value::String(dir.display().to_string()),
        ),
    ]))
}

pub fn file(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let upload_id = require_str(payload, "upload_id")?;
    let role = require_str(payload, "role")?;
    if !matches!(role, "old" | "new") {
        return Err(HandlerError::new(
            "invalid_payload",
            "role must be 'old' or 'new'",
        ));
    }
    let content = payload.get("content");
    let encoded = payload.get("content_base64");
    if content.is_some() && encoded.is_some() {
        return Err(HandlerError::new(
            "invalid_payload",
            "provide exactly one of 'content' or 'content_base64'",
        ));
    }

    let data = match (content, encoded) {
        (Some(Value::String(text)), None) => text.as_bytes().to_vec(),
        (None, Some(Value::String(text))) => STANDARD
            .decode(text)
            .map_err(|e| HandlerError::new("invalid_payload", format!("bad base64: {e}")))?,
        _ => {
            return Err(HandlerError::new(
                "invalid_payload",
                "missing 'content' or 'content_base64'",
            ));
        }
    };

    let dir = upload_dir(policy, upload_id)?;
    let path = dir.join(format!("{role}.txt"));
    fs::write(&path, &data)
        .map_err(|e| HandlerError::new("io_error", format!("failed writing staged role: {e}")))?;

    let filename = payload
        .get("filename")
        .and_then(Value::as_str)
        .and_then(|name| std::path::Path::new(name).file_name())
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && !name.starts_with('.'))
        .unwrap_or_else(|| if role == "old" { "old.txt" } else { "new.txt" });

    Ok(BTreeMap::from([
        ("upload_id".into(), Value::String(upload_id.into())),
        ("role".into(), Value::String(role.into())),
        ("filename".into(), Value::String(filename.into())),
        ("size_bytes".into(), Value::from(data.len() as u64)),
        ("path".into(), Value::String(path.display().to_string())),
    ]))
}

pub fn complete(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let upload_id = require_str(payload, "upload_id")?;
    let mode = require_str(payload, "mode")?;
    let _ = require_str(payload, "path")?;
    let dir = upload_dir(policy, upload_id)?;
    let old_path = dir.join("old.txt");
    let new_path = dir.join("new.txt");

    let needs_new = matches!(
        mode,
        "replace" | "regex" | "replace-block" | "append" | "prepend" | "write"
    );
    let needs_old = matches!(mode, "replace" | "replace-block");
    if needs_new && !new_path.exists() {
        return Err(HandlerError::new(
            "missing_role_file",
            format!("mode={mode} requires the 'new' role file"),
        ));
    }
    if needs_old && !old_path.exists() {
        return Err(HandlerError::new(
            "missing_role_file",
            format!("mode={mode} requires the 'old' role file"),
        ));
    }

    let mut edit_payload = payload.clone();
    edit_payload.remove("upload_id");
    if old_path.exists() {
        edit_payload.insert(
            "old".into(),
            Value::String(fs::read_to_string(&old_path).map_err(|e| {
                HandlerError::new("io_error", format!("failed reading old role: {e}"))
            })?),
        );
    }
    if new_path.exists() {
        edit_payload.insert(
            "new_text".into(),
            Value::String(fs::read_to_string(&new_path).map_err(|e| {
                HandlerError::new("io_error", format!("failed reading new role: {e}"))
            })?),
        );
    }

    let result = edit::edit(policy, &edit_payload);
    if result.is_ok() {
        let _ = fs::remove_dir_all(&dir);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{FileAccess, FileOpsPath};
    use tempfile::tempdir;

    #[test]
    fn chunked_write_flows_through_native_editor() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("x.txt");
        fs::write(&target, "before").unwrap();
        let policy = Policy {
            upload_base: dir.path().join("uploads"),
            file_ops_paths: vec![FileOpsPath {
                path: dir.path().to_owned(),
                access: FileAccess::ReadWrite,
            }],
            ..Policy::default()
        };
        let init = init(&policy).unwrap();
        let id = init["upload_id"].as_str().unwrap();
        file(
            &policy,
            &Map::from_iter([
                ("upload_id".into(), Value::String(id.into())),
                ("role".into(), Value::String("new".into())),
                ("content".into(), Value::String("after".into())),
            ]),
        )
        .unwrap();
        let result = complete(
            &policy,
            &Map::from_iter([
                ("upload_id".into(), Value::String(id.into())),
                ("path".into(), Value::String(target.display().to_string())),
                ("mode".into(), Value::String("write".into())),
            ]),
        )
        .unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(fs::read_to_string(target).unwrap(), "after");
    }
}
