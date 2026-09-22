use crate::{
    handler_error::{HandlerError, HandlerResult, require_str},
    policy::Policy,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sentinel0_proto::TRANSFER_CHUNK_BYTES;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    io::{Read, Seek, SeekFrom},
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

const SESSION_TTL: Duration = Duration::from_secs(3600);

#[derive(Debug)]
struct ExportSession {
    path: PathBuf,
    size: u64,
    chunk_size: usize,
    num_chunks: u64,
    filename: String,
    created_at: Instant,
    hasher: Sha256,
    next_index: u64,
}

type SessionMap = HashMap<String, Arc<Mutex<ExportSession>>>;

fn sessions() -> &'static Mutex<SessionMap> {
    static SESSIONS: OnceLock<Mutex<SessionMap>> = OnceLock::new();
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn valid_transfer_id(payload: &Map<String, Value>) -> Result<String, HandlerError> {
    let id = require_str(payload, "transfer_id")?;
    if id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(HandlerError::new(
            "invalid_payload",
            "transfer_id must be a 32-char hex string (16 bytes)",
        ));
    }
    Ok(id.to_ascii_lowercase())
}

fn sweep(map: &mut SessionMap) {
    map.retain(|_, session| {
        session
            .lock()
            .map(|session| session.created_at.elapsed() <= SESSION_TTL)
            .unwrap_or(false)
    });
}

pub fn init(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let transfer_id = valid_transfer_id(payload)?;
    let source = require_str(payload, "source_path")?;
    let mut chunk_size = payload
        .get("chunk_size")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(TRANSFER_CHUNK_BYTES);
    if chunk_size == 0 || chunk_size > TRANSFER_CHUNK_BYTES {
        chunk_size = TRANSFER_CHUNK_BYTES;
    }

    let resolved = policy.resolve_path(source, false).ok_or_else(|| {
        HandlerError::new(
            "path_not_allowed",
            format!("source_path {source:?} is outside file_ops paths"),
        )
    })?;
    let metadata = fs::metadata(&resolved).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => HandlerError::new(
            "not_found",
            format!("source file not found: {}", resolved.display()),
        ),
        std::io::ErrorKind::PermissionDenied => HandlerError::new(
            "permission_denied",
            format!("cannot stat source: {}", resolved.display()),
        ),
        _ => HandlerError::new("io_error", error.to_string()),
    })?;
    if metadata.is_dir() {
        return Err(HandlerError::new(
            "is_directory",
            format!("source is a directory: {}", resolved.display()),
        ));
    }
    if !metadata.is_file() {
        return Err(HandlerError::new(
            "not_a_file",
            format!("source is not a regular file: {}", resolved.display()),
        ));
    }

    let size = metadata.len();
    let num_chunks = size.div_ceil(chunk_size as u64).max(1);
    let filename = resolved
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("file")
        .to_owned();

    let session = ExportSession {
        path: resolved.clone(),
        size,
        chunk_size,
        num_chunks,
        filename: filename.clone(),
        created_at: Instant::now(),
        hasher: Sha256::new(),
        next_index: 0,
    };
    let mut map = sessions()
        .lock()
        .map_err(|_| HandlerError::new("internal_error", "export session lock poisoned"))?;
    sweep(&mut map);
    map.insert(transfer_id.clone(), Arc::new(Mutex::new(session)));

    Ok(BTreeMap::from([
        ("transfer_id".into(), Value::String(transfer_id)),
        ("filename".into(), Value::String(filename)),
        (
            "source_path".into(),
            Value::String(resolved.display().to_string()),
        ),
        ("size".into(), Value::from(size)),
        ("chunk_size".into(), Value::from(chunk_size as u64)),
        ("num_chunks".into(), Value::from(num_chunks)),
    ]))
}

pub async fn chunk(payload: &Map<String, Value>) -> HandlerResult {
    let transfer_id = valid_transfer_id(payload)?;
    let index = payload
        .get("chunk_index")
        .and_then(Value::as_i64)
        .ok_or_else(|| HandlerError::new("invalid_payload", "chunk_index must be an int"))?;
    if index < 0 {
        return Err(HandlerError::new(
            "invalid_payload",
            "chunk_index must be >= 0",
        ));
    }
    let index = index as u64;

    let session = {
        let map = sessions()
            .lock()
            .map_err(|_| HandlerError::new("internal_error", "export session lock poisoned"))?;
        map.get(&transfer_id).cloned()
    }
    .ok_or_else(|| {
        HandlerError::new(
            "not_found",
            format!("no export session for transfer_id {transfer_id}"),
        )
    })?;

    let (data, eof, bytes) = tokio::task::spawn_blocking(move || {
        let mut session = session
            .lock()
            .map_err(|_| HandlerError::new("internal_error", "export session lock poisoned"))?;
        if index >= session.num_chunks {
            return Err(HandlerError::new(
                "invalid_payload",
                format!(
                    "chunk_index {index} out of range (num_chunks={})",
                    session.num_chunks
                ),
            ));
        }
        let mut file = fs::File::open(&session.path).map_err(|e| {
            HandlerError::new("io_error", format!("cannot open export source: {e}"))
        })?;
        file.seek(SeekFrom::Start(index * session.chunk_size as u64))
            .map_err(|e| {
                HandlerError::new("io_error", format!("cannot seek export source: {e}"))
            })?;
        let mut data = vec![0_u8; session.chunk_size];
        let count = file.read(&mut data).map_err(|e| {
            HandlerError::new("io_error", format!("cannot read export source: {e}"))
        })?;
        data.truncate(count);
        if index == session.next_index {
            session.hasher.update(&data);
            session.next_index += 1;
        }
        let eof = index + 1 >= session.num_chunks;
        Ok::<_, HandlerError>((data, eof, count))
    })
    .await
    .map_err(|e| HandlerError::new("internal_error", format!("export worker failed: {e}")))??;

    Ok(BTreeMap::from([
        ("transfer_id".into(), Value::String(transfer_id)),
        ("chunk_index".into(), Value::from(index)),
        (
            "__binary_payload__".into(),
            Value::String(STANDARD.encode(&data)),
        ),
        ("bytes".into(), Value::from(bytes as u64)),
        ("eof".into(), Value::Bool(eof)),
    ]))
}

pub fn complete(payload: &Map<String, Value>) -> HandlerResult {
    let transfer_id = valid_transfer_id(payload)?;
    let session = {
        let mut map = sessions()
            .lock()
            .map_err(|_| HandlerError::new("internal_error", "export session lock poisoned"))?;
        map.remove(&transfer_id)
    }
    .ok_or_else(|| {
        HandlerError::new(
            "not_found",
            format!("no export session for transfer_id {transfer_id}"),
        )
    })?;

    let session = session
        .lock()
        .map_err(|_| HandlerError::new("internal_error", "export session lock poisoned"))?;
    let complete = session.next_index == session.num_chunks;
    let digest = complete.then(|| format!("{:x}", session.hasher.clone().finalize()));

    Ok(BTreeMap::from([
        ("transfer_id".into(), Value::String(transfer_id)),
        ("size".into(), Value::from(session.size)),
        ("chunks_read".into(), Value::from(session.next_index)),
        ("num_chunks".into(), Value::from(session.num_chunks)),
        (
            "sha256".into(),
            digest.map(Value::String).unwrap_or(Value::Null),
        ),
        ("sha256_complete".into(), Value::Bool(complete)),
        ("filename".into(), Value::String(session.filename.clone())),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{FileAccess, FileOpsPath};
    use tempfile::tempdir;

    #[tokio::test]
    async fn export_hashes_only_in_order_and_returns_binary_payload() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("x.bin");
        fs::write(&source, b"abcdef").unwrap();
        let policy = Policy {
            file_ops_paths: vec![FileOpsPath {
                path: dir.path().to_owned(),
                access: FileAccess::Read,
            }],
            ..Policy::default()
        };
        let transfer_id = "00112233445566778899aabbccddeeff";
        let start = init(
            &policy,
            &Map::from_iter([
                ("transfer_id".into(), Value::String(transfer_id.into())),
                (
                    "source_path".into(),
                    Value::String(source.display().to_string()),
                ),
                ("chunk_size".into(), Value::from(3)),
            ]),
        )
        .unwrap();
        assert_eq!(start["num_chunks"], 2);

        let first = chunk(&Map::from_iter([
            ("transfer_id".into(), Value::String(transfer_id.into())),
            ("chunk_index".into(), Value::from(0)),
        ]))
        .await
        .unwrap();
        assert_eq!(
            STANDARD
                .decode(first["__binary_payload__"].as_str().unwrap())
                .unwrap(),
            b"abc"
        );
        let _ = chunk(&Map::from_iter([
            ("transfer_id".into(), Value::String(transfer_id.into())),
            ("chunk_index".into(), Value::from(1)),
        ]))
        .await
        .unwrap();
        let done = complete(&Map::from_iter([(
            "transfer_id".into(),
            Value::String(transfer_id.into()),
        )]))
        .unwrap();
        assert_eq!(done["sha256_complete"], true);
        assert_eq!(done["chunks_read"], 2);
    }
}
