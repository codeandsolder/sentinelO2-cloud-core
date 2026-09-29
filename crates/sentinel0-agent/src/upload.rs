use crate::{
    fsutil::rename_no_replace,
    handler_error::{HandlerError, HandlerResult, require_str},
    policy::Policy,
    staging,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures_util::StreamExt;
use reqwest::{Client, redirect::Policy as RedirectPolicy};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Component, Path, PathBuf},
    time::Duration,
};
use tokio::{fs as async_fs, io::AsyncWriteExt, net::lookup_host};

pub const MAX_UPLOAD_BYTES: u64 = 10 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UploadMeta {
    upload_id: String,
    target_path: String,
    #[serde(default)]
    landed_in_place: bool,
    overwrite: bool,
    total_size: u64,
    filename: Option<String>,
}

fn valid_upload_id(value: Option<&Value>) -> Result<String, HandlerError> {
    match value {
        None | Some(Value::Null) => Ok(format!(
            "{:016x}{:016x}",
            rand::random::<u64>(),
            rand::random::<u64>()
        )),
        Some(Value::String(id))
            if (16..=64).contains(&id.len()) && id.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            Ok(id.to_ascii_lowercase())
        }
        _ => Err(HandlerError::new(
            "invalid_payload",
            "upload_id, when provided, must be a 16-64 char hex string",
        )),
    }
}

fn upload_dir(policy: &Policy, upload_id: &str) -> Result<PathBuf, HandlerError> {
    let root = staging::staging_root(&policy.upload_base)
        .map_err(|e| HandlerError::new("io_error", e.to_string()))?;
    let dir = root.join(upload_id);
    fs::create_dir_all(dir.join("parts"))
        .map_err(|e| HandlerError::new("io_error", format!("failed creating upload dir: {e}")))?;
    Ok(dir)
}

fn meta_path(dir: &Path) -> PathBuf {
    dir.join("meta.json")
}

fn safe_dest(upload_base: &Path, target: &str) -> Result<PathBuf, HandlerError> {
    if target.trim().is_empty() {
        return Err(HandlerError::new(
            "invalid_payload",
            "missing 'target_path'",
        ));
    }
    // Match the official upload staging semantics: a leading slash does
    // not grant an absolute write, it is stripped and the path remains rooted
    // under upload_base. Parent traversal is still refused.
    let stripped = target.trim().trim_start_matches('/');
    let relative = Path::new(stripped);
    if relative.as_os_str().is_empty()
        || relative.components().any(|part| {
            matches!(
                part,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(HandlerError::new(
            "path_traversal",
            "target_path must remain under upload_base and must not contain '..'",
        ));
    }

    let base = soft_canonicalize::soft_canonicalize(upload_base)
        .map_err(|e| HandlerError::new("io_error", format!("cannot resolve upload_base: {e}")))?;
    let joined = base.join(relative);
    let resolved = soft_canonicalize::soft_canonicalize(&joined)
        .map_err(|e| HandlerError::new("io_error", format!("cannot resolve upload target: {e}")))?;
    if resolved != base && !resolved.starts_with(&base) {
        return Err(HandlerError::new(
            "path_traversal",
            "target_path resolves outside upload_base",
        ));
    }
    Ok(resolved)
}

fn hex_bytes(bytes: impl AsRef<[u8]>) -> String {
    crate::hex_lower(bytes.as_ref())
}

fn hash_bytes(data: &[u8]) -> String {
    hex_bytes(Sha256::digest(data))
}

fn is_safe_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !(ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_unspecified()
                || ip.octets()[0] == 0
                || ip.octets()[0] >= 240
                || is_cgnat(ip))
        }
        IpAddr::V6(ip) => {
            !(ip.is_loopback()
                || ip.is_multicast()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || is_ipv6_documentation(ip))
        }
    }
}

fn is_cgnat(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

const fn is_ipv6_documentation(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] == 0x2001 && segments[1] == 0x0db8
}

async fn validate_fetch_url(
    policy: &Policy,
    raw: &str,
) -> Result<(url::Url, String, Vec<std::net::SocketAddr>), HandlerError> {
    let url = url::Url::parse(raw)
        .map_err(|e| HandlerError::new("invalid_payload", format!("bad file_url: {e}")))?;
    if url.scheme() != "https" {
        return Err(HandlerError::new(
            "invalid_payload",
            "file_url must be https",
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| HandlerError::new("invalid_payload", "file_url has no hostname"))?
        .to_ascii_lowercase();
    if policy.trusted_fetch_hosts.is_empty() {
        return Err(HandlerError::new(
            "fetch_blocked",
            "file_url fetching is disabled because trusted_fetch_hosts is empty",
        ));
    }
    if !policy
        .trusted_fetch_hosts
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&host))
    {
        return Err(HandlerError::new(
            "fetch_blocked",
            format!("hostname {host:?} is not in security.trusted_fetch_hosts"),
        ));
    }

    let port = url.port_or_known_default().unwrap_or(443);
    let addresses = lookup_host((host.as_str(), port))
        .await
        .map_err(|e| HandlerError::new("fetch_failed", format!("DNS resolution failed: {e}")))?
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(HandlerError::new(
            "fetch_failed",
            "DNS resolution returned no addresses",
        ));
    }
    for address in &addresses {
        if !is_safe_ip(address.ip()) {
            return Err(HandlerError::new(
                "fetch_blocked",
                format!(
                    "hostname {host:?} resolved to non-public IP {}",
                    address.ip()
                ),
            ));
        }
    }
    Ok((url, host, addresses))
}

async fn fetch_to(
    policy: &Policy,
    raw: &str,
    destination: &Path,
) -> Result<(u64, String), HandlerError> {
    let (url, host, addresses) = validate_fetch_url(policy, raw).await?;
    let client = Client::builder()
        .redirect(RedirectPolicy::none())
        // A proxy would resolve/connect independently and defeat the DNS pin.
        .no_proxy()
        .timeout(Duration::from_secs(policy.file_url_timeout_seconds))
        // Use the exact public addresses we just vetted. Otherwise reqwest
        // performs a second DNS lookup between the policy check and connect.
        .resolve_to_addrs(&host, &addresses)
        .build()
        .map_err(|e| HandlerError::new("fetch_failed", e.to_string()))?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| HandlerError::new("fetch_failed", format!("could not fetch URL: {e}")))?;
    if !response.status().is_success() {
        return Err(HandlerError::new(
            "fetch_failed",
            format!("remote returned HTTP {}", response.status()),
        ));
    }

    let mut file = async_fs::File::create(destination)
        .await
        .map_err(|e| HandlerError::new("io_error", format!("cannot create staged upload: {e}")))?;
    let mut stream = response.bytes_stream();
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| HandlerError::new("fetch_failed", e.to_string()))?;
        size = size.saturating_add(chunk.len() as u64);
        if size > MAX_UPLOAD_BYTES {
            return Err(HandlerError::new(
                "file_too_large",
                format!("file exceeds upload cap of {MAX_UPLOAD_BYTES} bytes"),
            ));
        }
        hasher.update(&chunk);
        file.write_all(&chunk).await.map_err(|e| {
            HandlerError::new("io_error", format!("failed writing staged upload: {e}"))
        })?;
    }
    Ok((size, hex_bytes(hasher.finalize())))
}

async fn prepare_single_destination(
    policy: &Policy,
    target: &str,
    overwrite: bool,
) -> Result<PathBuf, HandlerError> {
    async_fs::create_dir_all(&policy.upload_base)
        .await
        .map_err(|e| HandlerError::new("io_error", format!("cannot create upload_base: {e}")))?;
    let upload_base = policy.upload_base.clone();
    let target_owned = target.to_owned();
    let destination = tokio::task::spawn_blocking(move || safe_dest(&upload_base, &target_owned))
        .await
        .map_err(|e| HandlerError::new("internal_error", format!("path resolver failed: {e}")))??;
    if async_fs::try_exists(&destination)
        .await
        .map_err(|e| HandlerError::new("io_error", format!("cannot stat upload target: {e}")))?
        && !overwrite
    {
        return Err(HandlerError::new(
            "conflict",
            format!("a file already exists at {}", destination.display()),
        ));
    }
    if let Some(parent) = destination.parent() {
        async_fs::create_dir_all(parent).await.map_err(|e| {
            HandlerError::new("io_error", format!("cannot create destination parent: {e}"))
        })?;
    }
    Ok(destination)
}

async fn stage_single_upload(
    policy: &Policy,
    content: Option<&str>,
    file_url: Option<&str>,
    temp: &Path,
) -> Result<(u64, String), HandlerError> {
    if let Some(encoded) = content {
        let bytes = STANDARD
            .decode(encoded)
            .map_err(|e| HandlerError::new("invalid_payload", format!("bad base64: {e}")))?;
        let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if size > MAX_UPLOAD_BYTES {
            return Err(HandlerError::new(
                "file_too_large",
                "decoded file exceeds upload cap",
            ));
        }
        async_fs::write(temp, &bytes).await.map_err(|error| {
            HandlerError::new("io_error", format!("failed staging upload: {error}"))
        })?;
        Ok((size, hash_bytes(&bytes)))
    } else {
        fetch_to(policy, file_url.unwrap_or_default(), temp).await
    }
}

async fn finalize_single_upload(
    temp: &Path,
    destination: &Path,
    overwrite: bool,
) -> Result<(), HandlerError> {
    let finalize = if overwrite {
        async_fs::rename(temp, destination).await
    } else {
        let temp = temp.to_owned();
        let destination = destination.to_owned();
        tokio::task::spawn_blocking(move || rename_no_replace(&temp, &destination))
            .await
            .map_err(|error| {
                HandlerError::new(
                    "internal_error",
                    format!("upload finalization task failed: {error}"),
                )
            })?
    };
    if let Err(error) = finalize {
        let cleanup = match async_fs::remove_file(temp).await {
            Ok(()) => None,
            Err(cleanup) if cleanup.kind() == std::io::ErrorKind::NotFound => None,
            Err(cleanup) => Some(cleanup),
        };
        let code = if error.kind() == std::io::ErrorKind::AlreadyExists {
            "conflict"
        } else {
            "io_error"
        };
        return Err(HandlerError::new(
            code,
            cleanup.map_or_else(
                || format!("failed finalizing upload: {error}"),
                |cleanup| {
                    format!(
                        "failed finalizing upload: {error}; staged-file cleanup also failed: {cleanup}"
                    )
                },
            ),
        ));
    }
    Ok(())
}

/// # Errors
/// Returns an error when the upload request is invalid, disallowed, cannot be fetched, or cannot be finalized safely.
pub async fn upload_file(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let target = require_str(payload, "target_path")?;
    let overwrite = payload
        .get("overwrite")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let content = payload.get("content_base64").and_then(Value::as_str);
    let file_url = payload.get("file_url").and_then(Value::as_str);
    if content.is_some() == file_url.is_some() {
        return Err(HandlerError::new(
            "invalid_payload",
            "provide exactly one of 'content_base64' or 'file_url'",
        ));
    }

    let destination = prepare_single_destination(policy, target, overwrite).await?;
    let upload_base = policy.upload_base.clone();
    let staging = tokio::task::spawn_blocking(move || staging::staging_root(&upload_base))
        .await
        .map_err(|e| HandlerError::new("internal_error", format!("staging setup failed: {e}")))?
        .map_err(|e| HandlerError::new("io_error", e.to_string()))?;
    let temp = staging.join(format!("single-{:016x}.upload", rand::random::<u64>()));
    let staged = stage_single_upload(policy, content, file_url, &temp).await;
    let (size, sha256) = match staged {
        Ok(value) => value,
        Err(mut error) => {
            if let Err(cleanup) = async_fs::remove_file(&temp).await
                && cleanup.kind() != std::io::ErrorKind::NotFound
            {
                error.details.insert(
                    "cleanup_error".into(),
                    Value::String(format!("failed cleaning staged upload: {cleanup}")),
                );
            }
            return Err(error);
        }
    };
    finalize_single_upload(&temp, &destination, overwrite).await?;

    Ok(BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("mode".into(), Value::String("single".into())),
        (
            "target_path".into(),
            Value::String(destination.display().to_string()),
        ),
        ("size".into(), Value::from(size)),
        ("sha256".into(), Value::String(sha256)),
        (
            "filename".into(),
            payload.get("filename").cloned().unwrap_or(Value::Null),
        ),
    ]))
}

/// # Errors
/// Returns an error when upload metadata is invalid or the staging area cannot be prepared.
pub fn upload_init(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let target = require_str(payload, "target_path")?;
    let overwrite = payload
        .get("overwrite")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let total_size = payload
        .get("total_size")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if total_size > MAX_UPLOAD_BYTES {
        return Err(HandlerError::new(
            "file_too_large",
            format!("declared total_size exceeds upload cap of {MAX_UPLOAD_BYTES} bytes"),
        ));
    }
    let land_in_place = payload
        .get("land_in_place")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let (destination, landed_in_place) = if land_in_place {
        if let Some(resolved) = policy.resolve_path(target, true) {
            (resolved, true)
        } else {
            (safe_dest(&policy.upload_base, target)?, false)
        }
    } else {
        (safe_dest(&policy.upload_base, target)?, false)
    };
    if destination.exists() && !overwrite {
        return Err(HandlerError::new(
            "conflict",
            format!("a file already exists at {}", destination.display()),
        ));
    }
    let upload_id = valid_upload_id(payload.get("upload_id"))?;
    let dir = upload_dir(policy, &upload_id)?;
    let meta = UploadMeta {
        upload_id: upload_id.clone(),
        target_path: destination.display().to_string(),
        landed_in_place,
        overwrite,
        total_size,
        filename: payload
            .get("filename")
            .and_then(Value::as_str)
            .map(str::to_owned),
    };
    fs::write(
        meta_path(&dir),
        serde_json::to_vec(&meta)
            .map_err(|e| HandlerError::new("internal_error", e.to_string()))?,
    )
    .map_err(|e| HandlerError::new("io_error", format!("failed writing upload metadata: {e}")))?;

    Ok(BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("mode".into(), Value::String("chunked".into())),
        ("upload_id".into(), Value::String(upload_id)),
        (
            "target_path".into(),
            Value::String(destination.display().to_string()),
        ),
        ("total_size".into(), Value::from(total_size)),
    ]))
}

/// # Errors
/// Returns an error when the transfer identifier or chunk is invalid, or the part cannot be written.
pub fn write_transfer_part_at(
    upload_base: &Path,
    upload_id: &str,
    index: u32,
    data: &[u8],
) -> Result<usize, HandlerError> {
    let id = valid_upload_id(Some(&Value::String(upload_id.into())))?;
    let root = staging::staging_root(upload_base)
        .map_err(|e| HandlerError::new("io_error", e.to_string()))?;
    let dir = root.join(&id);
    if !meta_path(&dir).exists() {
        return Err(HandlerError::new(
            "not_found",
            format!("upload_id not found: {id}"),
        ));
    }
    let parts = dir.join("parts");
    fs::create_dir_all(&parts)
        .map_err(|e| HandlerError::new("io_error", format!("failed creating parts dir: {e}")))?;
    let part = parts.join(format!("{index:08}.part"));
    fs::write(&part, data)
        .map_err(|e| HandlerError::new("io_error", format!("failed writing transfer part: {e}")))?;
    Ok(data.len())
}

/// # Errors
/// Returns an error when the transfer is invalid, disallowed, or the part cannot be written.
pub fn write_transfer_part(
    policy: &Policy,
    upload_id: &str,
    index: u32,
    data: &[u8],
) -> Result<usize, HandlerError> {
    write_transfer_part_at(&policy.upload_base, upload_id, index, data)
}

/// # Errors
/// Returns an error when the upload chunk payload is invalid or cannot be written.
pub fn upload_chunk(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let id = require_str(payload, "upload_id")?;
    let index = payload
        .get("index")
        .and_then(Value::as_i64)
        .ok_or_else(|| HandlerError::new("invalid_payload", "index must be int"))?;
    if index < 0 {
        return Err(HandlerError::new("invalid_payload", "index must be >= 0"));
    }
    let index = u32::try_from(index).map_err(|_| {
        HandlerError::new(
            "invalid_payload",
            "index exceeds the chunked upload protocol limit",
        )
    })?;
    let encoded = require_str(payload, "content_base64")?;
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|e| HandlerError::new("invalid_payload", format!("bad base64: {e}")))?;
    write_transfer_part(policy, id, index, &bytes)?;

    Ok(BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("upload_id".into(), Value::String(id.into())),
        ("index".into(), Value::from(index)),
        ("chunk_size".into(), Value::from(bytes.len() as u64)),
    ]))
}

fn assemble_upload_parts(
    parts: Vec<PathBuf>,
    assembled: &Path,
) -> Result<(u64, String), HandlerError> {
    let mut output = fs::File::create(assembled).map_err(|e| {
        HandlerError::new("io_error", format!("cannot create assembled upload: {e}"))
    })?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; 1024 * 1024];
    for part in parts {
        let mut input = fs::File::open(&part)
            .map_err(|e| HandlerError::new("io_error", format!("cannot read part: {e}")))?;
        loop {
            let n = input
                .read(&mut buffer)
                .map_err(|e| HandlerError::new("io_error", format!("cannot read part: {e}")))?;
            if n == 0 {
                break;
            }
            total = total.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
            if total > MAX_UPLOAD_BYTES {
                return Err(HandlerError::new(
                    "file_too_large",
                    "reassembled upload exceeds cap",
                ));
            }
            hasher.update(&buffer[..n]);
            output.write_all(&buffer[..n]).map_err(|e| {
                HandlerError::new("io_error", format!("cannot assemble upload: {e}"))
            })?;
        }
    }
    Ok((total, hex_bytes(hasher.finalize())))
}

fn finalize_chunked_upload(
    assembled: &Path,
    destination: &Path,
    overwrite: bool,
) -> Result<(), HandlerError> {
    if destination.exists() && !overwrite {
        return Err(HandlerError::new(
            "conflict",
            format!("a file already exists at {}", destination.display()),
        ));
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            HandlerError::new("io_error", format!("cannot create destination parent: {e}"))
        })?;
    }
    let finalize = if overwrite {
        fs::rename(assembled, destination)
    } else {
        rename_no_replace(assembled, destination)
    };
    finalize.map_err(|error| {
        HandlerError::new(
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                "conflict"
            } else {
                "io_error"
            },
            format!("failed finalizing upload: {error}"),
        )
    })
}

/// # Errors
/// Returns an error when the staged upload cannot be validated or finalized safely.
pub fn upload_complete(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let id = require_str(payload, "upload_id")?;
    let id = valid_upload_id(Some(&Value::String(id.into())))?;
    let dir = upload_dir(policy, &id)?;
    let meta_bytes = fs::read(meta_path(&dir))
        .map_err(|_| HandlerError::new("not_found", format!("upload_id not found: {id}")))?;
    let meta: UploadMeta = serde_json::from_slice(&meta_bytes)
        .map_err(|e| HandlerError::new("invalid_state", format!("bad upload metadata: {e}")))?;

    let mut parts = fs::read_dir(dir.join("parts"))
        .map_err(|e| HandlerError::new("invalid_state", format!("cannot read upload parts: {e}")))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("part"))
        .collect::<Vec<_>>();
    parts.sort();
    if parts.is_empty() {
        return Err(HandlerError::new("invalid_state", "no chunks uploaded"));
    }

    let assembled = dir.join("assembled.bin");
    let (total, sha256) = assemble_upload_parts(parts, &assembled)?;

    if meta.total_size != 0 && meta.total_size != total {
        return Err(HandlerError::new(
            "size_mismatch",
            format!("expected {}, got {total}", meta.total_size),
        ));
    }
    if let Some(expected) = payload.get("sha256").and_then(Value::as_str) {
        let expected = expected.trim().to_ascii_lowercase();
        if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(HandlerError::new(
                "invalid_sha256",
                "expected a 64-character hexadecimal SHA-256 digest",
            ));
        }
        if expected != sha256 {
            return Err(HandlerError::new(
                "checksum_mismatch",
                format!("sha256 mismatch: assembled={sha256}, expected={expected}"),
            ));
        }
    }

    let destination = PathBuf::from(&meta.target_path);
    finalize_chunked_upload(&assembled, &destination, meta.overwrite)?;
    let cleanup_warning = match fs::remove_dir_all(&dir) {
        Ok(()) => None,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            let message = format!(
                "upload committed but session cleanup failed for {}: {error}",
                dir.display()
            );
            tracing::warn!(%message);
            Some(message)
        }
    };

    let mut result = BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("mode".into(), Value::String("chunked".into())),
        ("upload_id".into(), Value::String(id)),
        (
            "target_path".into(),
            Value::String(destination.display().to_string()),
        ),
        ("size".into(), Value::from(total)),
        ("sha256".into(), Value::String(sha256)),
        (
            "filename".into(),
            meta.filename.map_or(Value::Null, Value::String),
        ),
    ]);
    if let Some(warning) = cleanup_warning {
        result.insert("cleanup_warning".into(), Value::String(warning));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn policy(root: &Path) -> Policy {
        Policy {
            upload_base: root.to_owned(),
            ..Policy::default()
        }
    }

    #[test]
    fn legacy_json_chunk_index_must_fit_binary_protocol_width() {
        let dir = tempdir().unwrap();
        let policy = policy(dir.path());
        let init = upload_init(
            &policy,
            &Map::from_iter([
                ("target_path".into(), Value::String("x.bin".into())),
                ("total_size".into(), Value::from(1)),
            ]),
        )
        .unwrap();
        let id = init["upload_id"].as_str().unwrap();
        let error = upload_chunk(
            &policy,
            &Map::from_iter([
                ("upload_id".into(), Value::String(id.into())),
                ("index".into(), Value::from(u64::from(u32::MAX) + 1)),
                (
                    "content_base64".into(),
                    Value::String(STANDARD.encode(b"x")),
                ),
            ]),
        )
        .unwrap_err();
        assert_eq!(error.code, "invalid_payload");
    }

    #[test]
    fn chunked_upload_reassembles_and_verifies_case_insensitive_hash() {
        let dir = tempdir().unwrap();
        let policy = policy(dir.path());
        let init = upload_init(
            &policy,
            &Map::from_iter([
                ("target_path".into(), Value::String("nested/x.bin".into())),
                ("total_size".into(), Value::from(6)),
            ]),
        )
        .unwrap();
        let id = init["upload_id"].as_str().unwrap();
        for (index, bytes) in [(0, b"abc".as_slice()), (1, b"def".as_slice())] {
            upload_chunk(
                &policy,
                &Map::from_iter([
                    ("upload_id".into(), Value::String(id.into())),
                    ("index".into(), Value::from(index)),
                    (
                        "content_base64".into(),
                        Value::String(STANDARD.encode(bytes)),
                    ),
                ]),
            )
            .unwrap();
        }
        let expected = hash_bytes(b"abcdef").to_ascii_uppercase();
        let done = upload_complete(
            &policy,
            &Map::from_iter([
                ("upload_id".into(), Value::String(id.into())),
                ("sha256".into(), Value::String(expected)),
            ]),
        )
        .unwrap();
        assert_eq!(done["size"], 6);
        assert_eq!(
            fs::read(dir.path().join("nested/x.bin")).unwrap(),
            b"abcdef"
        );
    }

    fn landing_policy(
        upload_base: &Path,
        entries: Vec<(PathBuf, crate::policy::FileAccess)>,
    ) -> Policy {
        Policy {
            upload_base: upload_base.to_owned(),
            file_ops_paths: entries
                .into_iter()
                .map(|(path, access)| crate::policy::FileOpsPath { path, access })
                .collect(),
            ..Policy::default()
        }
    }

    fn upload_meta(policy: &Policy, init: &BTreeMap<String, Value>) -> UploadMeta {
        let id = init["upload_id"].as_str().unwrap();
        let bytes = fs::read(meta_path(&upload_dir(policy, id).unwrap())).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn land_in_place_under_rw_path() {
        let uploads = tempdir().unwrap();
        let workspace = tempdir().unwrap();
        let target = workspace.path().join("canary.txt");
        let policy = landing_policy(
            uploads.path(),
            vec![(
                workspace.path().to_owned(),
                crate::policy::FileAccess::ReadWrite,
            )],
        );
        let init = upload_init(
            &policy,
            &Map::from_iter([
                (
                    "target_path".into(),
                    Value::String(target.display().to_string()),
                ),
                ("total_size".into(), Value::from(10)),
                ("land_in_place".into(), Value::Bool(true)),
            ]),
        )
        .unwrap();
        let meta = upload_meta(&policy, &init);
        assert!(meta.landed_in_place);
        assert_eq!(PathBuf::from(meta.target_path), target);
    }

    #[test]
    fn land_in_place_outside_rw_falls_back_to_staging() {
        let uploads = tempdir().unwrap();
        let workspace = tempdir().unwrap();
        let elsewhere = tempdir().unwrap();
        let target = elsewhere.path().join("x.txt");
        let policy = landing_policy(
            uploads.path(),
            vec![(
                workspace.path().to_owned(),
                crate::policy::FileAccess::ReadWrite,
            )],
        );
        let init = upload_init(
            &policy,
            &Map::from_iter([
                (
                    "target_path".into(),
                    Value::String(target.display().to_string()),
                ),
                ("land_in_place".into(), Value::Bool(true)),
            ]),
        )
        .unwrap();
        let meta = upload_meta(&policy, &init);
        assert!(!meta.landed_in_place);
        assert!(PathBuf::from(meta.target_path).starts_with(uploads.path()));
    }

    #[test]
    fn land_in_place_is_opt_in_even_under_rw_path() {
        let uploads = tempdir().unwrap();
        let workspace = tempdir().unwrap();
        let target = workspace.path().join("default-staged.txt");
        let policy = landing_policy(
            uploads.path(),
            vec![(
                workspace.path().to_owned(),
                crate::policy::FileAccess::ReadWrite,
            )],
        );
        let init = upload_init(
            &policy,
            &Map::from_iter([(
                "target_path".into(),
                Value::String(target.display().to_string()),
            )]),
        )
        .unwrap();
        let meta = upload_meta(&policy, &init);
        assert!(!meta.landed_in_place);
        assert!(PathBuf::from(meta.target_path).starts_with(uploads.path()));
    }

    #[test]
    fn read_only_path_does_not_land_in_place() {
        let uploads = tempdir().unwrap();
        let readonly = tempdir().unwrap();
        let target = readonly.path().join("z.txt");
        let policy = landing_policy(
            uploads.path(),
            vec![(readonly.path().to_owned(), crate::policy::FileAccess::Read)],
        );
        let init = upload_init(
            &policy,
            &Map::from_iter([
                (
                    "target_path".into(),
                    Value::String(target.display().to_string()),
                ),
                ("land_in_place".into(), Value::Bool(true)),
            ]),
        )
        .unwrap();
        let meta = upload_meta(&policy, &init);
        assert!(!meta.landed_in_place);
        assert!(PathBuf::from(meta.target_path).starts_with(uploads.path()));
    }

    #[test]
    fn land_in_place_traversal_outside_rw_is_still_refused() {
        let uploads = tempdir().unwrap();
        let workspace = tempdir().unwrap();
        let policy = landing_policy(
            uploads.path(),
            vec![(
                workspace.path().to_owned(),
                crate::policy::FileAccess::ReadWrite,
            )],
        );
        let error = upload_init(
            &policy,
            &Map::from_iter([
                (
                    "target_path".into(),
                    Value::String("../../etc/passwd".into()),
                ),
                ("land_in_place".into(), Value::Bool(true)),
            ]),
        )
        .unwrap_err();
        assert_eq!(error.code, "path_traversal");
    }

    #[test]
    fn absolute_staging_target_is_rooted_under_upload_base() {
        let uploads = tempdir().unwrap();
        let policy = policy(uploads.path());
        let init = upload_init(
            &policy,
            &Map::from_iter([(
                "target_path".into(),
                Value::String("/srv/elsewhere/x.txt".into()),
            )]),
        )
        .unwrap();
        let meta = upload_meta(&policy, &init);
        assert!(!meta.landed_in_place);
        assert_eq!(
            PathBuf::from(meta.target_path),
            uploads.path().join("srv/elsewhere/x.txt")
        );
    }

    #[test]
    fn upload_target_cannot_escape_upload_base() {
        let dir = tempdir().unwrap();
        let error = upload_init(
            &policy(dir.path()),
            &Map::from_iter([("target_path".into(), Value::String("../escape".into()))]),
        )
        .unwrap_err();
        assert_eq!(error.code, "path_traversal");
    }

    #[tokio::test]
    async fn single_upload_finalize_failure_cleans_staged_file() {
        let dir = tempdir().unwrap();
        let policy = policy(dir.path());
        fs::create_dir(dir.path().join("target-dir")).unwrap();

        let error = upload_file(
            &policy,
            &Map::from_iter([
                ("target_path".into(), Value::String("target-dir".into())),
                ("overwrite".into(), Value::Bool(true)),
                (
                    "content_base64".into(),
                    Value::String(STANDARD.encode(b"payload")),
                ),
            ]),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "io_error");

        let staging = dir.path().join(crate::staging::STAGING_DIRNAME);
        let leaked = fs::read_dir(staging)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".upload"))
            .collect::<Vec<_>>();
        assert!(leaked.is_empty(), "failed upload leaked staged file");
    }
}
