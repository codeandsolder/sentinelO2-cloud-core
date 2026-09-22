#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

//! SentinelX v1 wire compatibility types.
//!
//! This models the wire contract, not the Python implementation. The legacy
//! protocol stays isolated so Sentinel0² can evolve independently.

pub mod bounding;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const PROTOCOL_VERSION: &str = "1.13.0";
pub const PROTOCOL_MAJOR: u32 = 1;
pub const MAX_FRAME_BYTES: usize = 1_048_576;
pub const RECOMMENDED_CHUNK_BYTES: usize = 262_144;
pub const HEARTBEAT_INTERVAL_SECS: u64 = 30;
pub const HEARTBEAT_TIMEOUT_SECS: u64 = 90;
pub const TRANSFER_CHUNK_BYTES: usize = 1_048_576;
pub const MAX_BINARY_FRAME_BYTES: usize = 2_097_152;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct ConfigSummary {
    pub allowed_command_count: Option<u64>,
    pub file_ops_path_count: Option<u64>,
    pub file_ops_rw_count: Option<u64>,
    pub service_count: Option<u64>,
    pub playbook_count: Option<u64>,
    pub trusted_fetch_host_count: Option<u64>,
    pub exec_timeout_default: Option<u64>,
    pub exec_timeout_max: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostInfo {
    pub id: String,
    pub hostname: String,
    #[serde(default = "default_os")]
    pub os: String,
    pub kernel: Option<String>,
    pub arch: Option<String>,
    pub cpu_model: Option<String>,
    pub cpu_cores: Option<u64>,
    pub mem_total_bytes: Option<u64>,
    pub disk_total_bytes: Option<u64>,
    pub machine_type: Option<String>,
    pub distro: Option<String>,
    pub config_summary: Option<ConfigSummary>,
}

fn default_os() -> String {
    "linux".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PreferredProfile {
    Compact,
    Full,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Ping,
    Capabilities,
    Help,
    State,
    Exec,
    ScriptRun,
    Edit,
    EditUploadInit,
    EditUploadFile,
    EditUploadComplete,
    Restart,
    Service,
    UploadInit,
    UploadChunk,
    UploadComplete,
    UploadFile,
    Read,
    List,
    Search,
    ProjectSnapshot,
    ReadAudit,
    Move,
    Copy,
    Delete,
    Chmod,
    Chown,
    Git,
    FileExportInit,
    FileExportChunk,
    FileExportComplete,
    LocalApi,
}

impl Op {
    pub const ALL: [Self; 31] = [
        Self::Ping,
        Self::Capabilities,
        Self::Help,
        Self::State,
        Self::Exec,
        Self::ScriptRun,
        Self::Edit,
        Self::EditUploadInit,
        Self::EditUploadFile,
        Self::EditUploadComplete,
        Self::Restart,
        Self::Service,
        Self::UploadInit,
        Self::UploadChunk,
        Self::UploadComplete,
        Self::UploadFile,
        Self::Read,
        Self::List,
        Self::Search,
        Self::ProjectSnapshot,
        Self::ReadAudit,
        Self::Move,
        Self::Copy,
        Self::Delete,
        Self::Chmod,
        Self::Chown,
        Self::Git,
        Self::FileExportInit,
        Self::FileExportChunk,
        Self::FileExportComplete,
        Self::LocalApi,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::Capabilities => "capabilities",
            Self::Help => "help",
            Self::State => "state",
            Self::Exec => "exec",
            Self::ScriptRun => "script_run",
            Self::Edit => "edit",
            Self::EditUploadInit => "edit_upload_init",
            Self::EditUploadFile => "edit_upload_file",
            Self::EditUploadComplete => "edit_upload_complete",
            Self::Restart => "restart",
            Self::Service => "service",
            Self::UploadInit => "upload_init",
            Self::UploadChunk => "upload_chunk",
            Self::UploadComplete => "upload_complete",
            Self::UploadFile => "upload_file",
            Self::Read => "read",
            Self::List => "list",
            Self::Search => "search",
            Self::ProjectSnapshot => "project_snapshot",
            Self::ReadAudit => "read_audit",
            Self::Move => "move",
            Self::Copy => "copy",
            Self::Delete => "delete",
            Self::Chmod => "chmod",
            Self::Chown => "chown",
            Self::Git => "git",
            Self::FileExportInit => "file_export_init",
            Self::FileExportChunk => "file_export_chunk",
            Self::FileExportComplete => "file_export_complete",
            Self::LocalApi => "local_api",
        }
    }
}

impl std::fmt::Display for Op {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum Message {
    Hello {
        protocol_version: String,
        agent_version: String,
        agent_name: Option<String>,
        host: Box<HostInfo>,
        #[serde(default)]
        capabilities: Vec<String>,
        preferred_profile: Option<PreferredProfile>,
    },
    Welcome {
        session_id: String,
        server_time: DateTime<Utc>,
        #[serde(default = "default_heartbeat")]
        heartbeat_interval_seconds: u64,
    },
    Request {
        id: String,
        op: Op,
        #[serde(default)]
        payload: BTreeMap<String, Value>,
        deadline: Option<DateTime<Utc>>,
        #[serde(default, deserialize_with = "deserialize_opaque_ref")]
        opaque_ref: Option<String>,
    },
    Response {
        id: String,
        ok: bool,
        result: Option<BTreeMap<String, Value>>,
        error: Option<ResponseError>,
    },
    Ping {
        timestamp: DateTime<Utc>,
    },
    Pong {
        timestamp: DateTime<Utc>,
    },
    Event {
        kind: String,
        #[serde(default)]
        data: BTreeMap<String, Value>,
        timestamp: DateTime<Utc>,
    },
    Error {
        code: String,
        message: String,
        #[serde(default = "yes")]
        fatal: bool,
    },
}

fn default_heartbeat() -> u64 {
    HEARTBEAT_INTERVAL_SECS
}
fn yes() -> bool {
    true
}

fn deserialize_opaque_ref<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;

    let value = Option::<String>::deserialize(deserializer)?;
    if let Some(ref value) = value {
        if value.chars().count() > 256 {
            return Err(D::Error::custom("opaque_ref exceeds 256 characters"));
        }
    }
    Ok(value)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ResponseError {
    pub code: String,
    pub message: String,
    pub details: Option<BTreeMap<String, Value>>,
}

impl Message {
    pub fn hello(
        host: HostInfo,
        agent_version: impl Into<String>,
        capabilities: Vec<String>,
    ) -> Self {
        Self::hello_with_profile(host, agent_version, capabilities, None)
    }

    pub fn hello_with_profile(
        host: HostInfo,
        agent_version: impl Into<String>,
        capabilities: Vec<String>,
        preferred_profile: Option<PreferredProfile>,
    ) -> Self {
        Self::Hello {
            protocol_version: PROTOCOL_VERSION.into(),
            agent_version: agent_version.into(),
            agent_name: Some("sentinelx-core".into()),
            host: Box::new(host),
            capabilities,
            preferred_profile,
        }
    }
}

pub const TRANSFER_ID_BYTES: usize = 16;
pub const BINARY_HEADER_BYTES: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryFrame<'a> {
    pub transfer_id: [u8; TRANSFER_ID_BYTES],
    pub chunk_index: u32,
    pub payload: &'a [u8],
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BinaryFrameError {
    #[error("binary transfer frame shorter than {BINARY_HEADER_BYTES} bytes")]
    TooShort,
}

pub fn is_binary_transfer_frame(frame: &[u8]) -> bool {
    frame.len() >= BINARY_HEADER_BYTES
}

pub fn decode_binary_frame(frame: &[u8]) -> Result<BinaryFrame<'_>, BinaryFrameError> {
    if frame.len() < BINARY_HEADER_BYTES {
        return Err(BinaryFrameError::TooShort);
    }
    let mut transfer_id = [0_u8; TRANSFER_ID_BYTES];
    transfer_id.copy_from_slice(&frame[..TRANSFER_ID_BYTES]);
    let chunk_bytes: [u8; 4] = frame
        .get(16..20)
        .ok_or(BinaryFrameError::TooShort)?
        .try_into()
        .map_err(|_| BinaryFrameError::TooShort)?;
    let chunk_index = u32::from_be_bytes(chunk_bytes);
    Ok(BinaryFrame {
        transfer_id,
        chunk_index,
        payload: &frame[BINARY_HEADER_BYTES..],
    })
}

pub fn encode_binary_frame(
    transfer_id: [u8; TRANSFER_ID_BYTES],
    chunk_index: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(BINARY_HEADER_BYTES + payload.len());
    out.extend_from_slice(&transfer_id);
    out.extend_from_slice(&chunk_index.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_frame_roundtrip_matches_spec() {
        let id = [0x5a; 16];
        let wire = encode_binary_frame(id, 0x0102_0304, b"payload");
        assert_eq!(&wire[16..20], &[1, 2, 3, 4]);
        let decoded = decode_binary_frame(&wire).unwrap();
        assert_eq!(decoded.transfer_id, id);
        assert_eq!(decoded.chunk_index, 0x0102_0304);
        assert_eq!(decoded.payload, b"payload");
    }

    #[test]
    fn wire_messages_reject_unknown_fields_like_pydantic_extra_forbid() {
        let bad = serde_json::json!({
            "type": "ping",
            "timestamp": "2026-09-21T21:00:00Z",
            "surprise": true
        });
        assert!(serde_json::from_value::<Message>(bad).is_err());
    }
}
