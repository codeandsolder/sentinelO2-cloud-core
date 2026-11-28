//! Agent-specific hub WebSocket handshake.
use http::{HeaderValue, StatusCode, Uri, header::AUTHORIZATION};
use wreq::{Client, ws::WebSocket};

#[derive(Debug, thiserror::Error)]
pub enum HubConnectError {
    #[error("invalid hub WebSocket URL: {0}")]
    InvalidUrl(String),
    #[error("hub rejected WebSocket handshake: HTTP {0}")]
    Status(StatusCode),
    #[error(transparent)]
    Transport(#[from] wreq::Error),
}

pub async fn connect_hub(
    client: &Client,
    base: &str,
    authorization: HeaderValue,
) -> Result<WebSocket, HubConnectError> {
    let url = format!("{}/agent/connect", base.trim_end_matches('/'));
    let uri = url
        .parse::<Uri>()
        .map_err(|e| HubConnectError::InvalidUrl(e.to_string()))?;
    if !matches!(uri.scheme_str(), Some("ws" | "wss")) || uri.host().is_none() {
        return Err(HubConnectError::InvalidUrl(
            "expected ws:// or wss:// with a host".into(),
        ));
    }
    let response = client
        .websocket(uri)
        .header(AUTHORIZATION, authorization)
        .max_message_size(sentinel0_proto::MAX_BINARY_FRAME_BYTES)
        .send()
        .await?;
    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Err(HubConnectError::Status(response.status()));
    }
    Ok(response.into_websocket().await?)
}
