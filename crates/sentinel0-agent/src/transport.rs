//! HTTP and WebSocket transport shared by the agent, enrollment and file APIs.
use bytes::Bytes;
use futures_util::{Stream, StreamExt as _};
use http::{HeaderValue, StatusCode, Uri, header::AUTHORIZATION};
use std::{pin::pin, time::Duration};
use wreq::{Client, ClientBuilder, Response, ws::WebSocket};

pub(crate) fn client_builder() -> ClientBuilder {
    // All outbound destinations are selected explicitly by the operation. Ambient
    // proxies and redirects would bypass that selection (and upload DNS pinning).
    Client::builder()
        .no_proxy()
        .redirect(wreq::redirect::Policy::none())
        .retry(wreq::retry::Policy::never())
        .tcp_happy_eyeballs_timeout(Duration::from_millis(250))
}

#[derive(Debug, thiserror::Error)]
pub enum HubConnectError {
    #[error("invalid hub WebSocket URL: {0}")]
    InvalidUrl(String),
    #[error("hub rejected WebSocket handshake: HTTP {0}")]
    Status(StatusCode),
    #[error(transparent)]
    Transport(#[from] wreq::Error),
}

pub(crate) async fn connect_hub(
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

#[derive(Debug, thiserror::Error)]
pub(crate) enum BodyError {
    #[error("response exceeded the byte limit")]
    TooLarge,
    #[error(transparent)]
    Transport(#[from] wreq::Error),
}

/// Check advertised length before reading, then enforce the limit on actual bytes,
/// including chunked responses. Callers stop consuming at the first error.
pub(crate) fn bounded_body(
    response: Response,
    limit: u64,
) -> Result<impl Stream<Item = Result<Bytes, BodyError>>, BodyError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit)
    {
        return Err(BodyError::TooLarge);
    }
    let mut remaining = limit;
    Ok(response.bytes_stream().map(move |chunk| {
        let chunk = chunk?;
        let len = u64::try_from(chunk.len()).map_err(|_| BodyError::TooLarge)?;
        remaining = remaining.checked_sub(len).ok_or(BodyError::TooLarge)?;
        Ok(chunk)
    }))
}

pub(crate) async fn read_bounded(response: Response, limit: u64) -> Result<Vec<u8>, BodyError> {
    let mut stream = pin!(bounded_body(response, limit)?);
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        body.extend_from_slice(&chunk?);
    }
    Ok(body)
}
