use crate::AuthToken;
use futures_util::StreamExt;
use http::header::AUTHORIZATION;
use std::time::Duration;
use tokio::time::timeout;
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{self, Message as WsMessage, client::IntoClientRequest},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightResult {
    pub ok: bool,
    pub reason: String,
    pub detail: String,
}

impl PreflightResult {
    fn accepted() -> Self {
        Self {
            ok: true,
            reason: "accepted".into(),
            detail: String::new(),
        }
    }

    fn failed(reason: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            ok: false,
            reason: reason.into(),
            detail: detail.into(),
        }
    }
}

pub async fn verify_enrollment(hub_ws_base: &str, token: &AuthToken) -> PreflightResult {
    let url = format!("{}/agent/connect", hub_ws_base.trim_end_matches('/'));
    let mut request = match url.into_client_request() {
        Ok(request) => request,
        Err(error) => return PreflightResult::failed("invalid_hub_url", error.to_string()),
    };
    let header = match token.bearer_header() {
        Ok(header) => header,
        Err(error) => return PreflightResult::failed("invalid_token_header", error.to_string()),
    };
    request.headers_mut().insert(AUTHORIZATION, header);

    let connected = timeout(
        Duration::from_secs(15),
        connect_async_with_config(request, None, false),
    )
    .await;
    let (mut websocket, _) = match connected {
        Err(_) => return PreflightResult::failed("unreachable", "connection timed out"),
        Ok(Err(tungstenite::Error::Io(error))) => {
            return PreflightResult::failed("unreachable", error.to_string());
        }
        Ok(Err(tungstenite::Error::Http(response))) => {
            return PreflightResult::failed(
                "rejected_by_hub",
                format!("HTTP {}", response.status()),
            );
        }
        Ok(Err(error)) => return PreflightResult::failed("error", error.to_string()),
        Ok(Ok(value)) => value,
    };

    match timeout(Duration::from_secs(6), websocket.next()).await {
        Err(_) => PreflightResult::accepted(),
        Ok(None) => PreflightResult::failed("closed", "hub closed before hello"),
        Ok(Some(Err(error))) => PreflightResult::failed("closed", error.to_string()),
        Ok(Some(Ok(WsMessage::Text(text)))) => {
            match serde_json::from_str::<serde_json::Value>(&text) {
                Ok(value) => PreflightResult::failed(
                    value
                        .get("code")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("rejected"),
                    value
                        .get("message")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or(""),
                ),
                Err(_) => PreflightResult::failed("rejected", "hub sent data before hello"),
            }
        }
        Ok(Some(Ok(WsMessage::Close(frame)))) => {
            let detail = frame
                .map(|frame| format!("{}: {}", u16::from(frame.code), frame.reason))
                .unwrap_or_default();
            PreflightResult::failed("closed", detail)
        }
        Ok(Some(Ok(_))) => PreflightResult::failed("rejected", "hub sent data before hello"),
    }
}
