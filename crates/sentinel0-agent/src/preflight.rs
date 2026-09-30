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
    verify_enrollment_with_timeouts(
        hub_ws_base,
        token,
        Duration::from_secs(15),
        Duration::from_secs(6),
    )
    .await
}

async fn verify_enrollment_with_timeouts(
    hub_ws_base: &str,
    token: &AuthToken,
    connect_timeout: Duration,
    accept_window: Duration,
) -> PreflightResult {
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
        connect_timeout,
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

    match timeout(accept_window, websocket.next()).await {
        Err(_) => PreflightResult::accepted(),
        Ok(None) => PreflightResult::failed("closed", "hub closed before hello"),
        Ok(Some(Err(error))) => PreflightResult::failed("closed", error.to_string()),
        Ok(Some(Ok(WsMessage::Text(text)))) => serde_json::from_str::<serde_json::Value>(&text)
            .map_or_else(
                |_| PreflightResult::failed("rejected", "hub sent data before hello"),
                |value| {
                    PreflightResult::failed(
                        value
                            .get("code")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("rejected"),
                        value
                            .get("message")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or(""),
                    )
                },
            ),
        Ok(Some(Ok(WsMessage::Close(frame)))) => {
            let Some(frame) = frame else {
                return PreflightResult::failed("closed", "");
            };
            let detail = format!("{}: {}", u16::from(frame.code), frame.reason);
            if frame.code == tungstenite::protocol::frame::coding::CloseCode::Policy {
                PreflightResult::failed("enrollment_rejected", detail)
            } else {
                PreflightResult::failed("closed", detail)
            }
        }
        Ok(Some(Ok(_))) => PreflightResult::failed("rejected", "hub sent data before hello"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TestResult, TestValue as _};
    use futures_util::SinkExt;
    use std::io;
    use tokio::net::TcpListener;
    use tokio_tungstenite::{
        accept_async, accept_hdr_async,
        tungstenite::{
            handshake::server::{Callback, ErrorResponse, Request, Response},
            protocol::{CloseFrame, frame::coding::CloseCode},
        },
    };

    struct AssertHeaders<F>(F);

    impl<F> Callback for AssertHeaders<F>
    where
        F: FnOnce(&Request),
    {
        fn on_request(
            self,
            request: &Request,
            response: Response,
        ) -> Result<Response, ErrorResponse> {
            (self.0)(request);
            Ok(response)
        }
    }

    #[tokio::test]
    async fn silence_means_accepted_and_request_has_auth() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0").await.test_value()?;
        let addr = listener.local_addr().test_value()?;
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.map_err(io::Error::other)?;
            let _websocket = accept_hdr_async(
                stream,
                AssertHeaders(|request: &Request| {
                    assert_eq!(request.uri().path(), "/agent/connect");
                    assert_eq!(
                        request
                            .headers()
                            .get(AUTHORIZATION)
                            .and_then(|value| value.to_str().ok()),
                        Some("Bearer preflight-token")
                    );
                }),
            )
            .await
            .map_err(io::Error::other)?;
            tokio::time::sleep(Duration::from_millis(80)).await;
            Ok::<(), io::Error>(())
        });

        let result = verify_enrollment_with_timeouts(
            &format!("ws://{addr}"),
            &AuthToken::new("preflight-token"),
            Duration::from_secs(1),
            Duration::from_millis(20),
        )
        .await;
        assert_eq!(result, PreflightResult::accepted());
        server.await.test_value()?.test_value()?;
        Ok(())
    }

    #[tokio::test]
    async fn error_frame_reports_hub_reason() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0").await.test_value()?;
        let addr = listener.local_addr().test_value()?;
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.map_err(io::Error::other)?;
            let mut websocket = accept_async(stream).await.map_err(io::Error::other)?;
            websocket
                .send(WsMessage::Text(
                    serde_json::json!({
                        "type": "error",
                        "code": "enrollment_rejected",
                        "message": "enrollment rejected: bad_signature",
                    })
                    .to_string()
                    .into(),
                ))
                .await
                .map_err(io::Error::other)?;
            Ok::<(), io::Error>(())
        });

        let result = verify_enrollment_with_timeouts(
            &format!("ws://{addr}"),
            &AuthToken::new("token"),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await;
        assert!(!result.ok);
        assert_eq!(result.reason, "enrollment_rejected");
        assert!(result.detail.contains("bad_signature"));
        server.await.test_value()?.test_value()?;
        Ok(())
    }

    #[tokio::test]
    async fn policy_close_is_enrollment_rejection() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0").await.test_value()?;
        let addr = listener.local_addr().test_value()?;
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.map_err(io::Error::other)?;
            let mut websocket = accept_async(stream).await.map_err(io::Error::other)?;
            websocket
                .close(Some(CloseFrame {
                    code: CloseCode::Policy,
                    reason: "invalid token".into(),
                }))
                .await
                .map_err(io::Error::other)?;
            Ok::<(), io::Error>(())
        });

        let result = verify_enrollment_with_timeouts(
            &format!("ws://{addr}"),
            &AuthToken::new("token"),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await;
        assert!(!result.ok);
        assert_eq!(result.reason, "enrollment_rejected");
        assert!(result.detail.contains("1008"));
        assert!(result.detail.contains("invalid token"));
        server.await.test_value()?.test_value()?;
        Ok(())
    }

    #[tokio::test]
    async fn invalid_token_header_is_reported_without_connecting() {
        let result = verify_enrollment_with_timeouts(
            "ws://127.0.0.1:9",
            &AuthToken::new("bad\ntoken"),
            Duration::from_millis(10),
            Duration::from_millis(10),
        )
        .await;
        assert!(!result.ok);
        assert_eq!(result.reason, "invalid_token_header");
    }
}
