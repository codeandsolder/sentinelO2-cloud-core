mod common;

use common::{TestResult, TestValue as _};
use futures_util::{SinkExt, StreamExt};
use sentinel0_agent::{Agent, AgentConfig, AuthToken, ReconnectPolicy, UnsupportedDispatcher};
use sentinel0_proto::{HostInfo, Message, PROTOCOL_VERSION};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::net::TcpListener;
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::{
        Message as WsMessage,
        handshake::server::{Callback, ErrorResponse, Request, Response},
        protocol::{CloseFrame, frame::coding::CloseCode},
    },
};
use tokio_util::sync::CancellationToken;

struct AssertHeaders<F>(F);

impl<F> Callback for AssertHeaders<F>
where
    F: FnOnce(&Request),
{
    fn on_request(self, request: &Request, response: Response) -> Result<Response, ErrorResponse> {
        (self.0)(request);
        Ok(response)
    }
}

fn host() -> HostInfo {
    HostInfo {
        id: "host_test".into(),
        hostname: "testbox".into(),
        os: "linux".into(),
        kernel: None,
        arch: Some("x86_64".into()),
        cpu_model: None,
        cpu_cores: None,
        mem_total_bytes: None,
        disk_total_bytes: None,
        machine_type: None,
        distro: None,
        config_summary: None,
    }
}

#[tokio::test]
async fn real_socket_reconnects_after_1012_and_reauthenticates() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await.test_value()?;
    let addr = listener.local_addr().test_value()?;
    let handshakes = Arc::new(AtomicUsize::new(0));
    let seen = handshakes.clone();
    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();

    let server = tokio::spawn(async move {
        for n in 0..2 {
            let (stream, _) = listener.accept().await.test_value()?;
            let mut ws = accept_hdr_async(
                stream,
                AssertHeaders(|req: &Request| {
                    assert_eq!(req.uri().path(), "/agent/connect");
                    assert_eq!(
                        req.headers()
                            .get("authorization")
                            .and_then(|value| value.to_str().ok()),
                        Some("Bearer test-token")
                    );
                    seen.fetch_add(1, Ordering::SeqCst);
                }),
            )
            .await
            .test_value()?;

            let WsMessage::Text(hello) = ws.next().await.test_value()?.test_value()? else {
                return Err(std::io::Error::other("expected hello").into());
            };
            match serde_json::from_str::<Message>(&hello).test_value()? {
                Message::Hello {
                    protocol_version,
                    host,
                    ..
                } => {
                    assert_eq!(protocol_version, PROTOCOL_VERSION);
                    assert_eq!(host.id, "host_test");
                }
                other => {
                    return Err(
                        std::io::Error::other(format!("expected hello, got {other:?}")).into(),
                    );
                }
            }

            let welcome = serde_json::json!({
                "type": "welcome",
                "session_id": format!("sess_{n}"),
                "server_time": "2026-09-21T21:00:00Z",
                "heartbeat_interval_seconds": 30
            });
            ws.send(WsMessage::Text(welcome.to_string().into()))
                .await
                .test_value()?;

            if n == 0 {
                ws.close(Some(CloseFrame {
                    code: CloseCode::Restart,
                    reason: "deploy".into(),
                }))
                .await
                .test_value()?;
            } else {
                server_cancel.cancel();
                let _ = ws.close(None).await;
            }
        }
        Ok::<(), common::TestFailure>(())
    });

    let agent = Agent::new(
        AgentConfig {
            hub_ws_base: format!("ws://{addr}"),
            token: AuthToken::new("test-token"),
            host: host(),
            agent_version: "0.1.0".into(),
            capabilities: vec!["opaque_ref".into()],
            preferred_profile: None,
            upload_base: std::env::temp_dir()
                .join(format!("sentinel0-reconnect-{}", addr.port()))
                .join("uploads"),
            reconnect: ReconnectPolicy {
                steps: vec![Duration::ZERO, Duration::from_millis(5)].into(),
                jitter: false,
            },
            connect_timeout: Duration::from_millis(250),
            welcome_timeout: Duration::from_millis(250),
            heartbeat_interval: Duration::from_secs(30),
            heartbeat_timeout: Duration::from_secs(90),
        },
        UnsupportedDispatcher,
    )
    .test_value()?;

    tokio::time::timeout(Duration::from_secs(2), agent.run(cancel.clone()))
        .await
        .test_value()?
        .test_value()?;
    server.await.test_value()??;
    assert_eq!(handshakes.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn established_session_loss_discards_old_handshake_backoff() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await.test_value()?;
    let addr = listener.local_addr().test_value()?;
    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();

    let server = tokio::spawn(async move {
        for n in 0..5 {
            let (stream, _) = listener.accept().await.test_value()?;
            let mut ws = accept_hdr_async(
                stream,
                AssertHeaders(|req: &Request| {
                    assert_eq!(
                        req.headers()
                            .get("authorization")
                            .and_then(|value| value.to_str().ok()),
                        Some("Bearer test-token")
                    );
                }),
            )
            .await
            .test_value()?;
            let _hello = ws.next().await.test_value()?.test_value()?;

            if n < 3 {
                drop(ws);
                continue;
            }

            let welcome = serde_json::json!({
                "type": "welcome",
                "session_id": format!("sess_{n}"),
                "server_time": "2026-09-21T21:00:00Z",
                "heartbeat_interval_seconds": 30
            });
            ws.send(WsMessage::Text(welcome.to_string().into()))
                .await
                .test_value()?;

            if n == 3 {
                drop(ws);
            } else {
                server_cancel.cancel();
                let _ = ws.close(None).await;
            }
        }
        Ok::<(), common::TestFailure>(())
    });

    let agent = Agent::new(
        AgentConfig {
            hub_ws_base: format!("ws://{addr}"),
            token: AuthToken::new("test-token"),
            host: host(),
            agent_version: "0.1.0".into(),
            capabilities: vec![],
            preferred_profile: None,
            upload_base: std::env::temp_dir()
                .join(format!("sentinel0-reconnect-{}", addr.port()))
                .join("uploads"),
            reconnect: ReconnectPolicy {
                steps: vec![
                    Duration::ZERO,
                    Duration::from_millis(5),
                    Duration::from_millis(10),
                    Duration::from_millis(20),
                    Duration::from_millis(300),
                ]
                .into(),
                jitter: false,
            },
            connect_timeout: Duration::from_millis(100),
            welcome_timeout: Duration::from_millis(100),
            heartbeat_interval: Duration::from_secs(30),
            heartbeat_timeout: Duration::from_secs(90),
        },
        UnsupportedDispatcher,
    )
    .test_value()?;

    tokio::time::timeout(Duration::from_millis(150), agent.run(cancel.clone()))
        .await
        .test_value()?
        .test_value()?;
    server.await.test_value()??;
    Ok(())
}

#[tokio::test]
async fn missing_welcome_times_out_and_next_real_connection_recovers() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await.test_value()?;
    let addr = listener.local_addr().test_value()?;
    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.test_value()?;
        let mut first = accept_hdr_async(stream, AssertHeaders(|_: &Request| {}))
            .await
            .test_value()?;
        let _hello = first.next().await.test_value()?.test_value()?;
        tokio::time::sleep(Duration::from_millis(60)).await;
        drop(first);

        let (stream, _) = listener.accept().await.test_value()?;
        let mut second = accept_hdr_async(stream, AssertHeaders(|_: &Request| {}))
            .await
            .test_value()?;
        let _hello = second.next().await.test_value()?.test_value()?;
        let welcome = serde_json::json!({
            "type": "welcome",
            "session_id": "sess_recovered",
            "server_time": "2026-09-21T21:00:00Z",
            "heartbeat_interval_seconds": 30
        });
        second
            .send(WsMessage::Text(welcome.to_string().into()))
            .await
            .test_value()?;
        server_cancel.cancel();
        let _ = second.close(None).await;
        Ok::<(), common::TestFailure>(())
    });

    let agent = Agent::new(
        AgentConfig {
            hub_ws_base: format!("ws://{addr}"),
            token: AuthToken::new("test-token"),
            host: host(),
            agent_version: "0.1.0".into(),
            capabilities: vec![],
            preferred_profile: None,
            upload_base: std::env::temp_dir()
                .join(format!("sentinel0-reconnect-{}", addr.port()))
                .join("uploads"),
            reconnect: ReconnectPolicy {
                steps: vec![Duration::ZERO, Duration::from_millis(5)].into(),
                jitter: false,
            },
            connect_timeout: Duration::from_millis(30),
            welcome_timeout: Duration::from_millis(30),
            heartbeat_interval: Duration::from_secs(30),
            heartbeat_timeout: Duration::from_secs(90),
        },
        UnsupportedDispatcher,
    )
    .test_value()?;

    tokio::time::timeout(Duration::from_millis(200), agent.run(cancel.clone()))
        .await
        .test_value()?
        .test_value()?;
    server.await.test_value()??;
    Ok(())
}

#[tokio::test]
async fn silent_established_peer_trips_heartbeat_deadline_and_reconnects() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await.test_value()?;
    let addr = listener.local_addr().test_value()?;
    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.test_value()?;
        let mut first = accept_hdr_async(stream, AssertHeaders(|_: &Request| {}))
            .await
            .test_value()?;
        let _hello = first.next().await.test_value()?.test_value()?;
        let welcome = serde_json::json!({
            "type": "welcome",
            "session_id": "sess_silent",
            "server_time": "2026-09-21T21:00:00Z",
            "heartbeat_interval_seconds": 30
        });
        first
            .send(WsMessage::Text(welcome.to_string().into()))
            .await
            .test_value()?;

        // Stay connected but deliberately ignore application-level pings.
        tokio::time::sleep(Duration::from_millis(60)).await;
        drop(first);

        let (stream, _) = listener.accept().await.test_value()?;
        let mut second = accept_hdr_async(stream, AssertHeaders(|_: &Request| {}))
            .await
            .test_value()?;
        let _hello = second.next().await.test_value()?.test_value()?;
        let welcome = serde_json::json!({
            "type": "welcome",
            "session_id": "sess_after_heartbeat_timeout",
            "server_time": "2026-09-21T21:00:00Z",
            "heartbeat_interval_seconds": 30
        });
        second
            .send(WsMessage::Text(welcome.to_string().into()))
            .await
            .test_value()?;
        server_cancel.cancel();
        let _ = second.close(None).await;
        Ok::<(), common::TestFailure>(())
    });

    let agent = Agent::new(
        AgentConfig {
            hub_ws_base: format!("ws://{addr}"),
            token: AuthToken::new("test-token"),
            host: host(),
            agent_version: "0.1.0".into(),
            capabilities: vec![],
            preferred_profile: None,
            upload_base: std::env::temp_dir()
                .join(format!("sentinel0-reconnect-{}", addr.port()))
                .join("uploads"),
            reconnect: ReconnectPolicy {
                steps: vec![Duration::ZERO, Duration::from_millis(5)].into(),
                jitter: false,
            },
            connect_timeout: Duration::from_millis(100),
            welcome_timeout: Duration::from_millis(100),
            heartbeat_interval: Duration::from_millis(10),
            heartbeat_timeout: Duration::from_millis(25),
        },
        UnsupportedDispatcher,
    )
    .test_value()?;

    tokio::time::timeout(Duration::from_millis(200), agent.run(cancel.clone()))
        .await
        .test_value()?
        .test_value()?;
    server.await.test_value()??;
    Ok(())
}

#[tokio::test]
async fn cancellation_interrupts_reconnect_sleep_immediately() -> TestResult {
    let cancel = CancellationToken::new();
    let cancel_for_task = cancel.clone();

    let agent = Agent::new(
        AgentConfig {
            hub_ws_base: "ws://127.0.0.1:9".into(),
            token: AuthToken::new("test-token"),
            host: host(),
            agent_version: "0.1.0".into(),
            capabilities: vec![],
            preferred_profile: None,
            upload_base: std::env::temp_dir().join("sentinel0-cancel-backoff/uploads"),
            reconnect: ReconnectPolicy {
                steps: vec![Duration::from_secs(5)].into(),
                jitter: false,
            },
            connect_timeout: Duration::from_millis(100),
            welcome_timeout: Duration::from_millis(100),
            heartbeat_interval: Duration::from_secs(30),
            heartbeat_timeout: Duration::from_secs(90),
        },
        UnsupportedDispatcher,
    )
    .test_value()?;

    let task = tokio::spawn(async move { agent.run(cancel_for_task).await });
    tokio::time::sleep(Duration::from_millis(10)).await;
    cancel.cancel();

    tokio::time::timeout(Duration::from_millis(100), task)
        .await
        .test_value()?
        .test_value()?
        .test_value()?;
    Ok(())
}

#[tokio::test]
async fn cancellation_interrupts_wait_for_welcome_immediately() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await.test_value()?;
    let addr = listener.local_addr().test_value()?;
    let cancel = CancellationToken::new();
    let agent_cancel = cancel.clone();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.test_value()?;
        let mut ws = accept_hdr_async(stream, AssertHeaders(|_: &Request| {}))
            .await
            .test_value()?;
        let _hello = ws.next().await.test_value()?.test_value()?;
        tokio::time::sleep(Duration::from_millis(250)).await;
        Ok::<(), common::TestFailure>(())
    });

    let agent = Agent::new(
        AgentConfig {
            hub_ws_base: format!("ws://{addr}"),
            token: AuthToken::new("test-token"),
            host: host(),
            agent_version: "0.1.0".into(),
            capabilities: vec![],
            preferred_profile: None,
            upload_base: std::env::temp_dir().join("sentinel0-cancel-welcome/uploads"),
            reconnect: ReconnectPolicy {
                steps: vec![Duration::ZERO].into(),
                jitter: false,
            },
            connect_timeout: Duration::from_millis(100),
            welcome_timeout: Duration::from_secs(5),
            heartbeat_interval: Duration::from_secs(30),
            heartbeat_timeout: Duration::from_secs(90),
        },
        UnsupportedDispatcher,
    )
    .test_value()?;

    let task = tokio::spawn(async move { agent.run(agent_cancel).await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    cancel.cancel();

    tokio::time::timeout(Duration::from_millis(100), task)
        .await
        .test_value()?
        .test_value()?
        .test_value()?;
    server.abort();
    Ok(())
}
