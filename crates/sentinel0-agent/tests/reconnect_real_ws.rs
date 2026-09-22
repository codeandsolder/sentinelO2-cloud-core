#![expect(
    clippy::result_large_err,
    reason = "tungstenite fixes the handshake callback Result error type"
)]

use futures_util::{SinkExt, StreamExt};
use sentinel0_agent::{Agent, AgentConfig, AuthToken, ReconnectPolicy, UnsupportedDispatcher};
use sentinel0_proto::{HostInfo, Message};
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
        handshake::server::{Request, Response},
        protocol::{CloseFrame, frame::coding::CloseCode},
    },
};
use tokio_util::sync::CancellationToken;

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
async fn real_socket_reconnects_after_1012_and_reauthenticates() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handshakes = Arc::new(AtomicUsize::new(0));
    let seen = handshakes.clone();
    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();

    let server = tokio::spawn(async move {
        for n in 0..2 {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = accept_hdr_async(stream, |req: &Request, response: Response| {
                assert_eq!(req.uri().path(), "/agent/connect");
                assert_eq!(
                    req.headers().get("authorization").unwrap(),
                    "Bearer test-token"
                );
                seen.fetch_add(1, Ordering::SeqCst);
                Ok(response)
            })
            .await
            .unwrap();

            let WsMessage::Text(hello) = ws.next().await.unwrap().unwrap() else {
                panic!("expected hello")
            };
            match serde_json::from_str::<Message>(&hello).unwrap() {
                Message::Hello {
                    protocol_version,
                    host,
                    ..
                } => {
                    assert_eq!(protocol_version, "1.13.0");
                    assert_eq!(host.id, "host_test");
                }
                other => panic!("expected hello, got {other:?}"),
            }

            let welcome = serde_json::json!({
                "type": "welcome",
                "session_id": format!("sess_{n}"),
                "server_time": "2026-09-21T21:00:00Z",
                "heartbeat_interval_seconds": 30
            });
            ws.send(WsMessage::Text(welcome.to_string().into()))
                .await
                .unwrap();

            if n == 0 {
                ws.close(Some(CloseFrame {
                    code: CloseCode::Restart,
                    reason: "deploy".into(),
                }))
                .await
                .unwrap();
            } else {
                server_cancel.cancel();
                let _ = ws.close(None).await;
            }
        }
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
    .unwrap();

    tokio::time::timeout(Duration::from_secs(2), agent.run(cancel.clone()))
        .await
        .unwrap()
        .unwrap();
    server.await.unwrap();
    assert_eq!(handshakes.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn established_session_loss_discards_old_handshake_backoff() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();

    let server = tokio::spawn(async move {
        for n in 0..5 {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = accept_hdr_async(stream, |req: &Request, response: Response| {
                assert_eq!(
                    req.headers().get("authorization").unwrap(),
                    "Bearer test-token"
                );
                Ok(response)
            })
            .await
            .unwrap();
            let _hello = ws.next().await.unwrap().unwrap();

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
                .unwrap();

            if n == 3 {
                drop(ws);
            } else {
                server_cancel.cancel();
                let _ = ws.close(None).await;
            }
        }
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
    .unwrap();

    tokio::time::timeout(Duration::from_millis(150), agent.run(cancel.clone()))
        .await
        .expect("established-session loss inherited stale 300ms handshake backoff")
        .unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn missing_welcome_times_out_and_next_real_connection_recovers() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut first = accept_hdr_async(stream, |_: &Request, response: Response| Ok(response))
            .await
            .unwrap();
        let _hello = first.next().await.unwrap().unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        drop(first);

        let (stream, _) = listener.accept().await.unwrap();
        let mut second = accept_hdr_async(stream, |_: &Request, response: Response| Ok(response))
            .await
            .unwrap();
        let _hello = second.next().await.unwrap().unwrap();
        let welcome = serde_json::json!({
            "type": "welcome",
            "session_id": "sess_recovered",
            "server_time": "2026-09-21T21:00:00Z",
            "heartbeat_interval_seconds": 30
        });
        second
            .send(WsMessage::Text(welcome.to_string().into()))
            .await
            .unwrap();
        server_cancel.cancel();
        let _ = second.close(None).await;
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
    .unwrap();

    tokio::time::timeout(Duration::from_millis(200), agent.run(cancel.clone()))
        .await
        .expect("agent hung on a hub that accepted WebSocket but never welcomed")
        .unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn silent_established_peer_trips_heartbeat_deadline_and_reconnects() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut first = accept_hdr_async(stream, |_: &Request, response: Response| Ok(response))
            .await
            .unwrap();
        let _hello = first.next().await.unwrap().unwrap();
        let welcome = serde_json::json!({
            "type": "welcome",
            "session_id": "sess_silent",
            "server_time": "2026-09-21T21:00:00Z",
            "heartbeat_interval_seconds": 30
        });
        first
            .send(WsMessage::Text(welcome.to_string().into()))
            .await
            .unwrap();

        // Stay connected but deliberately ignore application-level pings.
        tokio::time::sleep(Duration::from_millis(60)).await;
        drop(first);

        let (stream, _) = listener.accept().await.unwrap();
        let mut second = accept_hdr_async(stream, |_: &Request, response: Response| Ok(response))
            .await
            .unwrap();
        let _hello = second.next().await.unwrap().unwrap();
        let welcome = serde_json::json!({
            "type": "welcome",
            "session_id": "sess_after_heartbeat_timeout",
            "server_time": "2026-09-21T21:00:00Z",
            "heartbeat_interval_seconds": 30
        });
        second
            .send(WsMessage::Text(welcome.to_string().into()))
            .await
            .unwrap();
        server_cancel.cancel();
        let _ = second.close(None).await;
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
    .unwrap();

    tokio::time::timeout(Duration::from_millis(200), agent.run(cancel.clone()))
        .await
        .expect("silent established peer did not trigger heartbeat recovery")
        .unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn cancellation_interrupts_reconnect_sleep_immediately() {
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
    .unwrap();

    let task = tokio::spawn(async move { agent.run(cancel_for_task).await });
    tokio::time::sleep(Duration::from_millis(10)).await;
    cancel.cancel();

    tokio::time::timeout(Duration::from_millis(100), task)
        .await
        .expect("cancellation waited for the full reconnect delay")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn cancellation_interrupts_wait_for_welcome_immediately() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cancel = CancellationToken::new();
    let agent_cancel = cancel.clone();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = accept_hdr_async(stream, |_: &Request, response: Response| Ok(response))
            .await
            .unwrap();
        let _hello = ws.next().await.unwrap().unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
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
    .unwrap();

    let task = tokio::spawn(async move { agent.run(agent_cancel).await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    cancel.cancel();

    tokio::time::timeout(Duration::from_millis(100), task)
        .await
        .expect("cancellation waited for the welcome timeout")
        .unwrap()
        .unwrap();
    server.abort();
}
