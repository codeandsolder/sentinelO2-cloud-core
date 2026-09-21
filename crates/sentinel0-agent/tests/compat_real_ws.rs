#![expect(
    clippy::result_large_err,
    reason = "tungstenite fixes the handshake callback Result error type"
)]

use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use futures_util::{SinkExt, StreamExt};
use sentinel0_agent::{
    Agent, AgentConfig, AgentError, AuthToken, Dispatcher, ReconnectPolicy, UnsupportedDispatcher,
    pending_results,
};
use sentinel0_proto::{HostInfo, Message, Op};
use serde_json::{Map, Value, json};
use std::{collections::BTreeMap, fs, time::Duration};
use tokio::net::TcpListener;
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::{
        Message as WsMessage,
        handshake::server::{Request, Response},
    },
};
use tokio_util::sync::CancellationToken;

fn host() -> HostInfo {
    HostInfo {
        id: "host_compat".into(),
        hostname: "compat-host".into(),
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

fn config(addr: std::net::SocketAddr) -> AgentConfig {
    AgentConfig {
        hub_ws_base: format!("ws://{addr}"),
        token: AuthToken::new("compat-token"),
        host: host(),
        agent_version: "0.1-test".into(),
        capabilities: vec!["state".into(), "opaque_ref".into()],
        upload_base: std::env::temp_dir()
            .join(format!("sentinel0-compat-{}", addr.port()))
            .join("uploads"),
        reconnect: ReconnectPolicy {
            steps: vec![Duration::ZERO, Duration::from_millis(5)].into(),
            jitter: false,
        },
        connect_timeout: Duration::from_millis(100),
        welcome_timeout: Duration::from_millis(100),
        heartbeat_interval: Duration::from_secs(1),
        heartbeat_timeout: Duration::from_secs(3),
    }
}

async fn accept_agent(
    listener: &TcpListener,
) -> tokio_tungstenite::WebSocketStream<tokio::net::TcpStream> {
    let (stream, _) = listener.accept().await.unwrap();
    accept_hdr_async(stream, |req: &Request, response: Response| {
        assert_eq!(req.uri().path(), "/agent/connect");
        assert_eq!(
            req.headers().get("authorization").unwrap(),
            "Bearer compat-token"
        );
        Ok(response)
    })
    .await
    .unwrap()
}

async fn welcome(
    ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    session: &str,
) {
    let WsMessage::Text(hello) = ws.next().await.unwrap().unwrap() else {
        panic!("expected hello");
    };
    assert!(matches!(
        serde_json::from_str::<Message>(&hello).unwrap(),
        Message::Hello { .. }
    ));
    ws.send(WsMessage::Text(
        json!({
            "type": "welcome",
            "session_id": session,
            "server_time": "2026-09-21T21:00:00Z",
            "heartbeat_interval_seconds": 30
        })
        .to_string()
        .into(),
    ))
    .await
    .unwrap();
}

#[tokio::test]
async fn enrollment_rejected_is_retryable_and_recovers_without_restart() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();

    let server = tokio::spawn(async move {
        let mut first = accept_agent(&listener).await;
        let _hello = first.next().await.unwrap().unwrap();
        first
            .send(WsMessage::Text(
                json!({
                    "type": "error",
                    "code": "enrollment_rejected",
                    "message": "temporarily disabled",
                    "fatal": true
                })
                .to_string()
                .into(),
            ))
            .await
            .unwrap();
        drop(first);

        let mut second = accept_agent(&listener).await;
        welcome(&mut second, "sess_recovered").await;
        server_cancel.cancel();
        let _ = second.close(None).await;
    });

    let agent = Agent::new(config(addr), UnsupportedDispatcher);
    tokio::time::timeout(Duration::from_millis(200), agent.run(cancel.clone()))
        .await
        .expect("enrollment rejection did not retry")
        .unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn other_pre_welcome_error_is_fatal_and_does_not_retry() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let mut ws = accept_agent(&listener).await;
        let _hello = ws.next().await.unwrap().unwrap();
        ws.send(WsMessage::Text(
            json!({
                "type": "error",
                "code": "protocol_mismatch",
                "message": "nope",
                "fatal": true
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    });

    let agent = Agent::new(config(addr), UnsupportedDispatcher);
    let error = tokio::time::timeout(
        Duration::from_millis(100),
        agent.run(CancellationToken::new()),
    )
    .await
    .unwrap()
    .unwrap_err();

    assert!(matches!(
        error,
        AgentError::Rejected { ref code, .. } if code == "protocol_mismatch"
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn malformed_and_unknown_frames_are_ignored_and_ping_gets_fresh_pong() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();

    let server = tokio::spawn(async move {
        let mut ws = accept_agent(&listener).await;
        welcome(&mut ws, "sess_frames").await;

        ws.send(WsMessage::Text("{ definitely not json".into()))
            .await
            .unwrap();
        ws.send(WsMessage::Text(
            json!({
                "type": "request",
                "id": "req_unknown",
                "op": "not_an_official_op",
                "payload": {},
                "deadline": null,
                "opaque_ref": null
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();

        let stale = Utc.with_ymd_and_hms(2000, 1, 1, 0, 0, 0).unwrap();
        ws.send(WsMessage::Text(
            serde_json::to_string(&Message::Ping { timestamp: stale })
                .unwrap()
                .into(),
        ))
        .await
        .unwrap();

        let reply = tokio::time::timeout(Duration::from_millis(100), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let WsMessage::Text(reply) = reply else {
            panic!("expected pong text frame");
        };
        let Message::Pong { timestamp } = serde_json::from_str::<Message>(&reply).unwrap() else {
            panic!("expected pong");
        };
        assert!(
            timestamp > stale,
            "official agent timestamps pong at reply time"
        );

        server_cancel.cancel();
        let _ = ws.close(None).await;
    });

    let agent = Agent::new(config(addr), UnsupportedDispatcher);
    tokio::time::timeout(Duration::from_millis(200), agent.run(cancel.clone()))
        .await
        .unwrap()
        .unwrap();
    server.await.unwrap();
}

#[derive(Debug, Default)]
struct EchoDispatcher;

#[async_trait]
impl Dispatcher for EchoDispatcher {
    async fn dispatch(&self, id: &str, op: Op, payload: Map<String, Value>) -> Message {
        let mut result = BTreeMap::new();
        result.insert("op".into(), Value::String(op.as_str().into()));
        result.insert("payload".into(), Value::Object(payload));
        Message::Response {
            id: id.into(),
            ok: true,
            result: Some(result),
            error: None,
        }
    }
}

#[tokio::test]
async fn official_request_shape_reaches_dispatcher_and_response_returns_on_wire() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();

    let server = tokio::spawn(async move {
        let mut ws = accept_agent(&listener).await;
        welcome(&mut ws, "sess_request").await;

        ws.send(WsMessage::Text(
            json!({
                "type": "request",
                "id": "req_state",
                "op": "state",
                "payload": {"answer": 42},
                "deadline": null,
                "opaque_ref": "fixture"
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();

        let reply = tokio::time::timeout(Duration::from_millis(100), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let WsMessage::Text(reply) = reply else {
            panic!("expected response text frame");
        };
        let Message::Response {
            id,
            ok,
            result,
            error,
        } = serde_json::from_str::<Message>(&reply).unwrap()
        else {
            panic!("expected response");
        };
        assert_eq!(id, "req_state");
        assert!(ok);
        assert!(error.is_none());
        let result = result.unwrap();
        assert_eq!(result["op"], "state");
        assert_eq!(result["payload"], json!({"answer": 42}));
        let timing = result["_sx_timing"].as_object().unwrap();
        let received_at = timing["received_at"].as_f64().unwrap();
        let finished_at = timing["finished_at"].as_f64().unwrap();
        assert!(received_at <= finished_at);

        server_cancel.cancel();
        let _ = ws.close(None).await;
    });

    let agent = Agent::new(config(addr), EchoDispatcher);
    tokio::time::timeout(Duration::from_millis(200), agent.run(cancel.clone()))
        .await
        .unwrap()
        .unwrap();
    server.await.unwrap();
}

#[derive(Debug, Default)]
struct SlowDispatcher;

#[async_trait]
impl Dispatcher for SlowDispatcher {
    async fn dispatch(&self, id: &str, _op: Op, _payload: Map<String, Value>) -> Message {
        tokio::time::sleep(Duration::from_millis(200)).await;
        Message::Response {
            id: id.into(),
            ok: true,
            result: Some(BTreeMap::new()),
            error: None,
        }
    }
}

#[tokio::test]
async fn slow_request_does_not_block_ping_handling() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();

    let server = tokio::spawn(async move {
        let mut ws = accept_agent(&listener).await;
        welcome(&mut ws, "sess_concurrent").await;

        ws.send(WsMessage::Text(
            json!({
                "type": "request",
                "id": "req_slow",
                "op": "state",
                "payload": {},
                "deadline": null,
                "opaque_ref": null
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();

        ws.send(WsMessage::Text(
            serde_json::to_string(&Message::Ping {
                timestamp: Utc::now(),
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();

        let first = tokio::time::timeout(Duration::from_millis(80), ws.next())
            .await
            .expect(
                "slow request blocked read loop; official agent dispatches requests in background",
            )
            .unwrap()
            .unwrap();
        let WsMessage::Text(first) = first else {
            panic!("expected text frame");
        };
        assert!(matches!(
            serde_json::from_str::<Message>(&first).unwrap(),
            Message::Pong { .. }
        ));

        let second = tokio::time::timeout(Duration::from_millis(300), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let WsMessage::Text(second) = second else {
            panic!("expected response text frame");
        };
        assert!(matches!(
            serde_json::from_str::<Message>(&second).unwrap(),
            Message::Response { ref id, .. } if id == "req_slow"
        ));

        server_cancel.cancel();
        let _ = ws.close(None).await;
    });

    let agent = Agent::new(config(addr), SlowDispatcher);
    tokio::time::timeout(Duration::from_millis(600), agent.run(cancel.clone()))
        .await
        .unwrap()
        .unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn held_job_completion_replays_after_welcome_and_is_cleared() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let upload_base = temp.path().join("uploads");
    fs::create_dir(&upload_base).unwrap();

    let event = json!({
        "type": "event",
        "kind": "job_completed",
        "data": {"job_id": "job_held", "status": "failed"},
        "timestamp": "2026-09-21T21:00:00Z"
    });
    let pending_path = pending_results::record(&upload_base, "job_held", &event).unwrap();

    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();
    let server_event = event.clone();

    let server = tokio::spawn(async move {
        let mut ws = accept_agent(&listener).await;
        welcome(&mut ws, "sess_replay").await;

        let replay = tokio::time::timeout(Duration::from_millis(100), ws.next())
            .await
            .expect("held result was not replayed immediately after welcome")
            .unwrap()
            .unwrap();
        let WsMessage::Text(replay) = replay else {
            panic!("expected replayed event text frame");
        };
        assert_eq!(
            serde_json::from_str::<Value>(&replay).unwrap(),
            server_event
        );

        server_cancel.cancel();
        let _ = ws.close(None).await;
    });

    let mut cfg = config(addr);
    cfg.upload_base = upload_base;
    let agent = Agent::new(cfg, UnsupportedDispatcher);
    tokio::time::timeout(Duration::from_millis(200), agent.run(cancel.clone()))
        .await
        .unwrap()
        .unwrap();
    server.await.unwrap();

    assert!(
        !pending_path.exists(),
        "successful replay must clear durable copy"
    );
}

#[derive(Debug, Default)]
struct JobDispatcher;

#[async_trait]
impl Dispatcher for JobDispatcher {
    async fn dispatch(&self, id: &str, _op: Op, _payload: Map<String, Value>) -> Message {
        tokio::time::sleep(Duration::from_millis(500)).await;
        Message::Response {
            id: id.into(),
            ok: true,
            result: Some(BTreeMap::from([
                ("returncode".into(), Value::from(0)),
                ("output".into(), Value::String("job done".into())),
            ])),
            error: None,
        }
    }
}

#[tokio::test]
async fn background_job_acks_immediately_then_emits_completion_without_litter() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let upload_base = temp.path().join("uploads");
    fs::create_dir(&upload_base).unwrap();

    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();

    let server = tokio::spawn(async move {
        let mut ws = accept_agent(&listener).await;
        welcome(&mut ws, "sess_background").await;

        ws.send(WsMessage::Text(
            json!({
                "type": "request",
                "id": "req_bg",
                "op": "exec",
                "payload": {"background": true, "job_id": "job_fixture"},
                "deadline": null,
                "opaque_ref": null
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();

        let ack = tokio::time::timeout(Duration::from_millis(150), ws.next())
            .await
            .expect("background request was not acknowledged promptly")
            .unwrap()
            .unwrap();
        let WsMessage::Text(ack) = ack else {
            panic!("expected ack text frame");
        };
        let Message::Response {
            ok: true,
            result: Some(result),
            ..
        } = serde_json::from_str::<Message>(&ack).unwrap()
        else {
            panic!("expected successful running ack");
        };
        assert_eq!(result["status"], "running");
        assert_eq!(result["job_id"], "job_fixture");
        assert_eq!(result["tool"], "exec");
        assert_eq!(result["host"], "host_compat");

        let completion = tokio::time::timeout(Duration::from_millis(800), ws.next())
            .await
            .expect("job completion did not arrive")
            .unwrap()
            .unwrap();
        let WsMessage::Text(completion) = completion else {
            panic!("expected completion text frame");
        };
        let Message::Event { kind, data, .. } =
            serde_json::from_str::<Message>(&completion).unwrap()
        else {
            panic!("expected job_completed event");
        };
        assert_eq!(kind, "job_completed");
        assert_eq!(data["job_id"], "job_fixture");
        assert_eq!(data["status"], "succeeded");
        assert_eq!(data["exit_code"], 0);
        assert_eq!(data["output"], "job done");

        server_cancel.cancel();
        let _ = ws.close(None).await;
    });

    let mut cfg = config(addr);
    cfg.upload_base = upload_base.clone();
    let agent = Agent::new(cfg, JobDispatcher);
    tokio::time::timeout(Duration::from_millis(1200), agent.run(cancel.clone()))
        .await
        .unwrap()
        .unwrap();
    server.await.unwrap();

    assert!(pending_results::drain(&upload_base).is_empty());
}

#[tokio::test]
async fn background_completion_survives_dead_request_socket_and_replays_next_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let upload_base = temp.path().join("uploads");
    fs::create_dir(&upload_base).unwrap();

    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();

    let server = tokio::spawn(async move {
        let mut first = accept_agent(&listener).await;
        welcome(&mut first, "sess_before_drop").await;

        first
            .send(WsMessage::Text(
                json!({
                    "type": "request",
                    "id": "req_bg_drop",
                    "op": "exec",
                    "payload": {"background": true, "job_id": "job_survives"},
                    "deadline": null,
                    "opaque_ref": null
                })
                .to_string()
                .into(),
            ))
            .await
            .unwrap();

        let ack = tokio::time::timeout(Duration::from_millis(150), first.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(matches!(
            serde_json::from_str::<Message>(match &ack {
                WsMessage::Text(text) => text,
                _ => panic!("expected ack text"),
            })
            .unwrap(),
            Message::Response { ok: true, .. }
        ));

        // The operation has started. Kill exactly the socket its completion
        // would have used. Accept the replacement connection promptly so the
        // client's connect deadline is not what we are testing, but delay its
        // welcome until the old job has finished and persisted.
        drop(first);

        let mut second = accept_agent(&listener).await;
        let WsMessage::Text(hello) = second.next().await.unwrap().unwrap() else {
            panic!("expected replacement hello");
        };
        assert!(matches!(
            serde_json::from_str::<Message>(&hello).unwrap(),
            Message::Hello { .. }
        ));
        tokio::time::sleep(Duration::from_millis(650)).await;
        second
            .send(WsMessage::Text(
                json!({
                    "type": "welcome",
                    "session_id": "sess_after_drop",
                    "server_time": "2026-09-21T21:00:00Z",
                    "heartbeat_interval_seconds": 30
                })
                .to_string()
                .into(),
            ))
            .await
            .unwrap();

        let replay = tokio::time::timeout(Duration::from_millis(100), second.next())
            .await
            .expect("completed background result was not replayed")
            .unwrap()
            .unwrap();
        let WsMessage::Text(replay) = replay else {
            panic!("expected replayed event text");
        };
        let Message::Event { kind, data, .. } = serde_json::from_str::<Message>(&replay).unwrap()
        else {
            panic!("expected replayed job_completed event");
        };
        assert_eq!(kind, "job_completed");
        assert_eq!(data["job_id"], "job_survives");
        assert_eq!(data["status"], "succeeded");
        assert_eq!(data["output"], "job done");

        server_cancel.cancel();
        let _ = second.close(None).await;
    });

    let mut cfg = config(addr);
    cfg.upload_base = upload_base.clone();
    cfg.welcome_timeout = Duration::from_millis(900);
    let agent = Agent::new(cfg, JobDispatcher);
    tokio::time::timeout(Duration::from_millis(1800), agent.run(cancel.clone()))
        .await
        .unwrap()
        .unwrap();
    server.await.unwrap();

    assert!(pending_results::drain(&upload_base).is_empty());
}
