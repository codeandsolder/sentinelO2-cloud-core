#![expect(
    clippy::result_large_err,
    reason = "tungstenite fixes the handshake callback Result error type"
)]

use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use futures_util::{SinkExt, StreamExt};
use sentinel0_agent::{
    Agent, AgentConfig, AgentError, AuthToken, Dispatcher, ReconnectPolicy, UnsupportedDispatcher,
    core::CoreDispatcher,
    pending_results,
    policy::{FileAccess, FileOpsPath, Policy},
};
use sentinel0_proto::{
    HostInfo, Message, Op, PreferredProfile, decode_binary_frame, encode_binary_frame,
};
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
        preferred_profile: Some(PreferredProfile::Compact),
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

async fn next_non_heartbeat(
    ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
) -> WsMessage {
    loop {
        let frame = ws.next().await.unwrap().unwrap();
        if let WsMessage::Text(text) = &frame {
            if matches!(
                serde_json::from_str::<Message>(text),
                Ok(Message::Ping { .. })
            ) {
                ws.send(WsMessage::Text(
                    serde_json::to_string(&Message::Pong {
                        timestamp: Utc::now(),
                    })
                    .unwrap()
                    .into(),
                ))
                .await
                .unwrap();
                continue;
            }
        }
        return frame;
    }
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
        Message::Hello {
            preferred_profile: Some(PreferredProfile::Compact),
            ..
        }
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

    let agent = Agent::new(config(addr), UnsupportedDispatcher).unwrap();
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

    let agent = Agent::new(config(addr), UnsupportedDispatcher).unwrap();
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

        let reply = tokio::time::timeout(Duration::from_secs(1), next_non_heartbeat(&mut ws))
            .await
            .expect("fresh pong did not arrive");
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

    let agent = Agent::new(config(addr), UnsupportedDispatcher).unwrap();
    tokio::time::timeout(Duration::from_secs(2), agent.run(cancel.clone()))
        .await
        .expect("frame-handling session did not finish")
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

        let reply = tokio::time::timeout(Duration::from_secs(1), next_non_heartbeat(&mut ws))
            .await
            .expect("operation response did not arrive");
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

    let agent = Agent::new(config(addr), EchoDispatcher).unwrap();
    tokio::time::timeout(Duration::from_secs(2), agent.run(cancel.clone()))
        .await
        .expect("frame-handling session did not finish")
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

    let agent = Agent::new(config(addr), SlowDispatcher).unwrap();
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
    let agent = Agent::new(cfg, UnsupportedDispatcher).unwrap();
    tokio::time::timeout(Duration::from_secs(2), agent.run(cancel.clone()))
        .await
        .expect("frame-handling session did not finish")
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
    let agent = Agent::new(cfg, JobDispatcher).unwrap();
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
    let agent = Agent::new(cfg, JobDispatcher).unwrap();
    tokio::time::timeout(Duration::from_millis(1800), agent.run(cancel.clone()))
        .await
        .unwrap()
        .unwrap();
    server.await.unwrap();

    assert!(pending_results::drain(&upload_base).is_empty());
}

#[tokio::test]
async fn application_pong_keeps_quiet_connection_alive_without_native_keepalive() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();

    let server = tokio::spawn(async move {
        let mut ws = accept_agent(&listener).await;
        welcome(&mut ws, "sess_app_heartbeat").await;

        let deadline = tokio::time::Instant::now() + Duration::from_millis(180);
        while tokio::time::Instant::now() < deadline {
            let item = tokio::time::timeout(Duration::from_millis(60), ws.next())
                .await
                .expect("agent stopped sending application heartbeats")
                .unwrap()
                .unwrap();
            let WsMessage::Text(text) = item else {
                continue;
            };
            if matches!(
                serde_json::from_str::<Message>(&text).unwrap(),
                Message::Ping { .. }
            ) {
                ws.send(WsMessage::Text(
                    serde_json::to_string(&Message::Pong {
                        timestamp: Utc::now(),
                    })
                    .unwrap()
                    .into(),
                ))
                .await
                .unwrap();
            }
        }

        server_cancel.cancel();
        let _ = ws.close(None).await;
    });

    let mut cfg = config(addr);
    cfg.heartbeat_interval = Duration::from_millis(10);
    cfg.heartbeat_timeout = Duration::from_millis(30);
    let agent = Agent::new(cfg, UnsupportedDispatcher).unwrap();

    tokio::time::timeout(Duration::from_millis(400), agent.run(cancel.clone()))
        .await
        .expect("application pong heartbeat failed to keep the session alive")
        .unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn unrelated_application_traffic_does_not_mask_missing_heartbeat_pong() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();

    let server = tokio::spawn(async move {
        let mut first = accept_agent(&listener).await;
        welcome(&mut first, "sess_no_pong").await;

        // Keep sending valid application traffic while intentionally never
        // answering the agent's heartbeat Ping. This must not count as the
        // bidirectional liveness proof.
        let sender = tokio::spawn(async move {
            for _ in 0..8 {
                let _ = first
                    .send(WsMessage::Text(
                        json!({
                            "type": "event",
                            "kind": "noise",
                            "data": {},
                            "timestamp": "2026-09-21T21:00:00Z"
                        })
                        .to_string()
                        .into(),
                    ))
                    .await;
                tokio::time::sleep(Duration::from_millis(8)).await;
            }
        });

        let mut second = tokio::time::timeout(Duration::from_millis(150), accept_agent(&listener))
            .await
            .expect("missing application pong did not force a reconnect");
        welcome(&mut second, "sess_after_no_pong").await;
        server_cancel.cancel();
        let _ = second.close(None).await;
        sender.abort();
    });

    let mut cfg = config(addr);
    cfg.heartbeat_interval = Duration::from_millis(10);
    cfg.heartbeat_timeout = Duration::from_millis(30);
    let agent = Agent::new(cfg, UnsupportedDispatcher).unwrap();

    tokio::time::timeout(Duration::from_millis(250), agent.run(cancel.clone()))
        .await
        .unwrap()
        .unwrap();
    server.await.unwrap();
}

#[derive(Debug, Default)]
struct PanickingDispatcher;

#[async_trait]
impl Dispatcher for PanickingDispatcher {
    async fn dispatch(&self, _id: &str, _op: Op, _payload: Map<String, Value>) -> Message {
        panic!("intentional dispatcher panic fixture");
    }
}

#[tokio::test]
async fn dispatcher_panic_becomes_internal_error_without_killing_socket_loop() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();

    let server = tokio::spawn(async move {
        let mut ws = accept_agent(&listener).await;
        welcome(&mut ws, "sess_panic").await;

        ws.send(WsMessage::Text(
            json!({
                "type":"request",
                "id":"req_panic",
                "op":"state",
                "payload":{},
                "deadline":null,
                "opaque_ref":null
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();

        let reply = tokio::time::timeout(Duration::from_millis(150), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let WsMessage::Text(reply) = reply else {
            panic!("expected response");
        };
        let Message::Response { ok, error, .. } = serde_json::from_str::<Message>(&reply).unwrap()
        else {
            panic!("expected response message");
        };
        assert!(!ok);
        assert_eq!(error.unwrap().code, "internal_error");

        ws.send(WsMessage::Text(
            serde_json::to_string(&Message::Ping {
                timestamp: Utc::now(),
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
        let pong = tokio::time::timeout(Duration::from_millis(100), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(matches!(
            serde_json::from_str::<Message>(match &pong {
                WsMessage::Text(text) => text,
                _ => panic!("expected text pong"),
            })
            .unwrap(),
            Message::Pong { .. }
        ));

        server_cancel.cancel();
        let _ = ws.close(None).await;
    });

    let agent = Agent::new(config(addr), PanickingDispatcher).unwrap();
    tokio::time::timeout(Duration::from_millis(300), agent.run(cancel.clone()))
        .await
        .unwrap()
        .unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn inbound_websocket_control_ping_is_answered_without_native_keepalive_timer() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();

    let server = tokio::spawn(async move {
        let mut ws = accept_agent(&listener).await;
        welcome(&mut ws, "sess_control_ping").await;

        ws.send(WsMessage::Ping(vec![1, 2, 3, 4].into()))
            .await
            .unwrap();

        let reply = tokio::time::timeout(Duration::from_millis(100), ws.next())
            .await
            .expect("tungstenite did not emit automatic control pong")
            .unwrap()
            .unwrap();
        assert!(matches!(reply, WsMessage::Pong(ref payload) if payload.as_ref() == [1, 2, 3, 4]));

        server_cancel.cancel();
        let _ = ws.close(None).await;
    });

    let agent = Agent::new(config(addr), UnsupportedDispatcher).unwrap();
    tokio::time::timeout(Duration::from_millis(250), agent.run(cancel.clone()))
        .await
        .unwrap()
        .unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn binary_transfer_roundtrip_preserves_wire_order_and_stages_inbound_chunk() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.bin");
    fs::write(&source, b"abcdef").unwrap();
    let upload_base = dir.path().join("uploads");
    fs::create_dir_all(&upload_base).unwrap();
    let received = upload_base.join("received.bin");

    let policy = Policy {
        upload_base: upload_base.clone(),
        file_ops_paths: vec![FileOpsPath {
            path: dir.path().to_owned(),
            access: FileAccess::ReadWrite,
        }],
        ..Policy::default()
    };
    let dispatcher = CoreDispatcher::new(policy, dir.path().join("config.yaml"), "test");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();
    let source_for_server = source.display().to_string();

    let server = tokio::spawn(async move {
        let mut ws = accept_agent(&listener).await;
        welcome(&mut ws, "sess_binary_roundtrip").await;

        let export_id = "01010101010101010101010101010101";
        ws.send(WsMessage::Text(
            json!({
                "type": "request",
                "id": "export_init",
                "op": "file_export_init",
                "payload": {
                    "transfer_id": export_id,
                    "source_path": source_for_server,
                    "chunk_size": 3
                },
                "deadline": null,
                "opaque_ref": null
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
        let init = next_non_heartbeat(&mut ws).await;
        let WsMessage::Text(init) = init else {
            panic!("expected export init JSON response");
        };
        assert!(matches!(
            serde_json::from_str::<Message>(&init).unwrap(),
            Message::Response { ok: true, .. }
        ));

        ws.send(WsMessage::Text(
            json!({
                "type": "request",
                "id": "export_chunk",
                "op": "file_export_chunk",
                "payload": {
                    "transfer_id": export_id,
                    "chunk_index": 0
                },
                "deadline": null,
                "opaque_ref": null
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();

        let first = next_non_heartbeat(&mut ws).await;
        let WsMessage::Binary(first) = first else {
            panic!("binary export payload must arrive before JSON ack");
        };
        let frame = decode_binary_frame(&first).unwrap();
        assert_eq!(frame.transfer_id, [0x01; 16]);
        assert_eq!(frame.chunk_index, 0);
        assert_eq!(frame.payload, b"abc");

        let second = next_non_heartbeat(&mut ws).await;
        let WsMessage::Text(second) = second else {
            panic!("expected JSON ack after binary export payload");
        };
        let Message::Response {
            ok: true,
            result: Some(result),
            ..
        } = serde_json::from_str::<Message>(&second).unwrap()
        else {
            panic!("expected successful export chunk ack");
        };
        assert_eq!(result["chunk_index"], 0);
        assert!(!result.contains_key("__binary_payload__"));

        let inbound_id = "10101010101010101010101010101010";
        ws.send(WsMessage::Text(
            json!({
                "type": "request",
                "id": "upload_init",
                "op": "upload_init",
                "payload": {
                    "upload_id": inbound_id,
                    "target_path": "received.bin",
                    "total_size": 3
                },
                "deadline": null,
                "opaque_ref": null
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
        let upload_init = next_non_heartbeat(&mut ws).await;
        assert!(matches!(upload_init, WsMessage::Text(_)));

        ws.send(WsMessage::Binary(
            encode_binary_frame([0x10; 16], 0, b"xyz").into(),
        ))
        .await
        .unwrap();
        let ack = tokio::time::timeout(Duration::from_millis(250), next_non_heartbeat(&mut ws))
            .await
            .expect("missing transfer_chunk_ack");
        let WsMessage::Text(ack) = ack else {
            panic!("expected transfer chunk ack event");
        };
        let Message::Event { kind, data, .. } = serde_json::from_str::<Message>(&ack).unwrap()
        else {
            panic!("expected event");
        };
        assert_eq!(kind, "transfer_chunk_ack");
        assert_eq!(data["transfer_id"], inbound_id);
        assert_eq!(data["chunk_index"], 0);
        assert_eq!(data["ok"], true);
        assert_eq!(data["bytes"], 3);

        ws.send(WsMessage::Text(
            json!({
                "type": "request",
                "id": "upload_complete",
                "op": "upload_complete",
                "payload": {"upload_id": inbound_id},
                "deadline": null,
                "opaque_ref": null
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
        let complete = next_non_heartbeat(&mut ws).await;
        let WsMessage::Text(complete) = complete else {
            panic!("expected upload complete response");
        };
        let complete = serde_json::from_str::<Message>(&complete).unwrap();
        assert!(
            matches!(complete, Message::Response { ok: true, .. }),
            "unexpected upload complete response: {complete:?}"
        );

        server_cancel.cancel();
        let _ = ws.close(None).await;
    });

    let mut cfg = config(addr);
    cfg.upload_base = upload_base;
    let agent = Agent::new(cfg, dispatcher).unwrap();
    tokio::time::timeout(Duration::from_secs(3), agent.run(cancel.clone()))
        .await
        .expect("binary roundtrip session did not finish")
        .unwrap();
    server.await.unwrap();

    assert_eq!(fs::read(received).unwrap(), b"xyz");
}
