mod common;

use chrono::{TimeZone, Utc};
use common::{TestResult, TestValue as _};
use futures_util::{SinkExt, StreamExt};
use sentinel0_agent::{
    Agent, AgentConfig, AgentError, AuthToken, DispatchResponse, Dispatcher, ReconnectPolicy,
    UnsupportedDispatcher,
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
        handshake::server::{Callback, ErrorResponse, Request, Response},
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
) -> TestResult<tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>> {
    let (stream, _) = listener.accept().await.test_value()?;
    let websocket = accept_hdr_async(
        stream,
        AssertHeaders(|req: &Request| {
            assert_eq!(req.uri().path(), "/agent/connect");
            assert_eq!(
                req.headers()
                    .get("authorization")
                    .and_then(|value| value.to_str().ok()),
                Some("Bearer compat-token")
            );
        }),
    )
    .await
    .test_value()?;
    Ok(websocket)
}

async fn next_non_heartbeat(
    ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
) -> TestResult<WsMessage> {
    loop {
        let frame = ws.next().await.test_value()?.test_value()?;
        if let WsMessage::Text(text) = &frame
            && matches!(
                serde_json::from_str::<Message>(text),
                Ok(Message::Ping { .. })
            )
        {
            let pong = serde_json::to_string(&Message::Pong {
                timestamp: Utc::now(),
            })
            .test_value()?;
            ws.send(WsMessage::Text(pong.into())).await.test_value()?;
            continue;
        }
        return Ok(frame);
    }
}

async fn welcome(
    ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    session: &str,
) -> TestResult {
    let WsMessage::Text(hello) = ws.next().await.test_value()?.test_value()? else {
        return Err(std::io::Error::other("expected hello").into());
    };
    assert!(matches!(
        serde_json::from_str::<Message>(&hello).test_value()?,
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
    .test_value()?;
    Ok(())
}

#[tokio::test]
async fn enrollment_rejected_is_retryable_and_recovers_without_restart() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await.test_value()?;
    let addr = listener.local_addr().test_value()?;
    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();

    let server = tokio::spawn(async move {
        let mut first = accept_agent(&listener).await?;
        let _hello = first.next().await.test_value()?.test_value()?;
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
            .test_value()?;
        drop(first);

        let mut second = accept_agent(&listener).await?;
        welcome(&mut second, "sess_recovered").await?;
        server_cancel.cancel();
        let _ = second.close(None).await;
        Ok::<(), common::TestFailure>(())
    });

    let agent = Agent::new(config(addr), UnsupportedDispatcher).test_value()?;
    tokio::time::timeout(Duration::from_millis(200), agent.run(cancel.clone()))
        .await
        .test_value()?
        .test_value()?;
    server.await.test_value()??;
    Ok(())
}

#[tokio::test]
async fn other_pre_welcome_error_is_fatal_and_does_not_retry() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await.test_value()?;
    let addr = listener.local_addr().test_value()?;

    let server = tokio::spawn(async move {
        let mut ws = accept_agent(&listener).await?;
        let _hello = ws.next().await.test_value()?.test_value()?;
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
        .test_value()?;
        Ok::<(), common::TestFailure>(())
    });

    let agent = Agent::new(config(addr), UnsupportedDispatcher).test_value()?;
    let Err(error) = tokio::time::timeout(
        Duration::from_millis(100),
        agent.run(CancellationToken::new()),
    )
    .await
    .test_value()?
    else {
        return Err(std::io::Error::other("expected protocol rejection").into());
    };

    assert!(matches!(
        error,
        AgentError::Rejected { ref code, .. } if code == "protocol_mismatch"
    ));
    server.await.test_value()??;
    Ok(())
}

#[tokio::test]
async fn malformed_and_unknown_frames_are_ignored_and_ping_gets_fresh_pong() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await.test_value()?;
    let addr = listener.local_addr().test_value()?;
    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();

    let server = tokio::spawn(async move {
        let mut ws = accept_agent(&listener).await?;
        welcome(&mut ws, "sess_frames").await?;

        ws.send(WsMessage::Text("{ definitely not json".into()))
            .await
            .test_value()?;
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
        .test_value()?;

        let stale = Utc
            .with_ymd_and_hms(2000, 1, 1, 0, 0, 0)
            .single()
            .test_value()?;
        ws.send(WsMessage::Text(
            serde_json::to_string(&Message::Ping { timestamp: stale })
                .test_value()?
                .into(),
        ))
        .await
        .test_value()?;

        let reply = tokio::time::timeout(Duration::from_secs(1), next_non_heartbeat(&mut ws))
            .await
            .test_value()?
            .test_value()?;
        let WsMessage::Text(reply) = reply else {
            return Err(std::io::Error::other("expected pong text frame").into());
        };
        let Message::Pong { timestamp } = serde_json::from_str::<Message>(&reply).test_value()?
        else {
            return Err(std::io::Error::other("expected pong").into());
        };
        assert!(
            timestamp > stale,
            "official agent timestamps pong at reply time"
        );

        server_cancel.cancel();
        let _ = ws.close(None).await;
        Ok::<(), common::TestFailure>(())
    });

    let agent = Agent::new(config(addr), UnsupportedDispatcher).test_value()?;
    tokio::time::timeout(Duration::from_secs(2), agent.run(cancel.clone()))
        .await
        .test_value()?
        .test_value()?;
    server.await.test_value()??;
    Ok(())
}

#[derive(Debug, Default)]
struct EchoDispatcher;

impl Dispatcher for EchoDispatcher {
    fn dispatch(
        &self,
        id: &str,
        op: Op,
        payload: Map<String, Value>,
    ) -> impl std::future::Future<Output = DispatchResponse> + Send {
        let mut result = BTreeMap::new();
        result.insert("op".into(), Value::String(op.as_str().into()));
        result.insert("payload".into(), Value::Object(payload));
        std::future::ready(DispatchResponse::message(Message::Response {
            id: id.into(),
            ok: true,
            result: Some(result),
            error: None,
        }))
    }
}

async fn state_request_roundtrip(
    ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    id: &str,
    payload: Value,
    opaque_ref: Option<&str>,
) -> TestResult<BTreeMap<String, Value>> {
    ws.send(WsMessage::Text(
        json!({
            "type": "request",
            "id": id,
            "op": "state",
            "payload": payload,
            "deadline": null,
            "opaque_ref": opaque_ref
        })
        .to_string()
        .into(),
    ))
    .await
    .test_value()?;

    let reply = tokio::time::timeout(Duration::from_secs(1), next_non_heartbeat(ws))
        .await
        .test_value()?
        .test_value()?;
    let WsMessage::Text(reply) = reply else {
        return Err(std::io::Error::other("expected response text frame").into());
    };
    let Message::Response {
        id: response_id,
        ok,
        result,
        error,
    } = serde_json::from_str::<Message>(&reply).test_value()?
    else {
        return Err(std::io::Error::other("expected response").into());
    };
    assert_eq!(response_id, id);
    assert!(ok);
    assert!(error.is_none());
    result.test_value()
}

#[tokio::test]
async fn official_request_shape_reaches_dispatcher_and_response_returns_on_wire() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await.test_value()?;
    let addr = listener.local_addr().test_value()?;
    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();

    let server = tokio::spawn(async move {
        let mut ws = accept_agent(&listener).await?;
        welcome(&mut ws, "sess_request").await?;

        let result =
            state_request_roundtrip(&mut ws, "req_state", json!({"answer": 42}), Some("fixture"))
                .await?;
        assert_eq!(result["op"], "state");
        assert_eq!(result["payload"], json!({"answer": 42}));
        let timing = result["_sx_timing"].as_object().test_value()?;
        let received_at = timing["received_at"].as_f64().test_value()?;
        let finished_at = timing["finished_at"].as_f64().test_value()?;
        assert!(received_at <= finished_at);
        let response_at = result["response_time"].as_str().test_value()?;
        chrono::NaiveTime::parse_from_str(response_at, "%H:%M:%S").test_value()?;

        let second = state_request_roundtrip(&mut ws, "req_state_2", json!({}), None).await?;
        let response_time = second["response_time"].as_str().test_value()?;
        chrono::NaiveTime::parse_from_str(response_time, "%H:%M:%S").test_value()?;

        tokio::time::sleep(Duration::from_millis(60)).await;
        let third = state_request_roundtrip(&mut ws, "req_state_3", json!({}), None).await?;
        let response_at = third["response_time"].as_str().test_value()?;
        chrono::NaiveTime::parse_from_str(response_at, "%H:%M:%S").test_value()?;

        server_cancel.cancel();
        let _ = ws.close(None).await;
        Ok::<(), common::TestFailure>(())
    });

    let agent = Agent::new(config(addr), EchoDispatcher).test_value()?;
    tokio::time::timeout(Duration::from_secs(2), agent.run(cancel.clone()))
        .await
        .test_value()?
        .test_value()?;
    server.await.test_value()??;
    Ok(())
}

#[derive(Debug, Default)]
struct SlowDispatcher;

impl Dispatcher for SlowDispatcher {
    async fn dispatch(&self, id: &str, _op: Op, _payload: Map<String, Value>) -> DispatchResponse {
        tokio::time::sleep(Duration::from_millis(200)).await;
        DispatchResponse::message(Message::Response {
            id: id.into(),
            ok: true,
            result: Some(BTreeMap::new()),
            error: None,
        })
    }
}

#[tokio::test]
async fn slow_request_does_not_block_ping_handling() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await.test_value()?;
    let addr = listener.local_addr().test_value()?;
    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();

    let server = tokio::spawn(async move {
        let mut ws = accept_agent(&listener).await?;
        welcome(&mut ws, "sess_concurrent").await?;

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
        .test_value()?;

        ws.send(WsMessage::Text(
            serde_json::to_string(&Message::Ping {
                timestamp: Utc::now(),
            })
            .test_value()?
            .into(),
        ))
        .await
        .test_value()?;

        let first = tokio::time::timeout(Duration::from_millis(80), ws.next())
            .await
            .test_value()?
            .test_value()?
            .test_value()?;
        let WsMessage::Text(first) = first else {
            return Err(std::io::Error::other("expected text frame").into());
        };
        assert!(matches!(
            serde_json::from_str::<Message>(&first).test_value()?,
            Message::Pong { .. }
        ));

        let second = tokio::time::timeout(Duration::from_millis(300), ws.next())
            .await
            .test_value()?
            .test_value()?
            .test_value()?;
        let WsMessage::Text(second) = second else {
            return Err(std::io::Error::other("expected response text frame").into());
        };
        assert!(matches!(
            serde_json::from_str::<Message>(&second).test_value()?,
            Message::Response { ref id, .. } if id == "req_slow"
        ));

        server_cancel.cancel();
        let _ = ws.close(None).await;
        Ok::<(), common::TestFailure>(())
    });

    let agent = Agent::new(config(addr), SlowDispatcher).test_value()?;
    tokio::time::timeout(Duration::from_millis(600), agent.run(cancel.clone()))
        .await
        .test_value()?
        .test_value()?;
    server.await.test_value()??;
    Ok(())
}

#[tokio::test]
async fn held_job_completion_replays_after_welcome_and_is_cleared() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await.test_value()?;
    let addr = listener.local_addr().test_value()?;
    let temp = tempfile::tempdir().test_value()?;
    let upload_base = temp.path().join("uploads");
    fs::create_dir(&upload_base).test_value()?;

    let event = json!({
        "type": "event",
        "kind": "job_completed",
        "data": {"job_id": "job_held", "status": "failed"},
        "timestamp": "2026-09-21T21:00:00Z"
    });
    let pending_path = pending_results::record(&upload_base, "job_held", &event).test_value()?;

    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();
    let server_event = event.clone();

    let server = tokio::spawn(async move {
        let mut ws = accept_agent(&listener).await?;
        welcome(&mut ws, "sess_replay").await?;

        let replay = tokio::time::timeout(Duration::from_millis(100), ws.next())
            .await
            .test_value()?
            .test_value()?
            .test_value()?;
        let WsMessage::Text(replay) = replay else {
            return Err(std::io::Error::other("expected replayed event text frame").into());
        };
        assert_eq!(
            serde_json::from_str::<Value>(&replay).test_value()?,
            server_event
        );

        server_cancel.cancel();
        let _ = ws.close(None).await;
        Ok::<(), common::TestFailure>(())
    });

    let mut cfg = config(addr);
    cfg.upload_base = upload_base;
    let agent = Agent::new(cfg, UnsupportedDispatcher).test_value()?;
    tokio::time::timeout(Duration::from_secs(2), agent.run(cancel.clone()))
        .await
        .test_value()?
        .test_value()?;
    server.await.test_value()??;

    assert!(
        !pending_path.exists(),
        "successful replay must clear durable copy"
    );
    Ok(())
}

#[derive(Debug, Default)]
struct JobDispatcher;

impl Dispatcher for JobDispatcher {
    async fn dispatch(&self, id: &str, _op: Op, _payload: Map<String, Value>) -> DispatchResponse {
        tokio::time::sleep(Duration::from_millis(500)).await;
        DispatchResponse::message(Message::Response {
            id: id.into(),
            ok: true,
            result: Some(BTreeMap::from([
                ("returncode".into(), Value::from(0)),
                ("output".into(), Value::String("job done".into())),
            ])),
            error: None,
        })
    }
}

#[tokio::test]
async fn background_job_acks_immediately_then_emits_completion_without_litter() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await.test_value()?;
    let addr = listener.local_addr().test_value()?;
    let temp = tempfile::tempdir().test_value()?;
    let upload_base = temp.path().join("uploads");
    fs::create_dir(&upload_base).test_value()?;

    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();

    let server = tokio::spawn(async move {
        let mut ws = accept_agent(&listener).await?;
        welcome(&mut ws, "sess_background").await?;

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
        .test_value()?;

        let ack = tokio::time::timeout(Duration::from_millis(150), ws.next())
            .await
            .test_value()?
            .test_value()?
            .test_value()?;
        let WsMessage::Text(ack) = ack else {
            return Err(std::io::Error::other("expected ack text frame").into());
        };
        let Message::Response {
            ok: true,
            result: Some(result),
            ..
        } = serde_json::from_str::<Message>(&ack).test_value()?
        else {
            return Err(std::io::Error::other("expected successful running ack").into());
        };
        assert_eq!(result["status"], "running");
        assert_eq!(result["job_id"], "job_fixture");
        assert_eq!(result["tool"], "exec");
        assert_eq!(result["host"], "host_compat");

        let completion = tokio::time::timeout(Duration::from_millis(800), ws.next())
            .await
            .test_value()?
            .test_value()?
            .test_value()?;
        let WsMessage::Text(completion) = completion else {
            return Err(std::io::Error::other("expected completion text frame").into());
        };
        let Message::Event { kind, data, .. } =
            serde_json::from_str::<Message>(&completion).test_value()?
        else {
            return Err(std::io::Error::other("expected job_completed event").into());
        };
        assert_eq!(kind, "job_completed");
        assert_eq!(data["job_id"], "job_fixture");
        assert_eq!(data["status"], "succeeded");
        assert_eq!(data["exit_code"], 0);
        assert_eq!(data["output"], "job done");

        server_cancel.cancel();
        let _ = ws.close(None).await;
        Ok::<(), common::TestFailure>(())
    });

    let mut cfg = config(addr);
    cfg.upload_base = upload_base.clone();
    let agent = Agent::new(cfg, JobDispatcher).test_value()?;
    tokio::time::timeout(Duration::from_millis(1200), agent.run(cancel.clone()))
        .await
        .test_value()?
        .test_value()?;
    server.await.test_value()??;

    assert_eq!(pending_results::drain(&upload_base), Vec::new());
    Ok(())
}

#[tokio::test]
async fn background_completion_survives_dead_request_socket_and_replays_next_connection()
-> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await.test_value()?;
    let addr = listener.local_addr().test_value()?;
    let temp = tempfile::tempdir().test_value()?;
    let upload_base = temp.path().join("uploads");
    fs::create_dir(&upload_base).test_value()?;

    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();

    let server = tokio::spawn(async move {
        let mut first = accept_agent(&listener).await?;
        welcome(&mut first, "sess_before_drop").await?;

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
            .test_value()?;

        let ack = tokio::time::timeout(Duration::from_millis(150), first.next())
            .await
            .test_value()?
            .test_value()?
            .test_value()?;
        assert!(matches!(
            serde_json::from_str::<Message>(match &ack {
                WsMessage::Text(text) => text,
                _ => return Err(std::io::Error::other("expected ack text").into()),
            })
            .test_value()?,
            Message::Response { ok: true, .. }
        ));

        // The operation has started. Kill exactly the socket its completion
        // would have used. Accept the replacement connection promptly so the
        // client's connect deadline is not what we are testing, but delay its
        // welcome until the old job has finished and persisted.
        drop(first);

        let mut second = accept_agent(&listener).await?;
        let WsMessage::Text(hello) = second.next().await.test_value()?.test_value()? else {
            return Err(std::io::Error::other("expected replacement hello").into());
        };
        assert!(matches!(
            serde_json::from_str::<Message>(&hello).test_value()?,
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
            .test_value()?;

        let replay = tokio::time::timeout(Duration::from_millis(100), second.next())
            .await
            .test_value()?
            .test_value()?
            .test_value()?;
        let WsMessage::Text(replay) = replay else {
            return Err(std::io::Error::other("expected replayed event text").into());
        };
        let Message::Event { kind, data, .. } =
            serde_json::from_str::<Message>(&replay).test_value()?
        else {
            return Err(std::io::Error::other("expected replayed job_completed event").into());
        };
        assert_eq!(kind, "job_completed");
        assert_eq!(data["job_id"], "job_survives");
        assert_eq!(data["status"], "succeeded");
        assert_eq!(data["output"], "job done");

        server_cancel.cancel();
        let _ = second.close(None).await;
        Ok::<(), common::TestFailure>(())
    });

    let mut cfg = config(addr);
    cfg.upload_base = upload_base.clone();
    cfg.welcome_timeout = Duration::from_millis(900);
    let agent = Agent::new(cfg, JobDispatcher).test_value()?;
    tokio::time::timeout(Duration::from_millis(1800), agent.run(cancel.clone()))
        .await
        .test_value()?
        .test_value()?;
    server.await.test_value()??;

    assert_eq!(pending_results::drain(&upload_base), Vec::new());
    Ok(())
}

#[tokio::test]
async fn application_pong_keeps_quiet_connection_alive_without_native_keepalive() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await.test_value()?;
    let addr = listener.local_addr().test_value()?;
    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();

    let server = tokio::spawn(async move {
        let mut ws = accept_agent(&listener).await?;
        welcome(&mut ws, "sess_app_heartbeat").await?;

        let deadline = tokio::time::Instant::now() + Duration::from_millis(180);
        while tokio::time::Instant::now() < deadline {
            let item = tokio::time::timeout(Duration::from_millis(60), ws.next())
                .await
                .test_value()?
                .test_value()?
                .test_value()?;
            let WsMessage::Text(text) = item else {
                continue;
            };
            if matches!(
                serde_json::from_str::<Message>(&text).test_value()?,
                Message::Ping { .. }
            ) {
                ws.send(WsMessage::Text(
                    serde_json::to_string(&Message::Pong {
                        timestamp: Utc::now(),
                    })
                    .test_value()?
                    .into(),
                ))
                .await
                .test_value()?;
            }
        }

        server_cancel.cancel();
        let _ = ws.close(None).await;
        Ok::<(), common::TestFailure>(())
    });

    let mut cfg = config(addr);
    cfg.heartbeat_interval = Duration::from_millis(10);
    cfg.heartbeat_timeout = Duration::from_millis(30);
    let agent = Agent::new(cfg, UnsupportedDispatcher).test_value()?;

    tokio::time::timeout(Duration::from_millis(400), agent.run(cancel.clone()))
        .await
        .test_value()?
        .test_value()?;
    server.await.test_value()??;
    Ok(())
}

#[tokio::test]
async fn unrelated_application_traffic_does_not_mask_missing_heartbeat_pong() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await.test_value()?;
    let addr = listener.local_addr().test_value()?;
    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();

    let server = tokio::spawn(async move {
        let mut first = accept_agent(&listener).await?;
        welcome(&mut first, "sess_no_pong").await?;

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
            .test_value()?
            .test_value()?;
        welcome(&mut second, "sess_after_no_pong").await?;
        server_cancel.cancel();
        let _ = second.close(None).await;
        sender.abort();
        Ok::<(), common::TestFailure>(())
    });

    let mut cfg = config(addr);
    cfg.heartbeat_interval = Duration::from_millis(10);
    cfg.heartbeat_timeout = Duration::from_millis(30);
    let agent = Agent::new(cfg, UnsupportedDispatcher).test_value()?;

    tokio::time::timeout(Duration::from_millis(250), agent.run(cancel.clone()))
        .await
        .test_value()?
        .test_value()?;
    server.await.test_value()??;
    Ok(())
}

#[derive(Debug, Default)]
struct PanickingDispatcher;

impl Dispatcher for PanickingDispatcher {
    async fn dispatch(&self, _id: &str, _op: Op, _payload: Map<String, Value>) -> DispatchResponse {
        std::panic::resume_unwind(Box::new("intentional dispatcher panic fixture"));
    }
}

#[tokio::test]
async fn dispatcher_panic_becomes_internal_error_without_killing_socket_loop() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await.test_value()?;
    let addr = listener.local_addr().test_value()?;
    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();

    let server = tokio::spawn(async move {
        let mut ws = accept_agent(&listener).await?;
        welcome(&mut ws, "sess_panic").await?;

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
        .test_value()?;

        let reply = tokio::time::timeout(Duration::from_millis(150), ws.next())
            .await
            .test_value()?
            .test_value()?
            .test_value()?;
        let WsMessage::Text(reply) = reply else {
            return Err(std::io::Error::other("expected response").into());
        };
        let Message::Response { ok, error, .. } =
            serde_json::from_str::<Message>(&reply).test_value()?
        else {
            return Err(std::io::Error::other("expected response message").into());
        };
        assert!(!ok);
        assert_eq!(error.test_value()?.code, "internal_error");

        ws.send(WsMessage::Text(
            serde_json::to_string(&Message::Ping {
                timestamp: Utc::now(),
            })
            .test_value()?
            .into(),
        ))
        .await
        .test_value()?;
        let pong = tokio::time::timeout(Duration::from_millis(100), ws.next())
            .await
            .test_value()?
            .test_value()?
            .test_value()?;
        assert!(matches!(
            serde_json::from_str::<Message>(match &pong {
                WsMessage::Text(text) => text,
                _ => return Err(std::io::Error::other("expected text pong").into()),
            })
            .test_value()?,
            Message::Pong { .. }
        ));

        server_cancel.cancel();
        let _ = ws.close(None).await;
        Ok::<(), common::TestFailure>(())
    });

    let agent = Agent::new(config(addr), PanickingDispatcher).test_value()?;
    tokio::time::timeout(Duration::from_millis(300), agent.run(cancel.clone()))
        .await
        .test_value()?
        .test_value()?;
    server.await.test_value()??;
    Ok(())
}

#[tokio::test]
async fn inbound_websocket_control_ping_is_answered_without_native_keepalive_timer() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await.test_value()?;
    let addr = listener.local_addr().test_value()?;
    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();

    let server = tokio::spawn(async move {
        let mut ws = accept_agent(&listener).await?;
        welcome(&mut ws, "sess_control_ping").await?;

        ws.send(WsMessage::Ping(vec![1, 2, 3, 4].into()))
            .await
            .test_value()?;

        let reply = tokio::time::timeout(Duration::from_millis(100), ws.next())
            .await
            .test_value()?
            .test_value()?
            .test_value()?;
        assert!(matches!(reply, WsMessage::Pong(ref payload) if payload.as_ref() == [1, 2, 3, 4]));

        server_cancel.cancel();
        let _ = ws.close(None).await;
        Ok::<(), common::TestFailure>(())
    });

    let agent = Agent::new(config(addr), UnsupportedDispatcher).test_value()?;
    tokio::time::timeout(Duration::from_millis(250), agent.run(cancel.clone()))
        .await
        .test_value()?
        .test_value()?;
    server.await.test_value()??;
    Ok(())
}

async fn verify_export_roundtrip(
    ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    source_path: &str,
) -> TestResult {
    let export_id = "01010101010101010101010101010101";
    ws.send(WsMessage::Text(
        json!({
            "type": "request",
            "id": "export_init",
            "op": "file_export_init",
            "payload": {
                "transfer_id": export_id,
                "source_path": source_path,
                "chunk_size": 3
            },
            "deadline": null,
            "opaque_ref": null
        })
        .to_string()
        .into(),
    ))
    .await
    .test_value()?;
    let init = next_non_heartbeat(ws).await?;
    let WsMessage::Text(init) = init else {
        return Err(std::io::Error::other("expected export init JSON response").into());
    };
    assert!(matches!(
        serde_json::from_str::<Message>(&init).test_value()?,
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
    .test_value()?;

    let binary = next_non_heartbeat(ws).await?;
    let WsMessage::Binary(binary) = binary else {
        return Err(
            std::io::Error::other("binary export payload must arrive before JSON ack").into(),
        );
    };
    let frame = decode_binary_frame(&binary).test_value()?;
    assert_eq!(frame.transfer_id, [0x01; 16]);
    assert_eq!(frame.chunk_index, 0);
    assert_eq!(frame.payload, b"abc");

    let ack = next_non_heartbeat(ws).await?;
    let WsMessage::Text(ack) = ack else {
        return Err(std::io::Error::other("expected JSON ack after binary export payload").into());
    };
    let Message::Response {
        ok: true,
        result: Some(result),
        ..
    } = serde_json::from_str::<Message>(&ack).test_value()?
    else {
        return Err(std::io::Error::other("expected successful export chunk ack").into());
    };
    assert_eq!(result["chunk_index"], 0);
    assert!(!result.contains_key("__binary_payload__"));
    Ok(())
}

async fn verify_upload_roundtrip(
    ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
) -> TestResult {
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
    .test_value()?;
    let upload_init = next_non_heartbeat(ws).await?;
    assert!(matches!(upload_init, WsMessage::Text(_)));

    ws.send(WsMessage::Binary(
        encode_binary_frame([0x10; 16], 0, b"xyz").into(),
    ))
    .await
    .test_value()?;
    let ack = tokio::time::timeout(Duration::from_millis(250), next_non_heartbeat(ws))
        .await
        .test_value()?
        .test_value()?;
    let WsMessage::Text(ack) = ack else {
        return Err(std::io::Error::other("expected transfer chunk ack event").into());
    };
    let Message::Event { kind, data, .. } = serde_json::from_str::<Message>(&ack).test_value()?
    else {
        return Err(std::io::Error::other("expected event").into());
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
    .test_value()?;
    let complete = next_non_heartbeat(ws).await?;
    let WsMessage::Text(complete) = complete else {
        return Err(std::io::Error::other("expected upload complete response").into());
    };
    let complete = serde_json::from_str::<Message>(&complete).test_value()?;
    assert!(
        matches!(complete, Message::Response { ok: true, .. }),
        "unexpected upload complete response: {complete:?}"
    );
    Ok(())
}

#[tokio::test]
async fn binary_transfer_roundtrip_preserves_wire_order_and_stages_inbound_chunk() -> TestResult {
    let dir = tempfile::tempdir().test_value()?;
    let source = dir.path().join("source.bin");
    fs::write(&source, b"abcdef").test_value()?;
    let upload_base = dir.path().join("uploads");
    fs::create_dir_all(&upload_base).test_value()?;
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

    let listener = TcpListener::bind("127.0.0.1:0").await.test_value()?;
    let addr = listener.local_addr().test_value()?;
    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();
    let source_for_server = source.display().to_string();

    let server = tokio::spawn(async move {
        let mut ws = accept_agent(&listener).await?;
        welcome(&mut ws, "sess_binary_roundtrip").await?;
        verify_export_roundtrip(&mut ws, &source_for_server).await?;
        verify_upload_roundtrip(&mut ws).await?;
        server_cancel.cancel();
        let _ = ws.close(None).await;
        Ok::<(), common::TestFailure>(())
    });

    let mut cfg = config(addr);
    cfg.upload_base = upload_base;
    let agent = Agent::new(cfg, dispatcher).test_value()?;
    tokio::time::timeout(Duration::from_secs(3), agent.run(cancel.clone()))
        .await
        .test_value()?
        .test_value()?;
    server.await.test_value()??;
    assert_eq!(fs::read(received).test_value()?, b"xyz");
    Ok(())
}
