#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

pub mod jobs;
pub mod pending_results;

use async_trait::async_trait;
use chrono::Utc;
use futures_util::{FutureExt, SinkExt, StreamExt};
use http::{HeaderValue, header::AUTHORIZATION};
use rand::Rng;
use sentinel0_proto::{HostInfo, Message, Op, bounding::bound_response_default};
use std::{
    collections::BTreeMap, panic::AssertUnwindSafe, path::PathBuf, sync::Arc, time::Duration,
};
use tokio::{
    sync::mpsc,
    task::JoinSet,
    time::{Instant, interval, sleep, timeout},
};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{
        self, Message as WsMessage,
        protocol::{WebSocketConfig, frame::coding::CloseCode},
    },
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

#[derive(Clone)]
pub struct AuthToken(String);

impl AuthToken {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    fn bearer_header(&self) -> Result<HeaderValue, http::header::InvalidHeaderValue> {
        HeaderValue::from_str(&format!("Bearer {}", self.0))
    }
}

impl std::fmt::Debug for AuthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

#[derive(Clone)]
pub struct AgentConfig {
    pub hub_ws_base: String,
    pub token: AuthToken,
    pub host: HostInfo,
    pub agent_version: String,
    pub capabilities: Vec<String>,
    pub upload_base: PathBuf,
    pub reconnect: ReconnectPolicy,
    pub connect_timeout: Duration,
    pub welcome_timeout: Duration,
    pub heartbeat_interval: Duration,
    pub heartbeat_timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct ReconnectPolicy {
    pub steps: Arc<[Duration]>,
    pub jitter: bool,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            steps: vec![0, 1, 2, 5, 10, 20, 30, 60, 120, 300]
                .into_iter()
                .map(Duration::from_secs)
                .collect::<Vec<_>>()
                .into(),
            jitter: true,
        }
    }
}

impl ReconnectPolicy {
    pub fn delay(&self, attempt: usize) -> Duration {
        let Some(&raw) = self
            .steps
            .get(attempt.min(self.steps.len().saturating_sub(1)))
        else {
            return Duration::ZERO;
        };
        if !self.jitter || raw.is_zero() {
            return raw;
        }
        Duration::from_secs_f64(rand::rng().random_range(0.0..=raw.as_secs_f64()))
    }
}

#[async_trait]
pub trait Dispatcher: Send + Sync + 'static {
    async fn dispatch(
        &self,
        id: &str,
        op: Op,
        payload: serde_json::Map<String, serde_json::Value>,
    ) -> Message;
}

#[derive(Debug, Default)]
pub struct UnsupportedDispatcher;

#[async_trait]
impl Dispatcher for UnsupportedDispatcher {
    async fn dispatch(
        &self,
        id: &str,
        op: Op,
        _payload: serde_json::Map<String, serde_json::Value>,
    ) -> Message {
        Message::Response {
            id: id.into(),
            ok: false,
            result: None,
            error: Some(sentinel0_proto::ResponseError {
                code: "unsupported_op".into(),
                message: format!("agent does not support op: {op}"),
                details: None,
            }),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("hub WebSocket base URL must not be empty")]
    EmptyHubUrl,
    #[error("authorization token must not be empty")]
    EmptyToken,
    #[error("authorization token cannot be represented as an HTTP header")]
    InvalidTokenHeader,
    #[error("{0} must be greater than zero")]
    ZeroDuration(&'static str),
    #[error("heartbeat_timeout must be greater than heartbeat_interval")]
    HeartbeatTimeoutTooShort,
}

impl AgentConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.hub_ws_base.trim().is_empty() {
            return Err(ConfigError::EmptyHubUrl);
        }
        if self.token.0.is_empty() {
            return Err(ConfigError::EmptyToken);
        }
        self.token
            .bearer_header()
            .map_err(|_| ConfigError::InvalidTokenHeader)?;

        for (name, value) in [
            ("connect_timeout", self.connect_timeout),
            ("welcome_timeout", self.welcome_timeout),
            ("heartbeat_interval", self.heartbeat_interval),
            ("heartbeat_timeout", self.heartbeat_timeout),
        ] {
            if value.is_zero() {
                return Err(ConfigError::ZeroDuration(name));
            }
        }
        if self.heartbeat_timeout <= self.heartbeat_interval {
            return Err(ConfigError::HeartbeatTimeoutTooShort);
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AgentError {
    #[error("bad authorization header: {0}")]
    InvalidHeader(#[from] http::header::InvalidHeaderValue),
    #[error("websocket: {0}")]
    WebSocket(#[from] tungstenite::Error),
    #[error("protocol JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("hub rejected agent: {code}: {message}")]
    Rejected { code: String, message: String },
    #[error("enrollment rejected: {0}")]
    EnrollmentRejected(String),
    #[error("expected welcome as first hub message")]
    ExpectedWelcome,
    #[error("hub closed before welcome")]
    ClosedBeforeWelcome,
    #[error("{0} timed out")]
    Timeout(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum SessionEnd {
    Clean,
    Restart(Option<Duration>),
    Lost(Option<Duration>),
}

struct Outbound {
    message: Message,
    clear_after_send: Option<PathBuf>,
}

pub struct Agent<D> {
    config: AgentConfig,
    dispatcher: Arc<D>,
}

impl<D: Dispatcher> Agent<D> {
    pub fn new(config: AgentConfig, dispatcher: D) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            dispatcher: Arc::new(dispatcher),
        })
    }

    pub async fn run(&self, cancel: CancellationToken) -> Result<(), AgentError> {
        let mut attempt = 0usize;
        let mut retry_hint = None;
        let mut tasks = JoinSet::new();

        while !cancel.is_cancelled() {
            let delay = retry_hint
                .take()
                .unwrap_or_else(|| self.config.reconnect.delay(attempt));
            if !delay.is_zero() {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = sleep(delay) => {}
                }
            }

            match self.serve_one(&cancel, &mut tasks).await {
                Ok(SessionEnd::Clean) => {
                    attempt = 0;
                }
                Ok(SessionEnd::Restart(hint)) => {
                    retry_hint = hint;
                    attempt = 0;
                }
                Ok(SessionEnd::Lost(hint)) => {
                    debug!("established SentinelX compatibility session lost");
                    retry_hint = hint;
                    attempt = 1;
                }
                Err(AgentError::EnrollmentRejected(message)) => {
                    warn!(%message, "SentinelX enrollment rejected; keeping normal retry cadence");
                    attempt = attempt.saturating_add(1);
                }
                Err(AgentError::Rejected { code, message }) => {
                    return Err(AgentError::Rejected { code, message });
                }
                Err(error) => {
                    warn!(attempt, %error, "SentinelX compatibility connection failed before session establishment");
                    attempt = attempt.saturating_add(1);
                }
            }
        }

        tasks.abort_all();
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result {
                if !error.is_cancelled() {
                    warn!(?error, "request task failed during shutdown");
                }
            }
        }
        Ok(())
    }

    async fn serve_one(
        &self,
        cancel: &CancellationToken,
        tasks: &mut JoinSet<()>,
    ) -> Result<SessionEnd, AgentError> {
        let url = format!(
            "{}/agent/connect",
            self.config.hub_ws_base.trim_end_matches('/')
        );
        let mut req = url.into_client_request()?;
        req.headers_mut()
            .insert(AUTHORIZATION, self.config.token.bearer_header()?);
        let websocket_config = WebSocketConfig::default()
            .max_message_size(Some(sentinel0_proto::MAX_BINARY_FRAME_BYTES));
        let (mut ws, _) = timeout(
            self.config.connect_timeout,
            connect_async_with_config(req, Some(websocket_config), false),
        )
        .await
        .map_err(|_| AgentError::Timeout("connect"))??;

        let hello = Message::hello(
            self.config.host.clone(),
            self.config.agent_version.clone(),
            self.config.capabilities.clone(),
        );
        ws.send(WsMessage::Text(serde_json::to_string(&hello)?.into()))
            .await?;

        let first = tokio::select! {
            _ = cancel.cancelled() => {
                let _ = ws.close(None).await;
                return Ok(SessionEnd::Clean);
            }
            item = timeout(self.config.welcome_timeout, ws.next()) => {
                item.map_err(|_| AgentError::Timeout("welcome"))?
            },
        };
        let Some(first) = first else {
            return Err(AgentError::ClosedBeforeWelcome);
        };
        let first = first?;
        let WsMessage::Text(text) = first else {
            return Err(AgentError::ExpectedWelcome);
        };
        match serde_json::from_str::<Message>(&text)? {
            Message::Welcome { .. } => {}
            Message::Error { code, message, .. } if code == "enrollment_rejected" => {
                return Err(AgentError::EnrollmentRejected(message));
            }
            Message::Error { code, message, .. } => {
                return Err(AgentError::Rejected { code, message });
            }
            _ => return Err(AgentError::ExpectedWelcome),
        }

        for (path, event) in drain_pending(self.config.upload_base.clone()).await {
            if ws
                .send(WsMessage::Text(serde_json::to_string(&event)?.into()))
                .await
                .is_err()
            {
                break;
            }
            clear_pending(Some(path)).await;
        }

        let mut heartbeat = interval(self.config.heartbeat_interval);
        heartbeat.tick().await;
        let mut last_pong = Instant::now();
        let (response_tx, mut response_rx) = mpsc::channel::<Outbound>(64);

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    let _ = ws.close(None).await;
                    return Ok(SessionEnd::Clean);
                }
                _ = heartbeat.tick() => {
                    if last_pong.elapsed() >= self.config.heartbeat_timeout {
                        return Ok(SessionEnd::Lost(None));
                    }
                    let ping = Message::Ping { timestamp: Utc::now() };
                    if ws.send(WsMessage::Text(serde_json::to_string(&ping)?.into())).await.is_err() {
                        return Ok(SessionEnd::Lost(None));
                    }
                }
                outbound = response_rx.recv() => {
                    if let Some(outbound) = outbound {
                        let mut wire = serde_json::to_value(&outbound.message)?;
                        if matches!(outbound.message, Message::Response { .. }) {
                            let _ = bound_response_default(&mut wire);
                        }
                        if ws.send(WsMessage::Text(
                            serde_json::to_string(&wire)?.into()
                        )).await.is_err() {
                            return Ok(SessionEnd::Lost(None));
                        }
                        clear_pending(outbound.clear_after_send).await;
                    }
                }
                item = ws.next() => {
                    match item {
                        None => return Ok(SessionEnd::Lost(None)),
                        Some(Err(_)) => return Ok(SessionEnd::Lost(None)),
                        Some(Ok(WsMessage::Close(frame))) => {
                            let hint = frame.as_ref().and_then(|frame| parse_retry_after(frame.reason.as_str()));
                            return Ok(if frame.as_ref().is_some_and(|frame| frame.code == CloseCode::Restart) {
                                SessionEnd::Restart(hint)
                            } else {
                                SessionEnd::Lost(hint)
                            });
                        }
                        Some(Ok(WsMessage::Text(text))) => {
                            let Ok(msg) = serde_json::from_str::<Message>(&text) else {
                                continue;
                            };
                            match msg {
                                Message::Ping { .. } => {
                                    if ws.send(WsMessage::Text(
                                        serde_json::to_string(&Message::Pong { timestamp: Utc::now() })?.into()
                                    )).await.is_err() {
                                        return Ok(SessionEnd::Lost(None));
                                    }
                                }
                                Message::Request { id, op, payload, .. } => {
                                    let received_at = unix_time_seconds();
                                    let background = payload
                                        .get("background")
                                        .and_then(serde_json::Value::as_bool)
                                        .unwrap_or(false);
                                    let dispatcher = Arc::clone(&self.dispatcher);
                                    let response_tx = response_tx.clone();
                                    let payload: serde_json::Map<String, serde_json::Value> =
                                        payload.into_iter().collect();

                                    if background {
                                        let job_id = payload
                                            .get("job_id")
                                            .and_then(serde_json::Value::as_str)
                                            .map(ToOwned::to_owned)
                                            .unwrap_or_else(|| {
                                                format!(
                                                    "job_{:012x}",
                                                    rand::rng().random::<u64>() & 0xffffffffffff
                                                )
                                            });
                                        let ack = Message::Response {
                                            id: id.clone(),
                                            ok: true,
                                            result: Some(BTreeMap::from([
                                                ("status".into(), serde_json::Value::String("running".into())),
                                                ("job_id".into(), serde_json::Value::String(job_id.clone())),
                                                ("tool".into(), serde_json::Value::String(op.as_str().into())),
                                                ("host".into(), serde_json::Value::String(self.config.host.id.clone())),
                                            ])),
                                            error: None,
                                        };
                                        if ws
                                            .send(WsMessage::Text(serde_json::to_string(&ack)?.into()))
                                            .await
                                            .is_err()
                                        {
                                            return Ok(SessionEnd::Lost(None));
                                        }

                                        let started_at = Utc::now();
                                        let host_id = self.config.host.id.clone();
                                        let upload_base = self.config.upload_base.clone();
                                        tasks.spawn(async move {
                                            let mut response =
                                                dispatch_safely(dispatcher, id.clone(), op, payload).await;
                                            if let Ok(mut bounded) = serde_json::to_value(&response) {
                                                let _ = bound_response_default(&mut bounded);
                                                if let Ok(parsed) = serde_json::from_value(bounded) {
                                                    response = parsed;
                                                }
                                            }
                                            let finished_at = Utc::now();
                                            let data = jobs::build_completed_event_data(
                                                &job_id,
                                                op.as_str(),
                                                &host_id,
                                                &response,
                                                started_at,
                                                finished_at,
                                            );
                                            let event = Message::Event {
                                                kind: "job_completed".into(),
                                                data,
                                                timestamp: Utc::now(),
                                            };
                                            let pending_path = match serde_json::to_value(&event) {
                                                Ok(value) => {
                                                    record_pending(upload_base, job_id.clone(), value).await
                                                }
                                                Err(error) => {
                                                    warn!(?error, %job_id, "failed to serialize background completion for persistence");
                                                    None
                                                }
                                            };
                                            let _ = response_tx
                                                .send(Outbound {
                                                    message: event,
                                                    clear_after_send: pending_path,
                                                })
                                                .await;
                                        });
                                    } else {
                                        tasks.spawn(async move {
                                            let mut response =
                                                dispatch_safely(dispatcher, id.clone(), op, payload).await;
                                            if let Message::Response {
                                                result: Some(result),
                                                ..
                                            } = &mut response
                                            {
                                                if !result.contains_key("__binary_payload__") {
                                                    result.insert(
                                                        "_sx_timing".into(),
                                                        serde_json::json!({
                                                            "received_at": received_at,
                                                            "finished_at": unix_time_seconds(),
                                                        }),
                                                    );
                                                }
                                            }
                                            let _ = response_tx
                                                .send(Outbound {
                                                    message: response,
                                                    clear_after_send: None,
                                                })
                                                .await;
                                        });
                                    }
                                }
                                Message::Pong { .. } => {
                                    last_pong = Instant::now();
                                }
                                Message::Error { code, message, fatal: true } => {
                                    return Err(AgentError::Rejected { code, message });
                                }
                                _ => {}
                            }
                        }
                        Some(Ok(_)) => {}
                    }
                }
            }
        }
    }
}

async fn dispatch_safely<D: Dispatcher>(
    dispatcher: Arc<D>,
    id: String,
    op: Op,
    payload: serde_json::Map<String, serde_json::Value>,
) -> Message {
    match AssertUnwindSafe(dispatcher.dispatch(&id, op, payload))
        .catch_unwind()
        .await
    {
        Ok(response) => response,
        Err(_) => {
            warn!(%id, %op, "dispatcher panicked; converting panic into internal_error");
            Message::Response {
                id,
                ok: false,
                result: None,
                error: Some(sentinel0_proto::ResponseError {
                    code: "internal_error".into(),
                    message: "operation handler panicked".into(),
                    details: None,
                }),
            }
        }
    }
}

async fn drain_pending(upload_base: PathBuf) -> Vec<(PathBuf, serde_json::Value)> {
    match tokio::task::spawn_blocking(move || pending_results::drain(&upload_base)).await {
        Ok(entries) => entries,
        Err(error) => {
            warn!(?error, "pending-result drain task failed");
            Vec::new()
        }
    }
}

async fn record_pending(
    upload_base: PathBuf,
    job_id: String,
    event: serde_json::Value,
) -> Option<PathBuf> {
    match tokio::task::spawn_blocking(move || {
        pending_results::record(&upload_base, &job_id, &event)
    })
    .await
    {
        Ok(path) => path,
        Err(error) => {
            warn!(?error, "pending-result record task failed");
            None
        }
    }
}

async fn clear_pending(path: Option<PathBuf>) {
    if path.is_none() {
        return;
    }
    if let Err(error) =
        tokio::task::spawn_blocking(move || pending_results::clear(path.as_deref())).await
    {
        warn!(?error, "pending-result clear task failed");
    }
}

fn unix_time_seconds() -> f64 {
    Utc::now().timestamp_micros() as f64 / 1_000_000.0
}

pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(300);

pub fn parse_retry_after(reason: &str) -> Option<Duration> {
    for part in reason.replace(',', ";").split(';') {
        let Some((key, value)) = part.trim().split_once('=') else {
            continue;
        };
        if key.trim() != "retry_after" {
            continue;
        }

        let seconds = value.trim().parse::<f64>().ok()?;
        if !seconds.is_finite() {
            return None;
        }
        return Some(Duration::from_secs_f64(
            seconds.clamp(0.0, MAX_RETRY_AFTER.as_secs_f64()),
        ));
    }
    None
}
