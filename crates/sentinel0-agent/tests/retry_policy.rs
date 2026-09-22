use sentinel0_agent::{
    AgentConfig, AuthToken, ConfigError, MAX_RETRY_AFTER, ReconnectPolicy, parse_retry_after,
};
use sentinel0_proto::HostInfo;
use std::{path::PathBuf, sync::Arc, time::Duration};

#[test]
fn retry_after_parses_semicolon_and_comma_forms() {
    assert_eq!(
        parse_retry_after("hub_shutdown;retry_after=37"),
        Some(Duration::from_secs(37))
    );
    assert_eq!(
        parse_retry_after("hub_shutdown,retry_after=1.5"),
        Some(Duration::from_millis(1500))
    );
}

#[test]
fn retry_after_is_clamped_to_official_bounds() {
    assert_eq!(parse_retry_after("retry_after=-10"), Some(Duration::ZERO));
    assert_eq!(
        parse_retry_after("retry_after=999999"),
        Some(MAX_RETRY_AFTER)
    );
}

#[test]
fn malformed_retry_after_falls_back_to_local_schedule() {
    for reason in [
        "",
        "hub_shutdown",
        "retry_after=",
        "retry_after=nope",
        "retry_after=NaN",
        "retry_after=inf",
        "other=1",
    ] {
        assert_eq!(parse_retry_after(reason), None, "{reason}");
    }
}

#[test]
fn reconnect_policy_empty_schedule_is_safe() {
    let policy = ReconnectPolicy {
        steps: Arc::from([]),
        jitter: false,
    };
    assert_eq!(policy.delay(0), Duration::ZERO);
    assert_eq!(policy.delay(999), Duration::ZERO);
}

#[test]
fn reconnect_policy_saturates_at_last_step() {
    let policy = ReconnectPolicy {
        steps: vec![
            Duration::ZERO,
            Duration::from_secs(1),
            Duration::from_secs(2),
        ]
        .into(),
        jitter: false,
    };
    assert_eq!(policy.delay(0), Duration::ZERO);
    assert_eq!(policy.delay(1), Duration::from_secs(1));
    assert_eq!(policy.delay(2), Duration::from_secs(2));
    assert_eq!(policy.delay(200), Duration::from_secs(2));
}

#[test]
fn jitter_never_exceeds_selected_window() {
    let policy = ReconnectPolicy {
        steps: vec![Duration::from_millis(50)].into(),
        jitter: true,
    };
    for _ in 0..256 {
        assert!(policy.delay(0) <= Duration::from_millis(50));
    }
}

fn valid_config() -> AgentConfig {
    AgentConfig {
        hub_ws_base: "wss://example.invalid".into(),
        token: AuthToken::new("token"),
        host: HostInfo {
            id: "host".into(),
            hostname: "host".into(),
            os: "linux".into(),
            kernel: None,
            arch: None,
            cpu_model: None,
            cpu_cores: None,
            mem_total_bytes: None,
            disk_total_bytes: None,
            machine_type: None,
            distro: None,
            config_summary: None,
        },
        agent_version: "test".into(),
        capabilities: vec![],
        preferred_profile: None,
        upload_base: PathBuf::from("/tmp/uploads"),
        reconnect: ReconnectPolicy::default(),
        connect_timeout: Duration::from_secs(15),
        welcome_timeout: Duration::from_secs(10),
        heartbeat_interval: Duration::from_secs(30),
        heartbeat_timeout: Duration::from_secs(90),
    }
}

#[test]
fn valid_agent_config_passes_validation() {
    assert_eq!(valid_config().validate(), Ok(()));
}

#[test]
fn zero_heartbeat_interval_is_rejected_before_tokio_interval_can_panic() {
    let mut config = valid_config();
    config.heartbeat_interval = Duration::ZERO;
    assert_eq!(
        config.validate(),
        Err(ConfigError::ZeroDuration("heartbeat_interval"))
    );
}

#[test]
fn heartbeat_timeout_must_exceed_interval() {
    let mut config = valid_config();
    config.heartbeat_timeout = config.heartbeat_interval;
    assert_eq!(
        config.validate(),
        Err(ConfigError::HeartbeatTimeoutTooShort)
    );
}

#[test]
fn empty_or_header_invalid_tokens_are_rejected_at_startup() {
    let mut config = valid_config();
    config.token = AuthToken::new("");
    assert_eq!(config.validate(), Err(ConfigError::EmptyToken));

    config.token = AuthToken::new("bad\nheader");
    assert_eq!(config.validate(), Err(ConfigError::InvalidTokenHeader));
}
