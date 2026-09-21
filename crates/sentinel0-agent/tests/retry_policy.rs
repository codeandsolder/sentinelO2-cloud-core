use sentinel0_agent::{MAX_RETRY_AFTER, ReconnectPolicy, parse_retry_after};
use std::{sync::Arc, time::Duration};

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
