use chrono::{DateTime, Utc};
use sentinel0_proto::Message;
use serde_json::Value;
use std::collections::BTreeMap;

pub const BACKGROUND_TIMEOUT_MAX_SECS: u64 = 3600;
pub const MAX_EVENT_OUTPUT_BYTES: usize = 256 * 1024;

fn truncate_output(text: &str) -> (String, bool) {
    let raw = text.as_bytes();
    if raw.len() <= MAX_EVENT_OUTPUT_BYTES {
        return (text.to_owned(), false);
    }
    (
        String::from_utf8_lossy(&raw[..MAX_EVENT_OUTPUT_BYTES]).into_owned(),
        true,
    )
}

pub fn build_completed_event_data(
    job_id: &str,
    op: &str,
    host: &str,
    dispatch_response: &Message,
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
) -> BTreeMap<String, Value> {
    let (ok, result, error) = match dispatch_response {
        Message::Response {
            ok, result, error, ..
        } => (*ok, result.as_ref(), error.as_ref()),
        _ => (false, None, None),
    };

    let duration_s = ((finished_at - started_at).num_milliseconds() as f64 / 10.0).round() / 100.0;

    let (status, exit_code, output, error_message) = if !ok {
        (
            "failed",
            None,
            String::new(),
            Some(
                error
                    .map(|error| error.message.clone())
                    .filter(|message| !message.is_empty())
                    .unwrap_or_else(|| "operation failed".into()),
            ),
        )
    } else {
        let timed_out = result
            .and_then(|result| result.get("timed_out"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let returncode = result
            .and_then(|result| result.get("returncode"))
            .and_then(Value::as_i64);
        let status = if timed_out {
            "timeout"
        } else if returncode == Some(0) {
            "succeeded"
        } else {
            "failed"
        };
        let output = result
            .and_then(|result| result.get("output"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        (status, returncode, output, None)
    };

    let (output, output_truncated) = truncate_output(&output);

    BTreeMap::from([
        ("job_id".into(), Value::String(job_id.into())),
        ("tool".into(), Value::String(op.into())),
        ("host".into(), Value::String(host.into())),
        ("status".into(), Value::String(status.into())),
        (
            "exit_code".into(),
            exit_code.map(Value::from).unwrap_or(Value::Null),
        ),
        (
            "started_at".into(),
            Value::String(started_at.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, false)),
        ),
        (
            "finished_at".into(),
            Value::String(finished_at.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, false)),
        ),
        ("duration_s".into(), Value::from(duration_s)),
        ("output".into(), Value::String(output)),
        ("output_truncated".into(), Value::Bool(output_truncated)),
        (
            "error".into(),
            error_message.map(Value::String).unwrap_or(Value::Null),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use sentinel0_proto::ResponseError;

    fn times() -> (DateTime<Utc>, DateTime<Utc>) {
        (
            Utc.with_ymd_and_hms(2026, 9, 21, 21, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 9, 21, 21, 0, 1).unwrap()
                + chrono::Duration::milliseconds(234),
        )
    }

    fn response(ok: bool, result: Option<BTreeMap<String, Value>>) -> Message {
        Message::Response {
            id: "req".into(),
            ok,
            result,
            error: None,
        }
    }

    #[test]
    fn returncode_zero_maps_to_succeeded() {
        let (start, finish) = times();
        let data = build_completed_event_data(
            "job",
            "exec",
            "host",
            &response(
                true,
                Some(BTreeMap::from([
                    ("returncode".into(), Value::from(0)),
                    ("output".into(), Value::String("ok".into())),
                ])),
            ),
            start,
            finish,
        );
        assert_eq!(data["status"], "succeeded");
        assert_eq!(data["exit_code"], 0);
        assert_eq!(data["output"], "ok");
        assert_eq!(data["duration_s"], 1.23);
    }

    #[test]
    fn nonzero_and_missing_returncode_map_to_failed() {
        let (start, finish) = times();
        for result in [
            BTreeMap::from([("returncode".into(), Value::from(7))]),
            BTreeMap::new(),
        ] {
            let data = build_completed_event_data(
                "job",
                "exec",
                "host",
                &response(true, Some(result)),
                start,
                finish,
            );
            assert_eq!(data["status"], "failed");
        }
    }

    #[test]
    fn timed_out_overrides_returncode() {
        let (start, finish) = times();
        let data = build_completed_event_data(
            "job",
            "exec",
            "host",
            &response(
                true,
                Some(BTreeMap::from([
                    ("returncode".into(), Value::from(0)),
                    ("timed_out".into(), Value::Bool(true)),
                ])),
            ),
            start,
            finish,
        );
        assert_eq!(data["status"], "timeout");
    }

    #[test]
    fn handler_error_maps_to_failed_with_message() {
        let (start, finish) = times();
        let response = Message::Response {
            id: "req".into(),
            ok: false,
            result: None,
            error: Some(ResponseError {
                code: "bad".into(),
                message: "fixture failed".into(),
                details: None,
            }),
        };
        let data = build_completed_event_data("job", "exec", "host", &response, start, finish);
        assert_eq!(data["status"], "failed");
        assert_eq!(data["exit_code"], Value::Null);
        assert_eq!(data["error"], "fixture failed");
    }

    #[test]
    fn oversized_output_is_byte_bounded_and_flagged() {
        let (start, finish) = times();
        let output = "x".repeat(MAX_EVENT_OUTPUT_BYTES + 100);
        let data = build_completed_event_data(
            "job",
            "exec",
            "host",
            &response(
                true,
                Some(BTreeMap::from([
                    ("returncode".into(), Value::from(0)),
                    ("output".into(), Value::String(output)),
                ])),
            ),
            start,
            finish,
        );
        assert_eq!(
            data["output"].as_str().unwrap().len(),
            MAX_EVENT_OUTPUT_BYTES
        );
        assert_eq!(data["output_truncated"], true);
    }
}
