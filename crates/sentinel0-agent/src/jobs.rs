use sentinel0_proto::Message;
use serde_json::Value;
use std::{collections::BTreeMap, time::Duration};
use time::UtcDateTime;

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

#[derive(Clone, Copy)]
pub struct JobTiming {
    pub started_at: UtcDateTime,
    pub finished_at: UtcDateTime,
    pub elapsed: Duration,
}

pub fn build_completed_event_data(
    job_id: &str,
    op: &str,
    host: &str,
    dispatch_response: &Message,
    timing: JobTiming,
) -> BTreeMap<String, Value> {
    let (ok, result, error) = match dispatch_response {
        Message::Response {
            ok, result, error, ..
        } => (*ok, result.as_ref(), error.as_ref()),
        _ => (false, None, None),
    };

    let duration_seconds = (timing.elapsed.as_secs_f64() * 100.0).round() / 100.0;

    let (status, exit_code, output, error_message) = if ok {
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
    } else {
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
    };

    let (output, output_truncated) = truncate_output(&output);

    BTreeMap::from([
        ("job_id".into(), Value::String(job_id.into())),
        ("tool".into(), Value::String(op.into())),
        ("host".into(), Value::String(host.into())),
        ("status".into(), Value::String(status.into())),
        (
            "exit_code".into(),
            exit_code.map_or(Value::Null, Value::from),
        ),
        (
            "started_at".into(),
            Value::String(sentinel0_proto::clock::timestamp(
                timing.started_at,
                sentinel0_proto::clock::UtcSuffix::Colon,
                true,
            )),
        ),
        (
            "finished_at".into(),
            Value::String(sentinel0_proto::clock::timestamp(
                timing.finished_at,
                sentinel0_proto::clock::UtcSuffix::Colon,
                true,
            )),
        ),
        ("duration_s".into(), Value::from(duration_seconds)),
        ("output".into(), Value::String(output)),
        ("output_truncated".into(), Value::Bool(output_truncated)),
        (
            "error".into(),
            error_message.map_or(Value::Null, Value::String),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TestResult, TestValue as _};
    use sentinel0_proto::ResponseError;

    fn times() -> TestResult<JobTiming> {
        let started_at = UtcDateTime::parse(
            "2026-09-21T21:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .test_value()?;
        let finished_at = UtcDateTime::parse(
            "2026-09-21T21:00:01.234Z",
            &time::format_description::well_known::Rfc3339,
        )
        .test_value()?;
        Ok(JobTiming {
            started_at,
            finished_at,
            elapsed: Duration::from_millis(1234),
        })
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
    fn returncode_zero_maps_to_succeeded() -> TestResult {
        let timing = times()?;
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
            timing,
        );
        assert_eq!(data["status"], "succeeded");
        assert_eq!(data["exit_code"], 0);
        assert_eq!(data["output"], "ok");
        assert_eq!(data["duration_s"], 1.23);

        Ok(())
    }

    #[test]
    fn nonzero_and_missing_returncode_map_to_failed() -> TestResult {
        let timing = times()?;
        for result in [
            BTreeMap::from([("returncode".into(), Value::from(7))]),
            BTreeMap::new(),
        ] {
            let data = build_completed_event_data(
                "job",
                "exec",
                "host",
                &response(true, Some(result)),
                timing,
            );
            assert_eq!(data["status"], "failed");
        }

        Ok(())
    }

    #[test]
    fn timed_out_overrides_returncode() -> TestResult {
        let timing = times()?;
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
            timing,
        );
        assert_eq!(data["status"], "timeout");

        Ok(())
    }

    #[test]
    fn handler_error_maps_to_failed_with_message() -> TestResult {
        let timing = times()?;
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
        let data = build_completed_event_data("job", "exec", "host", &response, timing);
        assert_eq!(data["status"], "failed");
        assert_eq!(data["exit_code"], Value::Null);
        assert_eq!(data["error"], "fixture failed");

        Ok(())
    }

    #[test]
    fn oversized_output_is_byte_bounded_and_flagged() -> TestResult {
        let timing = times()?;
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
            timing,
        );
        assert_eq!(
            data["output"].as_str().test_value()?.len(),
            MAX_EVENT_OUTPUT_BYTES
        );
        assert_eq!(data["output_truncated"], true);

        Ok(())
    }
}
