use sentinel0_proto::ResponseError;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct HandlerError {
    pub code: String,
    pub message: String,
    pub details: BTreeMap<String, Value>,
}

impl HandlerError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            details: BTreeMap::new(),
        }
    }

    pub fn with_details(
        code: impl Into<String>,
        message: impl Into<String>,
        details: Map<String, Value>,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            details: details.into_iter().collect(),
        }
    }

    pub fn response_error(self) -> ResponseError {
        ResponseError {
            code: self.code,
            message: self.message,
            details: (!self.details.is_empty()).then_some(self.details),
        }
    }
}

pub type HandlerResult = Result<BTreeMap<String, Value>, HandlerError>;

pub fn require_str<'a>(
    payload: &'a Map<String, Value>,
    key: &'static str,
) -> Result<&'a str, HandlerError> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            HandlerError::new("invalid_payload", format!("missing or non-string '{key}'"))
        })
}
