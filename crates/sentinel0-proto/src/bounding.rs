use serde_json::{Map, Value, json};

pub const RESPONSE_SOFT_LIMIT_BYTES: usize = 131_072;
pub const RESPONSE_HEAD_RATIO: f64 = 0.6;
pub const TRUNCATION_KEY: &str = "_truncation";

const META_RESERVE: usize = 512;
const SHRINK_SLACK: f64 = 0.95;
const MAX_PASSES: usize = 64;
const MIN_TRUNCATABLE: usize = 256;

pub fn serialized_size(value: &Value) -> usize {
    match value {
        Value::Null => 4,
        Value::Bool(true) => 4,
        Value::Bool(false) => 5,
        Value::Number(number) => number.to_string().len(),
        Value::String(text) => python_json_string_size(text),
        Value::Array(items) => {
            2 + items.iter().map(serialized_size).sum::<usize>() + items.len().saturating_sub(1) * 2
        }
        Value::Object(map) => {
            2 + map
                .iter()
                .map(|(key, value)| python_json_string_size(key) + 2 + serialized_size(value))
                .sum::<usize>()
                + map.len().saturating_sub(1) * 2
        }
    }
}

fn python_json_string_size(text: &str) -> usize {
    let mut size = 2; // quotes
    for ch in text.chars() {
        size += match ch {
            '"' | '\\' | '\u{0008}' | '\u{000c}' | '\n' | '\r' | '\t' => 2,
            ch if (ch as u32) < 0x20 => 6,
            ch if ch.is_ascii() => 1,
            ch if (ch as u32) <= 0xffff => 6,
            _ => 12, // UTF-16 surrogate pair, each written as \uXXXX
        };
    }
    size
}

fn decode_utf8_ignoring_invalid(mut bytes: &[u8]) -> String {
    let mut out = String::new();
    while !bytes.is_empty() {
        match std::str::from_utf8(bytes) {
            Ok(valid) => {
                out.push_str(valid);
                break;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                if valid > 0 {
                    // SAFETY: from_utf8 reported this prefix as valid.
                    out.push_str(
                        std::str::from_utf8(&bytes[..valid]).expect("validated UTF-8 prefix"),
                    );
                }
                let skip = error.error_len().unwrap_or(bytes.len() - valid);
                bytes = &bytes[(valid + skip).min(bytes.len())..];
            }
        }
    }
    out
}

fn marker(omitted: usize) -> String {
    format!("\n…[sentinelx: truncated {omitted} bytes]…\n")
}

fn truncate_text(text: &str, keep_bytes: usize) -> String {
    let raw = text.as_bytes();
    let original = raw.len();
    if original <= keep_bytes || keep_bytes == 0 {
        return text.to_owned();
    }

    let head_budget = (keep_bytes as f64 * RESPONSE_HEAD_RATIO) as usize;
    let tail_budget = keep_bytes - head_budget;
    let head = decode_utf8_ignoring_invalid(&raw[..head_budget.min(original)]);
    let tail = if tail_budget > 0 {
        decode_utf8_ignoring_invalid(&raw[original.saturating_sub(tail_budget)..])
    } else {
        String::new()
    };
    let omitted = original - head.len() - tail.len();
    format!("{head}{}{tail}", marker(omitted))
}

#[derive(Clone)]
enum PathPart {
    Key(String),
    Index(usize),
}

fn largest_string_path(root: &Value) -> Option<(Vec<PathPart>, usize)> {
    fn visit(node: &Value, path: &mut Vec<PathPart>, best: &mut Option<(Vec<PathPart>, usize)>) {
        match node {
            Value::Object(map) => {
                for (key, value) in map {
                    path.push(PathPart::Key(key.clone()));
                    match value {
                        Value::String(text) => {
                            let size = text.len();
                            if size >= MIN_TRUNCATABLE
                                && best.as_ref().is_none_or(|(_, best_size)| size > *best_size)
                            {
                                *best = Some((path.clone(), size));
                            }
                        }
                        Value::Object(_) | Value::Array(_) => visit(value, path, best),
                        _ => {}
                    }
                    path.pop();
                }
            }
            Value::Array(items) => {
                for (index, value) in items.iter().enumerate() {
                    path.push(PathPart::Index(index));
                    match value {
                        Value::String(text) => {
                            let size = text.len();
                            if size >= MIN_TRUNCATABLE
                                && best.as_ref().is_none_or(|(_, best_size)| size > *best_size)
                            {
                                *best = Some((path.clone(), size));
                            }
                        }
                        Value::Object(_) | Value::Array(_) => visit(value, path, best),
                        _ => {}
                    }
                    path.pop();
                }
            }
            _ => {}
        }
    }

    let mut best = None;
    visit(root, &mut Vec::new(), &mut best);
    best
}

fn value_at_mut<'a>(mut value: &'a mut Value, path: &[PathPart]) -> Option<&'a mut Value> {
    for part in path {
        value = match part {
            PathPart::Key(key) => value.as_object_mut()?.get_mut(key)?,
            PathPart::Index(index) => value.as_array_mut()?.get_mut(*index)?,
        };
    }
    Some(value)
}

fn shrink_largest(response: &mut Value, root_key: &str, budget: usize) -> bool {
    for _ in 0..MAX_PASSES {
        let current = serialized_size(response);
        if current <= budget {
            return true;
        }

        let Some(root) = response.get(root_key) else {
            return false;
        };
        let Some((path, raw_len)) = largest_string_path(root) else {
            return false;
        };

        let proportional =
            (raw_len as f64 * (budget as f64 / current as f64) * SHRINK_SLACK) as usize;
        let keep = proportional
            .max(MIN_TRUNCATABLE)
            .min(raw_len.saturating_sub(1));

        let Some(Value::String(text)) = response
            .get_mut(root_key)
            .and_then(|root| value_at_mut(root, &path))
        else {
            return false;
        };
        *text = truncate_text(text, keep);
    }
    serialized_size(response) <= budget
}

fn truncation_meta(original: usize, response: &Value) -> Value {
    json!({
        "response_truncated": true,
        "original_bytes": original,
        "delivered_bytes": serialized_size(response),
        "continuation_available": false,
        "execution_status": if response.get("ok").and_then(Value::as_bool).unwrap_or(false) {
            "completed"
        } else {
            "failed"
        },
    })
}

pub fn bound_response(response: &mut Value, soft_limit: usize) -> Option<Value> {
    let original = serialized_size(response);
    if original <= soft_limit {
        return None;
    }

    let budget = soft_limit.saturating_sub(META_RESERVE);

    if response.get("result").is_some_and(Value::is_object) {
        if !shrink_largest(response, "result", budget) {
            response["result"] = json!({"note": "result omitted: too large to bound field-wise"});
        }

        let mut meta = truncation_meta(original, response);
        response
            .get_mut("result")
            .and_then(Value::as_object_mut)
            .expect("result was normalized to an object")
            .insert(TRUNCATION_KEY.into(), meta.clone());

        let delivered = serialized_size(response);
        if let Some(object) = meta.as_object_mut() {
            object.insert("delivered_bytes".into(), Value::from(delivered));
        }
        if let Some(result) = response.get_mut("result").and_then(Value::as_object_mut) {
            result.insert(TRUNCATION_KEY.into(), meta.clone());
        }
        return Some(meta);
    }

    if response
        .get("error")
        .and_then(Value::as_object)
        .and_then(|error| error.get("message"))
        .is_some_and(Value::is_string)
    {
        let _ = shrink_largest(response, "error", budget);
    }

    let mut meta = truncation_meta(original, response);
    if response.get("result").is_none_or(Value::is_null) {
        response["result"] = Value::Object(Map::from_iter([(TRUNCATION_KEY.into(), meta.clone())]));
    }

    let delivered = serialized_size(response);
    if let Some(object) = meta.as_object_mut() {
        object.insert("delivered_bytes".into(), Value::from(delivered));
    }
    if let Some(result) = response.get_mut("result").and_then(Value::as_object_mut) {
        result.insert(TRUNCATION_KEY.into(), meta.clone());
    }
    Some(meta)
}

pub fn bound_response_default(response: &mut Value) -> Option<Value> {
    bound_response(response, RESPONSE_SOFT_LIMIT_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_json_sizing_matches_known_spacing_and_ascii_escape_rules() {
        assert_eq!(serialized_size(&json!({"a": 1})), br#"{"a": 1}"#.len());
        assert_eq!(serialized_size(&json!("é")), r#""\u00e9""#.len());
        assert_eq!(serialized_size(&json!("😀")), r#""\ud83d\ude00""#.len());
    }

    #[test]
    fn small_response_is_unchanged() {
        let mut response = json!({"type":"response","id":"x","ok":true,"result":{"x":"y"}});
        let original = response.clone();
        assert!(bound_response_default(&mut response).is_none());
        assert_eq!(response, original);
    }
}
