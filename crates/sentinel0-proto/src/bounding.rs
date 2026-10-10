use num_traits::ToPrimitive;
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
        Value::Null | Value::Bool(true) => 4,
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
                if valid > 0
                    && let Ok(prefix) = std::str::from_utf8(&bytes[..valid])
                {
                    out.push_str(prefix);
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

fn usize_to_f64(value: usize) -> f64 {
    value.to_f64().unwrap_or(f64::MAX)
}

fn nonnegative_f64_to_usize(value: f64) -> usize {
    value.to_usize().unwrap_or(usize::MAX)
}

fn truncate_text(text: &str, keep_bytes: usize) -> String {
    let raw = text.as_bytes();
    let original = raw.len();
    if original <= keep_bytes || keep_bytes == 0 {
        return text.to_owned();
    }

    let head_budget = nonnegative_f64_to_usize(usize_to_f64(keep_bytes) * RESPONSE_HEAD_RATIO);
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

#[derive(Clone, Debug, PartialEq, Eq)]
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

fn largest_container_path(root: &Value) -> Option<(Vec<PathPart>, usize)> {
    fn visit(node: &Value, path: &mut Vec<PathPart>, best: &mut Option<(Vec<PathPart>, usize)>) {
        match node {
            Value::Object(map) => {
                for (key, value) in map {
                    path.push(PathPart::Key(key.clone()));
                    if matches!(value, Value::Object(map) if map.len() >= 2)
                        || matches!(value, Value::Array(items) if items.len() >= 2)
                    {
                        let size = serialized_size(value);
                        if best.as_ref().is_none_or(|(_, best_size)| size > *best_size) {
                            *best = Some((path.clone(), size));
                        }
                    }
                    if matches!(value, Value::Object(_) | Value::Array(_)) {
                        visit(value, path, best);
                    }
                    path.pop();
                }
            }
            Value::Array(items) => {
                for (index, value) in items.iter().enumerate() {
                    path.push(PathPart::Index(index));
                    if matches!(value, Value::Object(map) if map.len() >= 2)
                        || matches!(value, Value::Array(items) if items.len() >= 2)
                    {
                        let size = serialized_size(value);
                        if best.as_ref().is_none_or(|(_, best_size)| size > *best_size) {
                            *best = Some((path.clone(), size));
                        }
                    }
                    if matches!(value, Value::Object(_) | Value::Array(_)) {
                        visit(value, path, best);
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

fn value_at<'a>(mut value: &'a Value, path: &[PathPart]) -> Option<&'a Value> {
    for part in path {
        value = match part {
            PathPart::Key(key) => value.as_object()?.get(key)?,
            PathPart::Index(index) => value.as_array()?.get(*index)?,
        };
    }
    Some(value)
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

fn container_len(value: &Value) -> Option<usize> {
    match value {
        Value::Array(items) => Some(items.len()),
        Value::Object(map) => Some(map.len()),
        _ => None,
    }
}

fn trim_container(value: &mut Value, keep: usize) -> bool {
    match value {
        Value::Array(items) => {
            if items.len() <= keep {
                return false;
            }
            items.truncate(keep);
            true
        }
        Value::Object(map) => {
            if map.len() <= keep {
                return false;
            }
            let retained = std::mem::take(map).into_iter().take(keep).collect();
            *map = retained;
            true
        }
        _ => false,
    }
}

#[derive(Clone, Debug)]
struct Omission {
    path: Vec<PathPart>,
    total: usize,
    kept: usize,
}

fn record_omission(omitted: &mut Vec<Omission>, path: &[PathPart], total: usize, kept: usize) {
    if let Some(existing) = omitted.iter_mut().find(|entry| entry.path == path) {
        existing.kept = kept;
    } else {
        omitted.push(Omission {
            path: path.to_vec(),
            total,
            kept,
        });
    }
}

fn shrink_largest(
    response: &mut Value,
    root_key: &str,
    budget: usize,
    mut omitted: Option<&mut Vec<Omission>>,
) -> bool {
    for _ in 0..MAX_PASSES {
        let current = serialized_size(response);
        if current <= budget {
            return true;
        }

        let Some(root) = response.get(root_key) else {
            return false;
        };
        let string_ref = largest_string_path(root);
        let container_ref = largest_container_path(root);
        if string_ref.is_none() && container_ref.is_none() {
            return false;
        }

        if let Some((path, container_size)) = container_ref
            && string_ref
                .as_ref()
                .is_none_or(|(_, string_size)| container_size > *string_size)
        {
            let Some(root) = response.get(root_key) else {
                return false;
            };
            let Some(target) = value_at(root, &path) else {
                return false;
            };
            let Some(n_items) = container_len(target) else {
                return false;
            };
            if n_items < 2 {
                return false;
            }
            let proportional = nonnegative_f64_to_usize(
                usize_to_f64(n_items)
                    * (usize_to_f64(budget) / usize_to_f64(current))
                    * SHRINK_SLACK,
            );
            let keep = proportional.max(1).min(n_items - 1);
            let Some(target) = response
                .get_mut(root_key)
                .and_then(|root| value_at_mut(root, &path))
            else {
                return false;
            };
            if !trim_container(target, keep) {
                return false;
            }
            if let Some(omitted) = omitted.as_deref_mut() {
                record_omission(omitted, &path, n_items, keep);
            }
            continue;
        }

        let Some((path, raw_len)) = string_ref else {
            return false;
        };
        let proportional = nonnegative_f64_to_usize(
            usize_to_f64(raw_len) * (usize_to_f64(budget) / usize_to_f64(current)) * SHRINK_SLACK,
        );
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

fn json_pointer(path: &[PathPart]) -> String {
    let mut pointer = String::new();
    for part in path {
        pointer.push('/');
        let raw = match part {
            PathPart::Key(key) => key.clone(),
            PathPart::Index(index) => index.to_string(),
        };
        pointer.push_str(&raw.replace('~', "~0").replace('/', "~1"));
    }
    pointer
}

fn omitted_meta(root: &Value, omitted: &[Omission]) -> Vec<Value> {
    let mut entries = omitted
        .iter()
        .filter(|entry| value_at(root, &entry.path).is_some())
        .map(|entry| {
            json!({
                "path": json_pointer(&entry.path),
                "kept": entry.kept,
                "omitted": entry.total.saturating_sub(entry.kept),
            })
        })
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| {
        std::cmp::Reverse(
            entry
                .get("omitted")
                .and_then(Value::as_u64)
                .unwrap_or_default(),
        )
    });
    entries
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

fn insert_meta(response: &mut Value, meta: &Value) {
    if let Some(result) = response.get_mut("result").and_then(Value::as_object_mut) {
        result.insert(TRUNCATION_KEY.into(), meta.clone());
    }
}

pub fn bound_response(response: &mut Value, soft_limit: usize) -> Option<Value> {
    const OMITTED_MAX_ENTRIES: usize = 20;

    let original = serialized_size(response);
    if original <= soft_limit {
        return None;
    }

    let budget = soft_limit.saturating_sub(META_RESERVE);

    if response.get("result").is_some_and(Value::is_object) {
        let mut omitted = Vec::new();
        if !shrink_largest(response, "result", budget, Some(&mut omitted)) {
            response["result"] = json!({"note": "result omitted: too large to bound field-wise"});
            omitted.clear();
        }

        let mut meta = truncation_meta(original, response);
        if let Some(result) = response.get("result") {
            let entries = omitted_meta(result, &omitted);
            if !entries.is_empty()
                && let Some(object) = meta.as_object_mut()
            {
                object.insert(
                    "omitted".into(),
                    Value::Array(entries.iter().take(OMITTED_MAX_ENTRIES).cloned().collect()),
                );
                if entries.len() > OMITTED_MAX_ENTRIES {
                    object.insert(
                        "omitted_more".into(),
                        Value::from(entries.len() - OMITTED_MAX_ENTRIES),
                    );
                }
            }
        }
        insert_meta(response, &meta);

        loop {
            if serialized_size(response) <= soft_limit {
                break;
            }
            let popped = meta
                .as_object_mut()
                .and_then(|object| object.get_mut("omitted"))
                .and_then(Value::as_array_mut)
                .and_then(Vec::pop);
            if popped.is_none() {
                break;
            }
            if let Some(object) = meta.as_object_mut() {
                let more = object
                    .get("omitted_more")
                    .and_then(Value::as_u64)
                    .unwrap_or_default()
                    .saturating_add(1);
                object.insert("omitted_more".into(), Value::from(more));
            }
            insert_meta(response, &meta);
        }

        let delivered = serialized_size(response);
        if let Some(object) = meta.as_object_mut() {
            object.insert("delivered_bytes".into(), Value::from(delivered));
        }
        insert_meta(response, &meta);
        return Some(meta);
    }

    if response
        .get("error")
        .and_then(Value::as_object)
        .and_then(|error| error.get("message"))
        .is_some_and(Value::is_string)
    {
        let _ = shrink_largest(response, "error", budget, None);
    }

    let mut meta = truncation_meta(original, response);
    if response.get("result").is_none_or(Value::is_null) {
        response["result"] = Value::Object(Map::from_iter([(TRUNCATION_KEY.into(), meta.clone())]));
    }

    let delivered = serialized_size(response);
    if let Some(object) = meta.as_object_mut() {
        object.insert("delivered_bytes".into(), Value::from(delivered));
    }
    insert_meta(response, &meta);
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

    #[test]
    fn long_lists_are_trimmed_without_changing_item_types() {
        let items = (0..20_000)
            .map(|id| json!({"id": id, "name": format!("item-{id}")}))
            .collect::<Vec<_>>();
        let mut response = json!({
            "type": "response",
            "id": "list",
            "ok": true,
            "result": {"items": items},
        });
        let meta = bound_response(&mut response, 16_384).unwrap_or(Value::Null);
        assert!(
            response["result"]["items"]
                .as_array()
                .is_some_and(|kept| !kept.is_empty() && kept.iter().all(Value::is_object))
        );
        assert!(
            meta["omitted"]
                .as_array()
                .is_some_and(|entries| !entries.is_empty())
        );
        assert_eq!(meta["omitted"][0]["path"], "/items");
        assert!(serialized_size(&response) <= 16_384);
    }

    #[test]
    fn dict_heavy_results_keep_the_result_shape_and_report_omissions() {
        let services = (0..2_000)
            .map(|id| {
                (
                    format!("svc-{id:04}"),
                    json!({
                        "actions": ["status", "restart"],
                        "description": "d".repeat(80),
                    }),
                )
            })
            .collect::<Map<_, _>>();
        let mut response = json!({
            "type": "response",
            "id": "caps",
            "ok": true,
            "result": {"version": "x", "services": services, "ops_supported": ["state", "help"]},
        });
        let meta = bound_response(&mut response, 24_576).unwrap_or(Value::Null);
        assert_eq!(response["result"]["version"], "x");
        assert!(response["result"]["services"].is_object());
        assert!(response["result"].get("note").is_none());
        assert!(
            meta["omitted"]
                .as_array()
                .is_some_and(|entries| entries.iter().any(|entry| entry["path"] == "/services"))
        );
        assert!(serialized_size(&response) <= 24_576);
    }

    #[test]
    fn omission_paths_are_json_pointers() {
        assert_eq!(
            json_pointer(&[
                PathPart::Key("a/b".into()),
                PathPart::Key("c~d".into()),
                PathPart::Index(3),
            ]),
            "/a~1b/c~0d/3"
        );
    }
}
