use crate::handler_error::{HandlerError, HandlerResult};
use regex::Regex;
use serde_json::{Map, Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
};

const PAGE_DEFAULT: usize = 50;
const PAGE_MAX: usize = 100;
const TOPICS: &[(&str, &str, &str)] = &[
    (
        "getting_started",
        "getting_started",
        "minimal first-use guidance",
    ),
    (
        "security",
        "security_model",
        "security and permission model",
    ),
    ("operations", "navigation", "operation/navigation map"),
    (
        "operating_notes",
        "operating_notes",
        "general operating notes",
    ),
    (
        "access",
        "extending_access",
        "how to extend configured access",
    ),
    (
        "hosts",
        "managing_hosts",
        "host enrollment, update, and targeting",
    ),
    ("playbooks", "playbooks", "paged playbook-name index"),
    ("policy", "policy", "policy summary counts"),
    ("examples", "examples", "example task prompts"),
    (
        "resources",
        "resources",
        "project/dashboard/contact resources",
    ),
    ("about", "about", "project/creator information"),
];

fn query(op: &str, payload: Value) -> Value {
    json!({"backend_operation": op, "payload": payload})
}

fn string_field(payload: &Map<String, Value>, key: &str) -> Result<Option<String>, HandlerError> {
    match payload.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(Some(value.trim().to_owned())),
        Some(_) => Err(HandlerError::new(
            "invalid_payload",
            format!("{key:?} must be a non-empty string"),
        )),
    }
}

fn integer(
    payload: &Map<String, Value>,
    key: &str,
    default: usize,
    minimum: usize,
    maximum: Option<usize>,
) -> Result<usize, HandlerError> {
    let value = match payload.get(key) {
        None | Some(Value::Null) => default,
        Some(Value::Number(value)) => value
            .as_u64()
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| {
                HandlerError::new("invalid_payload", format!("{key:?} must be an integer"))
            })?,
        Some(_) => {
            return Err(HandlerError::new(
                "invalid_payload",
                format!("{key:?} must be an integer"),
            ));
        }
    };
    if value < minimum || maximum.is_some_and(|maximum| value > maximum) {
        return Err(HandlerError::new(
            "invalid_payload",
            format!(
                "{key:?} must be between {minimum} and {}",
                maximum.map_or_else(|| "unbounded".into(), |value| value.to_string())
            ),
        ));
    }
    Ok(value)
}

fn page(
    values: Vec<Value>,
    payload: &Map<String, Value>,
) -> Result<(Vec<Value>, Value), HandlerError> {
    let offset = integer(payload, "offset", 0, 0, None)?;
    let limit = integer(payload, "limit", PAGE_DEFAULT, 1, Some(PAGE_MAX))?;
    let total = values.len();
    let items = values
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();
    let after = offset.saturating_add(items.len());
    let next_offset = (after < total).then_some(after);
    Ok((
        items,
        json!({
            "total": total,
            "offset": offset,
            "limit": limit,
            "next_offset": next_offset,
            "truncated": next_offset.is_some(),
        }),
    ))
}

fn lookup(root: &Value, path: &str) -> Result<Value, HandlerError> {
    let parts = path.split('.').collect::<Vec<_>>();
    if parts.iter().any(|part| part.is_empty()) {
        return Err(HandlerError::new(
            "invalid_payload",
            "path must be dot-separated object keys",
        ));
    }

    let mut node = root;
    let mut walked = Vec::new();
    for part in parts {
        let Some(map) = node.as_object() else {
            return Err(HandlerError::new(
                "invalid_payload",
                format!(
                    "help path cannot descend through non-object at {}",
                    if walked.is_empty() {
                        "<root>".into()
                    } else {
                        walked.join(".")
                    }
                ),
            ));
        };
        let Some(next) = map.get(part) else {
            let mut keys = map.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            let available_count = keys.len();
            keys.truncate(50);
            return Err(HandlerError::with_details(
                "invalid_payload",
                format!("unknown help path component: {part}"),
                Map::from_iter([
                    ("path_prefix".into(), Value::String(walked.join("."))),
                    (
                        "available_keys".into(),
                        Value::Array(keys.into_iter().map(Value::String).collect()),
                    ),
                    (
                        "available_key_count".into(),
                        Value::from(available_count as u64),
                    ),
                    (
                        "available_keys_truncated".into(),
                        Value::Bool(available_count > 50),
                    ),
                ]),
            ));
        };
        node = next;
        walked.push(part);
    }
    Ok(node.clone())
}

fn neutralize(value: Value) -> (Value, BTreeMap<String, String>) {
    fn pattern() -> &'static Regex {
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        PATTERN.get_or_init(|| Regex::new(r"\bsentinel_([a-z][a-z0-9_]*)\b").expect("valid regex"))
    }

    fn visit(value: Value, refs: &mut BTreeMap<String, String>) -> Value {
        match value {
            Value::String(text) => {
                let replaced = pattern()
                    .replace_all(&text, |captures: &regex::Captures<'_>| {
                        let source = captures.get(0).map_or("", |value| value.as_str());
                        let operation = captures.get(1).map_or("", |value| value.as_str());
                        refs.insert(source.to_owned(), operation.to_owned());
                        format!("op:{operation}")
                    })
                    .into_owned();
                Value::String(replaced)
            }
            Value::Array(items) => {
                Value::Array(items.into_iter().map(|item| visit(item, refs)).collect())
            }
            Value::Object(map) => Value::Object(
                map.into_iter()
                    .map(|(key, value)| (key, visit(value, refs)))
                    .collect(),
            ),
            other => other,
        }
    }

    let mut refs = BTreeMap::new();
    (visit(value, &mut refs), refs)
}

fn presentation(refs: BTreeMap<String, String>) -> Option<Value> {
    (!refs.is_empty()).then(|| {
        json!({
            "tool_reference_map": refs,
            "note": "Progressive guidance rewrites full-profile sentinel_* names as op:<name>. Route op:<name> through the active Hub profile.",
        })
    })
}

fn base(full: &Map<String, Value>) -> BTreeMap<String, Value> {
    BTreeMap::from([
        (
            "agent".into(),
            full.get("agent").cloned().unwrap_or(Value::Null),
        ),
        (
            "version".into(),
            full.get("version").cloned().unwrap_or(Value::Null),
        ),
        (
            "host_label".into(),
            full.get("host_label").cloned().unwrap_or(Value::Null),
        ),
    ])
}

fn project_selected(
    value: Value,
    payload: &Map<String, Value>,
) -> Result<(Value, Option<Value>), HandlerError> {
    let has_page = payload.contains_key("offset") || payload.contains_key("limit");
    if let Value::Array(items) = value {
        let (items, metadata) = page(items, payload)?;
        Ok((Value::Array(items), Some(metadata)))
    } else if has_page {
        Err(HandlerError::new(
            "invalid_payload",
            "offset/limit require a list-valued path",
        ))
    } else {
        Ok((value, None))
    }
}

pub fn capabilities_detail(payload: &Map<String, Value>) -> Result<&'static str, HandlerError> {
    let unknown = payload
        .keys()
        .filter(|key| key.as_str() != "detail")
        .cloned()
        .collect::<Vec<_>>();
    if !unknown.is_empty() {
        return Err(HandlerError::new(
            "invalid_payload",
            format!("unknown capabilities field(s): {}", unknown.join(", ")),
        ));
    }
    match payload.get("detail") {
        None | Some(Value::Null) => Ok("full"),
        Some(Value::String(value)) if value.eq_ignore_ascii_case("full") => Ok("full"),
        Some(Value::String(value)) if value.eq_ignore_ascii_case("summary") => Ok("summary"),
        _ => Err(HandlerError::new(
            "invalid_payload",
            "detail must be 'full' or 'summary'",
        )),
    }
}

pub fn select_help_response(
    payload: &Map<String, Value>,
    full: Map<String, Value>,
    playbooks: &BTreeMap<String, yaml_serde::Value>,
) -> HandlerResult {
    let allowed = BTreeSet::from(["topic", "path", "playbook", "offset", "limit"]);
    let unknown = payload
        .keys()
        .filter(|key| !allowed.contains(key.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if !unknown.is_empty() {
        return Err(HandlerError::new(
            "invalid_payload",
            format!("unknown help field(s): {}", unknown.join(", ")),
        ));
    }

    let topic = string_field(payload, "topic")?;
    let path = string_field(payload, "path")?;
    let playbook = string_field(payload, "playbook")?;
    let has_page = payload.contains_key("offset") || payload.contains_key("limit");

    if topic.is_some() && (path.is_some() || playbook.is_some()) {
        return Err(HandlerError::new(
            "invalid_payload",
            "topic is mutually exclusive with path/playbook",
        ));
    }

    if topic.is_none() && path.is_none() && playbook.is_none() {
        if has_page {
            return Err(HandlerError::new(
                "invalid_payload",
                "offset/limit require an index or list-valued path",
            ));
        }
        return Ok(full.into_iter().collect());
    }

    let full_value = Value::Object(full.clone());
    let mut result = base(&full);

    if let Some(playbook_name) = playbook {
        let Some(definition) = playbooks.get(&playbook_name) else {
            let names = playbooks
                .keys()
                .cloned()
                .map(Value::String)
                .collect::<Vec<_>>();
            let (names, metadata) = page(names, &Map::new())?;
            return Err(HandlerError::with_details(
                "invalid_payload",
                format!("unknown playbook: {playbook_name}"),
                Map::from_iter([(
                    "available_playbooks".into(),
                    json!({
                        "names": names,
                        "total": metadata["total"],
                        "offset": metadata["offset"],
                        "limit": metadata["limit"],
                        "next_offset": metadata["next_offset"],
                        "truncated": metadata["truncated"],
                    }),
                )]),
            ));
        };
        let definition = serde_json::to_value(definition).unwrap_or(Value::Null);

        if let Some(path) = path {
            let selected = lookup(&definition, &path)?;
            let (selected, pagination) = project_selected(selected, payload)?;
            let (value, refs) = neutralize(selected);
            result.insert("playbook".into(), Value::String(playbook_name.clone()));
            result.insert("path".into(), Value::String(path.clone()));
            result.insert("value".into(), value);
            if let Some(pagination) = pagination {
                let next_offset = pagination["next_offset"].as_u64();
                result.insert("pagination".into(), pagination.clone());
                if let Some(next_offset) = next_offset {
                    result.insert(
                        "next".into(),
                        query(
                            "help",
                            json!({
                                "playbook": playbook_name,
                                "path": path,
                                "offset": next_offset,
                                "limit": pagination["limit"],
                            }),
                        ),
                    );
                }
            }
            if let Some(presentation) = presentation(refs) {
                result.insert("presentation".into(), presentation);
            }
            return Ok(result);
        }

        if has_page {
            return Err(HandlerError::new(
                "invalid_payload",
                "offset/limit require a playbook subpath",
            ));
        }
        let (definition, refs) = neutralize(definition);
        result.insert("playbook".into(), Value::String(playbook_name));
        result.insert("definition".into(), definition);
        if let Some(presentation) = presentation(refs) {
            result.insert("presentation".into(), presentation);
        }
        return Ok(result);
    }

    if let Some(path) = path {
        let selected = lookup(&full_value, &path)?;
        let (selected, pagination) = project_selected(selected, payload)?;
        let (value, refs) = neutralize(selected);
        result.insert("path".into(), Value::String(path.clone()));
        result.insert("value".into(), value);
        if let Some(pagination) = pagination {
            let next_offset = pagination["next_offset"].as_u64();
            result.insert("pagination".into(), pagination.clone());
            if let Some(next_offset) = next_offset {
                result.insert(
                    "next".into(),
                    query(
                        "help",
                        json!({
                            "path": path,
                            "offset": next_offset,
                            "limit": pagination["limit"],
                        }),
                    ),
                );
            }
        }
        if let Some(presentation) = presentation(refs) {
            result.insert("presentation".into(), presentation);
        }
        return Ok(result);
    }

    let topic = topic.ok_or_else(|| HandlerError::new("invalid_payload", "topic is required"))?;
    let topic = topic.to_ascii_lowercase();

    if topic == "all" {
        if has_page {
            return Err(HandlerError::new(
                "invalid_payload",
                "topic=all does not accept offset/limit",
            ));
        }
        return Ok(full.into_iter().collect());
    }

    if topic == "index" {
        let names = playbooks
            .keys()
            .cloned()
            .map(Value::String)
            .collect::<Vec<_>>();
        let (names, metadata) = page(names, payload)?;
        let topics = TOPICS
            .iter()
            .map(|(name, _, description)| {
                ((*name).to_owned(), Value::String((*description).into()))
            })
            .collect::<Map<_, _>>();
        result.insert(
            "summary".into(),
            full.get("summary").cloned().unwrap_or(Value::Null),
        );
        result.insert("topics".into(), Value::Object(topics));
        result.insert(
            "path_examples".into(),
            json!([
                "security_model.permission_errors",
                "security_model.allowlist_errors",
                "navigation.exec",
                "managing_hosts.targeting",
            ]),
        );
        result.insert(
            "playbooks".into(),
            json!({
                "names": names,
                "total": metadata["total"],
                "offset": metadata["offset"],
                "limit": metadata["limit"],
                "next_offset": metadata["next_offset"],
                "truncated": metadata["truncated"],
            }),
        );
        result.insert(
            "next".into(),
            json!({
                "topic": query("help", json!({"topic": "security"})),
                "path": query("help", json!({"path": "security_model.permission_errors"})),
                "playbook": query("help", json!({"playbook": "<name>"})),
                "next_page": metadata["next_offset"].as_u64().map(|next_offset| {
                    query(
                        "help",
                        json!({
                            "topic": "index",
                            "offset": next_offset,
                            "limit": metadata["limit"],
                        }),
                    )
                }),
                "full": query("help", json!({"topic": "all"})),
            }),
        );
        return Ok(result);
    }

    let Some((_, key, _)) = TOPICS.iter().find(|(name, _, _)| *name == topic) else {
        return Err(HandlerError::with_details(
            "invalid_payload",
            format!("unknown help topic: {topic}"),
            Map::from_iter([(
                "available_topics".into(),
                Value::Array(
                    std::iter::once("index")
                        .chain(TOPICS.iter().map(|(name, _, _)| *name))
                        .chain(std::iter::once("all"))
                        .map(|name| Value::String(name.into()))
                        .collect(),
                ),
            )]),
        ));
    };

    if topic == "playbooks" {
        let names = playbooks
            .keys()
            .cloned()
            .map(Value::String)
            .collect::<Vec<_>>();
        let (names, metadata) = page(names, payload)?;
        result.insert("topic".into(), Value::String(topic));
        result.insert(
            "playbooks".into(),
            json!({
                "names": names,
                "total": metadata["total"],
                "offset": metadata["offset"],
                "limit": metadata["limit"],
                "next_offset": metadata["next_offset"],
                "truncated": metadata["truncated"],
            }),
        );
        result.insert(
            "next".into(),
            json!({
                "playbook": query("help", json!({"playbook": "<name>"})),
                "next_page": metadata["next_offset"].as_u64().map(|next_offset| {
                    query(
                        "help",
                        json!({
                            "topic": "playbooks",
                            "offset": next_offset,
                            "limit": metadata["limit"],
                        }),
                    )
                }),
            }),
        );
        return Ok(result);
    }

    if has_page {
        return Err(HandlerError::new(
            "invalid_payload",
            "offset/limit are valid only for paged lists",
        ));
    }

    let value = full.get(*key).cloned().unwrap_or(Value::Null);
    let (value, refs) = neutralize(value);
    result.insert("topic".into(), Value::String(topic));
    result.insert((*key).into(), value);
    if let Some(presentation) = presentation(refs) {
        result.insert("presentation".into(), presentation);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> Map<String, Value> {
        Map::from_iter([
            ("agent".into(), Value::String("sentinelx-cloud-core".into())),
            ("version".into(), Value::String("test".into())),
            ("host_label".into(), Value::String("host".into())),
            ("summary".into(), Value::String("summary".into())),
            (
                "security_model".into(),
                json!({"permission_errors": "explain", "allowlist_errors": "explain"}),
            ),
            ("navigation".into(), json!({"exec": "sentinel_exec"})),
            ("playbooks".into(), json!({"names": ["a", "b"]})),
        ])
    }

    #[test]
    fn path_selects_nested_value_and_neutralizes_tool_names() {
        let payload = Map::from_iter([("path".into(), Value::String("navigation.exec".into()))]);
        let result = select_help_response(&payload, full(), &BTreeMap::new()).unwrap();
        assert_eq!(result["value"], "op:exec");
        assert_eq!(
            result["presentation"]["tool_reference_map"]["sentinel_exec"],
            "exec"
        );
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let payload = Map::from_iter([("wat".into(), Value::Bool(true))]);
        assert_eq!(
            select_help_response(&payload, full(), &BTreeMap::new())
                .unwrap_err()
                .code,
            "invalid_payload"
        );
    }

    #[test]
    fn capabilities_detail_is_strict() {
        assert_eq!(capabilities_detail(&Map::new()).unwrap(), "full");
        assert_eq!(
            capabilities_detail(&Map::from_iter([(
                "detail".into(),
                Value::String("SUMMARY".into()),
            )]))
            .unwrap(),
            "summary"
        );
        assert!(
            capabilities_detail(&Map::from_iter([(
                "detail".into(),
                Value::String("tiny".into()),
            )]))
            .is_err()
        );
    }
}
