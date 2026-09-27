use crate::{
    handler_error::{HandlerError, HandlerResult},
    policy::Policy,
    process_output::capture_bounded,
};
use serde_json::{Map, Value, json};
use std::{
    collections::BTreeMap,
    io::{Read as _, Write as _},
    path::Path,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    process::Command,
    time::timeout,
};

const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

fn relay_command(
    policy: &Policy,
    endpoint: &Endpoint,
    executable: &Path,
) -> Result<Vec<String>, HandlerError> {
    let user = endpoint.run_as.as_deref().ok_or_else(|| {
        HandlerError::new("internal_error", "relay requested without run_as user")
    })?;
    Ok(vec![
        policy.tooling.command("sudo").display().to_string(),
        "-n".into(),
        "-u".into(),
        user.into(),
        executable.display().to_string(),
        "--local-api-relay".into(),
        endpoint.path.clone(),
        "--relay-timeout".into(),
        endpoint.timeout.as_secs_f64().to_string(),
    ])
}

pub fn run_local_api_relay(path: &Path, timeout_seconds: f64) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::net::UnixStream as StdUnixStream;

        let timeout = Duration::from_secs_f64(timeout_seconds.clamp(0.1, 300.0));
        let mut payload = Vec::new();
        if let Err(error) = std::io::stdin()
            .take((MAX_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut payload)
        {
            eprintln!("stdin read failed: {error}");
            return 2;
        }
        if payload.is_empty() {
            eprintln!("nothing to send");
            return 2;
        }
        if payload.len() > MAX_RESPONSE_BYTES {
            eprintln!("request exceeded the cap");
            return 4;
        }

        let mut stream = match StdUnixStream::connect(path) {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("connect failed: {error}");
                return 3;
            }
        };
        if let Err(error) = stream.set_read_timeout(Some(timeout)) {
            eprintln!("could not set relay read timeout: {error}");
            return 3;
        }
        if let Err(error) = stream.set_write_timeout(Some(timeout)) {
            eprintln!("could not set relay write timeout: {error}");
            return 3;
        }

        if let Err(error) = stream.write_all(&payload) {
            eprintln!("relay failed: {error}");
            return 3;
        }

        let mut reply = Vec::new();
        let mut chunk = [0_u8; 65_536];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(count) => {
                    let take = chunk[..count]
                        .iter()
                        .position(|byte| *byte == b'\n')
                        .map_or(count, |index| index + 1);
                    reply.extend_from_slice(&chunk[..take]);
                    if reply.len() > MAX_RESPONSE_BYTES {
                        eprintln!("reply exceeded the cap");
                        return 4;
                    }
                    if take < count || reply.ends_with(b"\n") {
                        break;
                    }
                }
                Err(error) => {
                    eprintln!("relay failed: {error}");
                    return 3;
                }
            }
        }

        if let Err(error) = std::io::stdout().write_all(&reply) {
            eprintln!("stdout write failed: {error}");
            return 3;
        }
        0
    }

    #[cfg(not(unix))]
    {
        drop((path, timeout_seconds));
        eprintln!("local_api relay requires a Unix-domain socket");
        3
    }
}

#[derive(Debug, Clone)]
struct Action {
    request: Option<String>,
    method: Option<String>,
    select: Vec<String>,
    description: Option<String>,
    params_schema: Option<Value>,
}

#[derive(Debug, Clone)]
struct Endpoint {
    name: String,
    transport: String,
    protocol: String,
    path: String,
    timeout: Duration,
    run_as: Option<String>,
    actions: BTreeMap<String, Action>,
    compatibility: Option<Value>,
}

fn reject_unknown_keys(
    map: &Map<String, Value>,
    allowed: &[&str],
    context: &str,
) -> Result<(), String> {
    if let Some(key) = map.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(format!("{context} contains unknown key {key:?}"));
    }
    Ok(())
}

fn yaml_to_json(value: &yaml_serde::Value) -> Result<Value, String> {
    serde_json::to_value(value)
        .map_err(|error| format!("could not decode endpoint config: {error}"))
}

fn valid_compatibility(value: Option<&Value>, protocol: &str) -> Result<Option<Value>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value
        .as_object()
        .ok_or_else(|| "compatibility must be an object".to_owned())?;
    reject_unknown_keys(value, &["probe", "extract", "accept"], "compatibility")?;
    let probe = value
        .get("probe")
        .and_then(Value::as_object)
        .ok_or_else(|| "compatibility.probe must be an object".to_owned())?;
    let probe_keys: &[&str] = match protocol {
        "http" => &["request"],
        "jsonrpc" => &["method"],
        _ => &[],
    };
    reject_unknown_keys(probe, probe_keys, "compatibility.probe")?;
    let extract = value
        .get("extract")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "compatibility.extract must be a non-empty string".to_owned())?;
    let accept = value
        .get("accept")
        .and_then(Value::as_object)
        .ok_or_else(|| "compatibility.accept must be an object".to_owned())?;
    reject_unknown_keys(accept, &["exact", "allowed"], "compatibility.accept")?;
    let has_exact = accept.contains_key("exact");
    let has_allowed = accept
        .get("allowed")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty());
    if has_exact == has_allowed {
        return Err(
            "compatibility.accept must contain exactly one of: exact, non-empty allowed".into(),
        );
    }

    let probe_ok = match protocol {
        "http" => probe
            .get("request")
            .and_then(Value::as_str)
            .is_some_and(|request| !request.trim().is_empty()),
        "jsonrpc" => probe
            .get("method")
            .and_then(Value::as_str)
            .is_some_and(|method| !method.trim().is_empty()),
        _ => false,
    };
    if !probe_ok {
        return Err(format!(
            "compatibility.probe is missing the field required by protocol {protocol:?}"
        ));
    }
    let _ = extract;
    Ok(Some(Value::Object(value.clone())))
}

fn endpoint_from_raw(name: &str, raw: &yaml_serde::Value) -> Result<Endpoint, String> {
    let value = yaml_to_json(raw)?;
    let map = value
        .as_object()
        .ok_or_else(|| format!("local_apis.{name} must be an object"))?;
    reject_unknown_keys(
        map,
        &[
            "transport",
            "protocol",
            "path",
            "timeout_s",
            "run_as",
            "compatibility",
            "actions",
        ],
        &format!("local_apis.{name}"),
    )?;
    let transport = map
        .get("transport")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("local_apis.{name}.transport is required"))?
        .to_owned();
    if transport != "unix" {
        return Err(format!(
            "local_apis.{name}.transport={transport:?} is unsupported; the Rust agent currently supports only unix"
        ));
    }
    let protocol = map
        .get("protocol")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("local_apis.{name}.protocol is required"))?
        .to_owned();
    if !matches!(protocol.as_str(), "http" | "jsonrpc") {
        return Err(format!(
            "local_apis.{name}.protocol must be http or jsonrpc, got {protocol:?}"
        ));
    }
    let path = map
        .get("path")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("local_apis.{name}.path is required"))?
        .to_owned();

    let raw_actions = map
        .get("actions")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("local_apis.{name}.actions must be an object"))?;
    if raw_actions.is_empty() {
        return Err(format!("local_apis.{name}.actions must not be empty"));
    }

    let mut actions = BTreeMap::new();
    for (action_name, raw_action) in raw_actions {
        let action = raw_action
            .as_object()
            .ok_or_else(|| format!("local_apis.{name}.actions.{action_name} must be an object"))?;
        reject_unknown_keys(
            action,
            &["request", "method", "select", "description", "params"],
            &format!("local_apis.{name}.actions.{action_name}"),
        )?;
        let request = action
            .get("request")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let method = action
            .get("method")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if protocol == "http"
            && request
                .as_deref()
                .is_none_or(|request| request.trim().is_empty())
        {
            return Err(format!(
                "local_apis.{name}.actions.{action_name}.request is required for HTTP"
            ));
        }
        if protocol == "jsonrpc"
            && method
                .as_deref()
                .is_none_or(|method| method.trim().is_empty())
        {
            return Err(format!(
                "local_apis.{name}.actions.{action_name}.method is required for JSON-RPC"
            ));
        }

        let select = match action.get("select") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| {
                    item.as_str().map(str::to_owned).ok_or_else(|| {
                        format!(
                            "local_apis.{name}.actions.{action_name}.select must contain only strings"
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => {
                return Err(format!(
                    "local_apis.{name}.actions.{action_name}.select must be an array"
                ));
            }
        };
        let params_schema = match action.get("params") {
            None | Some(Value::Null) => None,
            Some(Value::Object(_)) => action.get("params").cloned(),
            Some(_) => {
                return Err(format!(
                    "local_apis.{name}.actions.{action_name}.params must be an object"
                ));
            }
        };
        actions.insert(
            action_name.clone(),
            Action {
                request,
                method,
                select,
                description: match action.get("description") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(value)) => Some(value.clone()),
                    Some(_) => {
                        return Err(format!(
                            "local_apis.{name}.actions.{action_name}.description must be a string"
                        ));
                    }
                },
                params_schema,
            },
        );
    }

    let timeout_seconds = match map.get("timeout_s") {
        None | Some(Value::Null) => 30.0,
        Some(value) => value
            .as_f64()
            .filter(|value| value.is_finite() && *value >= 0.1 && *value <= 300.0)
            .ok_or_else(|| {
                format!("local_apis.{name}.timeout_s must be between 0.1 and 300 seconds")
            })?,
    };
    let compatibility = valid_compatibility(map.get("compatibility"), &protocol)
        .map_err(|error| format!("local_apis.{name}.{error}"))?;
    Ok(Endpoint {
        name: name.to_owned(),
        transport,
        protocol,
        path,
        timeout: Duration::from_secs_f64(timeout_seconds),
        run_as: match map.get("run_as") {
            None | Some(Value::Null) => None,
            Some(Value::String(value)) if !value.trim().is_empty() => Some(value.trim().to_owned()),
            Some(Value::String(_)) => None,
            Some(_) => {
                return Err(format!("local_apis.{name}.run_as must be a string"));
            }
        },
        actions,
        compatibility,
    })
}

fn endpoints(policy: &Policy) -> Result<BTreeMap<String, Endpoint>, HandlerError> {
    policy
        .local_apis
        .iter()
        .map(|(name, raw)| {
            endpoint_from_raw(name, raw)
                .map(|endpoint| (name.clone(), endpoint))
                .map_err(|message| HandlerError::new("invalid_config", message))
        })
        .collect()
}

pub(crate) fn validate_config(
    local_apis: &BTreeMap<String, yaml_serde::Value>,
) -> Result<(), String> {
    for (name, raw) in local_apis {
        endpoint_from_raw(name, raw)?;
    }
    Ok(())
}

#[must_use]
pub fn has_usable_endpoints(policy: &Policy) -> bool {
    match endpoints(policy) {
        Ok(endpoints) => !endpoints.is_empty(),
        Err(error) => {
            tracing::error!(message = %error.message, "invalid local_api config reached runtime");
            false
        }
    }
}

fn param_names(action: &Action) -> Vec<String> {
    if let Some(schema) = action.params_schema.as_ref().and_then(Value::as_object)
        && let Some(properties) = schema.get("properties").and_then(Value::as_object)
    {
        let required = schema
            .get("required")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|name| properties.contains_key(*name))
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let mut rest = properties
            .keys()
            .filter(|name| !required.contains(name))
            .cloned()
            .collect::<Vec<_>>();
        rest.sort();
        let mut names = required;
        names.extend(rest);
        return names;
    }
    let mut names = Vec::new();
    if let Some(request) = action.request.as_deref() {
        let bytes = request.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'{'
                && let Some(end) = request[index + 1..].find('}')
            {
                let name = &request[index + 1..index + 1 + end];
                if !name.is_empty() && !names.iter().any(|existing| existing == name) {
                    names.push(name.to_owned());
                }
                index += end + 2;
                continue;
            }
            index += 1;
        }
    }
    names.sort();
    names
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                vec![byte as char]
            } else {
                format!("%{byte:02X}").chars().collect::<Vec<_>>()
            }
        })
        .collect()
}

fn render(template: &str, params: &Map<String, Value>) -> Result<String, HandlerError> {
    let mut output = template.to_owned();
    for (key, value) in params {
        let value = value
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| value.to_string());
        output = output.replace(&format!("{{{key}}}"), &percent_encode(&value));
    }
    if let Some(start) = output.find('{')
        && let Some(end) = output[start + 1..].find('}')
    {
        let missing = &output[start + 1..start + 1 + end];
        return Err(HandlerError::new(
            "missing_param",
            format!("the action needs a value for {missing:?}"),
        ));
    }
    Ok(output)
}

fn project(data: Value, select: &[String]) -> Value {
    if select.is_empty() {
        return data;
    }
    match data {
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| project(item, select))
                .collect(),
        ),
        Value::Object(map) => {
            let mut output = Map::new();
            for spec in select {
                let mut current = Value::Object(map.clone());
                let mut found = true;
                for part in spec.split('.') {
                    let Some(next) = current.as_object().and_then(|map| map.get(part)).cloned()
                    else {
                        found = false;
                        break;
                    };
                    current = next;
                }
                if found && !current.is_null() {
                    output.insert(spec.clone(), current);
                }
            }
            Value::Object(output)
        }
        other => other,
    }
}

async fn connect(endpoint: &Endpoint) -> Result<UnixStream, HandlerError> {
    if endpoint.transport != "unix" {
        return Err(HandlerError::new(
            "endpoint_unreachable",
            format!(
                "transport {:?} is not available in the Rust compatibility agent",
                endpoint.transport
            ),
        ));
    }
    timeout(
        endpoint.timeout,
        UnixStream::connect(Path::new(&endpoint.path)),
    )
    .await
    .map_err(|_| HandlerError::new("timeout", format!("timed out opening {}", endpoint.path)))?
    .map_err(|error| {
        HandlerError::new(
            "endpoint_unreachable",
            format!("cannot open {}: {error}", endpoint.path),
        )
    })
}

async fn read_until_bounded<R>(
    reader: &mut R,
    delimiter: u8,
    max_bytes: usize,
    label: &'static str,
) -> Result<Vec<u8>, HandlerError>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let mut out = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|error| HandlerError::new("bad_response", error.to_string()))?;
        if available.is_empty() {
            return Ok(out);
        }
        let take = available
            .iter()
            .position(|byte| *byte == delimiter)
            .map_or(available.len(), |index| index + 1);
        if out.len().saturating_add(take) > max_bytes {
            return Err(HandlerError::new(
                "too_large",
                format!("{label} exceeded the cap of {max_bytes} bytes"),
            ));
        }
        out.extend_from_slice(&available[..take]);
        reader.consume(take);
        if out.last() == Some(&delimiter) {
            return Ok(out);
        }
    }
}

async fn read_http_body(stream: UnixStream) -> Result<Value, HandlerError> {
    const MAX_HEADER_BYTES: usize = 128 * 1024;
    const MAX_HEADER_LINE_BYTES: usize = 16 * 1024;

    let mut reader = BufReader::new(stream);
    let mut header = Vec::new();
    loop {
        let remaining = MAX_HEADER_BYTES.saturating_sub(header.len());
        if remaining == 0 {
            return Err(HandlerError::new("too_large", "HTTP headers exceeded cap"));
        }
        let line = read_until_bounded(
            &mut reader,
            b'\n',
            remaining.min(MAX_HEADER_LINE_BYTES),
            "HTTP header line",
        )
        .await?;
        if line.is_empty() {
            return Err(HandlerError::new(
                "bad_response",
                "endpoint closed before HTTP headers completed",
            ));
        }
        let blank = line == b"\r\n" || line == b"\n";
        header.extend_from_slice(&line);
        if blank {
            break;
        }
    }

    let head = String::from_utf8_lossy(&header);
    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| {
            HandlerError::new(
                "bad_response",
                format!("unparseable HTTP status: {status_line:?}"),
            )
        })?;

    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            let parsed = value
                .trim()
                .parse::<usize>()
                .map_err(|_| HandlerError::new("bad_response", "invalid Content-Length header"))?;
            if content_length.is_some_and(|existing| existing != parsed) {
                return Err(HandlerError::new(
                    "bad_response",
                    "conflicting Content-Length headers",
                ));
            }
            content_length = Some(parsed);
        }
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value
                .split(',')
                .any(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"))
        {
            chunked = true;
        }
    }

    let body = if chunked {
        let mut body = Vec::new();
        loop {
            let size_line =
                read_until_bounded(&mut reader, b'\n', 8192, "HTTP chunk-size line").await?;
            if size_line.is_empty() {
                return Err(HandlerError::new(
                    "bad_response",
                    "endpoint closed before chunk size",
                ));
            }
            let size_line = String::from_utf8_lossy(&size_line);
            let size_text = size_line.trim().split(';').next().unwrap_or("0");
            let size = usize::from_str_radix(size_text, 16)
                .map_err(|_| HandlerError::new("bad_response", "invalid chunk size"))?;
            if size == 0 {
                let mut trailer_bytes = 0_usize;
                loop {
                    let trailer =
                        read_until_bounded(&mut reader, b'\n', 16 * 1024, "HTTP trailer line")
                            .await?;
                    if trailer.is_empty() {
                        return Err(HandlerError::new(
                            "bad_response",
                            "endpoint closed inside HTTP trailers",
                        ));
                    }
                    trailer_bytes = trailer_bytes.saturating_add(trailer.len());
                    if trailer_bytes > MAX_HEADER_BYTES {
                        return Err(HandlerError::new("too_large", "HTTP trailers exceeded cap"));
                    }
                    if trailer == b"\r\n" || trailer == b"\n" {
                        break;
                    }
                }
                break;
            }
            if body.len().saturating_add(size) > MAX_RESPONSE_BYTES {
                return Err(HandlerError::new(
                    "too_large",
                    "endpoint response exceeded the cap",
                ));
            }
            let start = body.len();
            body.resize(start + size, 0);
            reader
                .read_exact(&mut body[start..])
                .await
                .map_err(|error| HandlerError::new("bad_response", error.to_string()))?;
            let mut crlf = [0_u8; 2];
            reader
                .read_exact(&mut crlf)
                .await
                .map_err(|error| HandlerError::new("bad_response", error.to_string()))?;
            if crlf != *b"\r\n" {
                return Err(HandlerError::new(
                    "bad_response",
                    "chunk payload was not followed by CRLF",
                ));
            }
        }
        body
    } else if let Some(length) = content_length {
        if length > MAX_RESPONSE_BYTES {
            return Err(HandlerError::new(
                "too_large",
                "endpoint response exceeded the cap",
            ));
        }
        let mut body = vec![0_u8; length];
        if length != 0 {
            reader
                .read_exact(&mut body)
                .await
                .map_err(|error| HandlerError::new("bad_response", error.to_string()))?;
        }
        body
    } else {
        let mut body = Vec::new();
        let mut limited = reader.take((MAX_RESPONSE_BYTES + 1) as u64);
        limited
            .read_to_end(&mut body)
            .await
            .map_err(|error| HandlerError::new("bad_response", error.to_string()))?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(HandlerError::new(
                "too_large",
                "endpoint response exceeded the cap",
            ));
        }
        body
    };

    if status >= 400 {
        return Err(HandlerError::new(
            "endpoint_error",
            format!(
                "endpoint answered HTTP {status}: {}",
                String::from_utf8_lossy(&body)
                    .chars()
                    .take(200)
                    .collect::<String>()
            ),
        ));
    }
    if body.is_empty() {
        Ok(Value::Null)
    } else {
        serde_json::from_slice(&body)
            .map_err(|_| HandlerError::new("bad_response", "endpoint did not return JSON"))
    }
}

async fn call_http(
    endpoint: &Endpoint,
    action: &Action,
    params: &Map<String, Value>,
) -> Result<Value, HandlerError> {
    let request = action.request.as_deref().unwrap_or("").trim();
    let (method, target) = request.split_once(' ').ok_or_else(|| {
        HandlerError::new(
            "bad_action",
            format!("request must look like 'GET /path', got {request:?}"),
        )
    })?;
    let target = render(target.trim(), params)?;
    let mut stream = connect(endpoint).await?;
    let wire = format!(
        "{} {} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        method.to_ascii_uppercase(),
        target
    );
    timeout(endpoint.timeout, stream.write_all(wire.as_bytes()))
        .await
        .map_err(|_| HandlerError::new("timeout", "timed out writing request"))?
        .map_err(|e| HandlerError::new("endpoint_unreachable", e.to_string()))?;
    timeout(endpoint.timeout, read_http_body(stream))
        .await
        .map_err(|_| HandlerError::new("timeout", "endpoint did not answer in time"))?
}

async fn kill_and_reap_relay(
    child: &mut tokio::process::Child,
    pid: Option<u32>,
    reason: &'static str,
) -> Option<String> {
    let mut cleanup_error = None;
    let should_kill = match child.try_wait() {
        Ok(Some(_)) => false,
        Ok(None) => true,
        Err(error) => {
            let message = format!(
                "failed checking local-api relay state after {reason}: {error}; refusing PID-based group signal"
            );
            tracing::warn!(%message);
            cleanup_error = Some(message);
            false
        }
    };

    #[cfg(unix)]
    if should_kill {
        if let Some(pid) = pid {
            let pgid = nix::unistd::Pid::from_raw(pid as i32);
            if let Err(error) = nix::sys::signal::killpg(pgid, nix::sys::signal::Signal::SIGKILL)
                && error != nix::errno::Errno::ESRCH
            {
                let message = format!("failed killing local-api relay process group: {error}");
                tracing::warn!(%message);
                cleanup_error.get_or_insert(message);
            }
        } else {
            cleanup_error.get_or_insert_with(|| {
                "local-api relay PID was unavailable; process group could not be killed".into()
            });
        }
    }

    #[cfg(not(unix))]
    if should_kill && let Err(error) = child.kill().await {
        let message = format!("failed killing local-api relay: {error}");
        tracing::warn!(%message);
        cleanup_error.get_or_insert(message);
    }

    if let Err(error) = child.wait().await {
        let message = format!("failed reaping local-api relay: {error}");
        tracing::warn!(%message);
        cleanup_error.get_or_insert(message);
    }
    cleanup_error
}

async fn call_via_run_as(
    policy: &Policy,
    endpoint: &Endpoint,
    payload: &[u8],
) -> Result<Vec<u8>, HandlerError> {
    const RELAY_STDERR_BYTES: usize = 64 * 1024;

    let executable = std::env::current_exe()
        .map_err(|error| HandlerError::new("internal_error", error.to_string()))?;
    let argv = relay_command(policy, endpoint, &executable)?;
    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    policy.tooling.configure_tokio(&mut command)?;

    let mut child = command.spawn().map_err(|error| {
        HandlerError::new(
            "run_as_not_permitted",
            format!("could not start run_as relay: {error}"),
        )
    })?;
    let pid = child.id();

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| HandlerError::new("internal_error", "run_as relay stdin was not piped"))?;
    let write = async move {
        stdin
            .write_all(payload)
            .await
            .map_err(|error| std::io::Error::other(format!("relay stdin write failed: {error}")))?;
        drop(stdin);
        Ok::<(), std::io::Error>(())
    };
    let work = async {
        let capture = capture_bounded(&mut child, MAX_RESPONSE_BYTES, RELAY_STDERR_BYTES);
        let (_, captured) = tokio::try_join!(write, capture)?;
        Ok::<_, std::io::Error>(captured)
    };
    let captured = match timeout(endpoint.timeout + Duration::from_secs(5), work).await {
        Ok(Ok(captured)) => captured,
        Ok(Err(error)) => {
            let cleanup_error = kill_and_reap_relay(&mut child, pid, "I/O failure").await;
            return Err(HandlerError::with_details(
                "bad_response",
                format!("local-api relay I/O failed: {error}"),
                cleanup_error
                    .map(|error| Map::from_iter([("cleanup_error".into(), Value::String(error))]))
                    .unwrap_or_default(),
            ));
        }
        Err(_) => {
            let cleanup_error = kill_and_reap_relay(&mut child, pid, "timeout").await;
            return Err(HandlerError::with_details(
                "timeout",
                format!("{} did not answer in time", endpoint.name),
                cleanup_error
                    .map(|error| Map::from_iter([("cleanup_error".into(), Value::String(error))]))
                    .unwrap_or_default(),
            ));
        }
    };

    if captured.stdout.truncated() {
        return Err(HandlerError::new(
            "too_large",
            "local-api relay response exceeded the cap",
        ));
    }

    let stdout = captured.stdout.rendered();
    if captured.status.success() && !stdout.is_empty() {
        return Ok(stdout);
    }

    let detail = captured.stderr.rendered_trimmed_lossy();
    let rc = captured.status.code().unwrap_or(-1);
    if detail.contains("a password is required")
        || detail.contains("not allowed to execute")
        || (rc == 1 && detail.to_ascii_lowercase().contains("sudo"))
    {
        let user = endpoint.run_as.as_deref().unwrap_or("<unknown>");
        return Err(HandlerError::new(
            "run_as_not_permitted",
            format!(
                "{:?} declares run_as={user:?}, but this agent may not become that user. The host owner can allow only this relay with a sudoers rule such as: sentinelx ALL=({user}) NOPASSWD: {} --local-api-relay * ({})",
                endpoint.name,
                executable.display(),
                detail.chars().take(120).collect::<String>()
            ),
        ));
    }
    if rc == 3 {
        return Err(HandlerError::new(
            "endpoint_unreachable",
            format!(
                "cannot open {} as {}: {}",
                endpoint.path,
                endpoint.run_as.as_deref().unwrap_or("<unknown>"),
                detail.chars().take(160).collect::<String>()
            ),
        ));
    }

    Err(HandlerError::new(
        "bad_response",
        format!(
            "relay failed (rc={rc}): {}",
            detail.chars().take(160).collect::<String>()
        ),
    ))
}

async fn call_jsonrpc(
    policy: &Policy,
    endpoint: &Endpoint,
    action: &Action,
    params: &Map<String, Value>,
) -> Result<Value, HandlerError> {
    let request = json!({
        "jsonrpc": "2.0",
        "id": format!("sentinel-local-api-{:08x}", rand::random::<u32>()),
        "method": action.method,
        "params": params,
    });
    let mut encoded = serde_json::to_vec(&request)
        .map_err(|e| HandlerError::new("internal_error", e.to_string()))?;
    encoded.push(b'\n');

    let line = if endpoint.run_as.is_some() {
        call_via_run_as(policy, endpoint, &encoded).await?
    } else {
        let mut stream = connect(endpoint).await?;
        timeout(endpoint.timeout, stream.write_all(&encoded))
            .await
            .map_err(|_| HandlerError::new("timeout", "timed out writing request"))?
            .map_err(|e| HandlerError::new("endpoint_unreachable", e.to_string()))?;

        let mut reader = BufReader::new(stream);
        timeout(
            endpoint.timeout,
            read_until_bounded(&mut reader, b'\n', MAX_RESPONSE_BYTES, "JSON-RPC response"),
        )
        .await
        .map_err(|_| HandlerError::new("timeout", "endpoint did not answer in time"))??
    };

    if line.is_empty() {
        return Err(HandlerError::new(
            "bad_response",
            "endpoint closed without answering",
        ));
    }
    let response: Value = serde_json::from_slice(&line)
        .map_err(|_| HandlerError::new("bad_response", "endpoint did not return JSON"))?;
    if let Some(error) = response.get("error").filter(|value| !value.is_null()) {
        return Err(HandlerError::new("endpoint_error", error.to_string()));
    }
    Ok(response.get("result").cloned().unwrap_or(response))
}

fn extract<'a>(data: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = data;
    for part in path.split('.') {
        current = current.as_object()?.get(part)?;
    }
    Some(current)
}

async fn ensure_compatible(policy: &Policy, endpoint: &Endpoint) -> Result<(), HandlerError> {
    let Some(constraint) = endpoint.compatibility.as_ref().and_then(Value::as_object) else {
        return Ok(());
    };

    // Probe on every call. Each action opens a fresh local connection, so there
    // is no reliable longer-lived "endpoint epoch" on which a cached verdict
    // could be based. Re-probing prevents a restarted/upgraded service from
    // inheriting a stale compatibility decision indefinitely.
    let probe = constraint
        .get("probe")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            HandlerError::new("compatibility_unknown", "compatibility probe is malformed")
        })?;
    let extract_path = constraint
        .get("extract")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            HandlerError::new("compatibility_unknown", "compatibility extract is missing")
        })?;
    let accept = constraint
        .get("accept")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            HandlerError::new("compatibility_unknown", "compatibility accept is missing")
        })?;

    let probe_action = Action {
        request: probe
            .get("request")
            .and_then(Value::as_str)
            .map(str::to_owned),
        method: probe
            .get("method")
            .and_then(Value::as_str)
            .map(str::to_owned),
        select: Vec::new(),
        description: None,
        params_schema: None,
    };
    let response = match if endpoint.protocol == "http" {
        call_http(endpoint, &probe_action, &Map::new()).await
    } else {
        call_jsonrpc(policy, endpoint, &probe_action, &Map::new()).await
    } {
        Ok(response) => response,
        Err(error)
            if matches!(
                error.code.as_str(),
                "endpoint_unreachable" | "timeout" | "run_as_not_permitted"
            ) =>
        {
            return Err(error);
        }
        Err(error) => {
            return Err(HandlerError::new(
                "compatibility_unknown",
                format!(
                    "could not read compatibility metadata {extract_path:?} from {:?}: {}",
                    endpoint.name, error.message
                ),
            ));
        }
    };

    let Some(found) = extract(&response, extract_path) else {
        return Err(HandlerError::new(
            "compatibility_unknown",
            format!(
                "{:?} did not report {extract_path:?}, so its compatibility cannot be established",
                endpoint.name
            ),
        ));
    };

    let accepted = if let Some(exact) = accept.get("exact") {
        found == exact
    } else if let Some(allowed) = accept.get("allowed").and_then(Value::as_array) {
        allowed.iter().any(|value| value == found)
    } else {
        false
    };

    if accepted {
        Ok(())
    } else {
        Err(HandlerError::new(
            "compatibility_mismatch",
            format!(
                "{:?} reports {extract_path}={found}, which is not accepted by this profile",
                endpoint.name
            ),
        ))
    }
}

async fn call_action(
    policy: &Policy,
    endpoint: &Endpoint,
    action_name: &str,
    params: &Map<String, Value>,
) -> Result<Value, HandlerError> {
    let action = endpoint.actions.get(action_name).ok_or_else(|| {
        HandlerError::new(
            "action_not_allowed",
            format!(
                "{action_name:?} is not an allowed action; allowed: {:?}",
                endpoint.actions.keys().collect::<Vec<_>>()
            ),
        )
    })?;
    ensure_compatible(policy, endpoint).await?;
    let raw = match if endpoint.protocol == "http" {
        call_http(endpoint, action, params).await
    } else {
        call_jsonrpc(policy, endpoint, action, params).await
    } {
        Ok(raw) => raw,
        Err(error) => return Err(error),
    };
    Ok(project(raw, &action.select))
}

pub async fn handle(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let endpoints = endpoints(policy)?;
    let operation = payload
        .get("operation")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();

    if operation == "list" {
        let listed = endpoints
            .values()
            .filter(|endpoint| endpoint.transport == "unix")
            .map(|endpoint| {
                json!({
                    "name": endpoint.name,
                    "protocol": endpoint.protocol,
                    "transport": endpoint.transport,
                    "action_count": endpoint.actions.len(),
                })
            })
            .collect::<Vec<_>>();
        return Ok(BTreeMap::from([
            ("ok".into(), Value::Bool(true)),
            ("operation".into(), Value::String("list".into())),
            ("endpoints".into(), Value::Array(listed)),
        ]));
    }

    let name = payload
        .get("endpoint")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    let endpoint = endpoints.get(name).ok_or_else(|| {
        HandlerError::new(
            "endpoint_not_configured",
            format!(
                "no local endpoint named {name:?}; configured: {:?}",
                endpoints.keys().collect::<Vec<_>>()
            ),
        )
    })?;

    if operation == "describe" {
        let actions = endpoint
            .actions
            .iter()
            .map(|(name, action)| {
                let mut value = Map::from_iter([
                    (
                        "request".into(),
                        action
                            .request
                            .clone()
                            .map(Value::String)
                            .unwrap_or(Value::Null),
                    ),
                    (
                        "method".into(),
                        action
                            .method
                            .clone()
                            .map(Value::String)
                            .unwrap_or(Value::Null),
                    ),
                    (
                        "returns".into(),
                        if action.select.is_empty() {
                            Value::String("the endpoint's own shape".into())
                        } else {
                            Value::Array(action.select.iter().cloned().map(Value::String).collect())
                        },
                    ),
                    (
                        "description".into(),
                        action
                            .description
                            .clone()
                            .map(Value::String)
                            .unwrap_or(Value::Null),
                    ),
                    (
                        "params".into(),
                        Value::Array(param_names(action).into_iter().map(Value::String).collect()),
                    ),
                ]);
                if let Some(schema) = action.params_schema.clone() {
                    value.insert("params_schema".into(), schema);
                }
                (name.clone(), Value::Object(value))
            })
            .collect::<Map<_, _>>();
        return Ok(BTreeMap::from([
            ("ok".into(), Value::Bool(true)),
            ("operation".into(), Value::String("describe".into())),
            ("endpoint".into(), Value::String(endpoint.name.clone())),
            ("protocol".into(), Value::String(endpoint.protocol.clone())),
            ("actions".into(), Value::Object(actions)),
        ]));
    }

    if operation == "call" {
        let action = payload
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        let params = match payload.get("params") {
            None | Some(Value::Null) => Map::new(),
            Some(Value::Object(params)) => params.clone(),
            _ => {
                return Err(HandlerError::new(
                    "invalid_payload",
                    "params must be an object",
                ));
            }
        };
        let result = call_action(policy, endpoint, action, &params).await?;
        return Ok(BTreeMap::from([
            ("ok".into(), Value::Bool(true)),
            ("operation".into(), Value::String("call".into())),
            ("endpoint".into(), Value::String(endpoint.name.clone())),
            ("action".into(), Value::String(action.into())),
            ("result".into(), result),
        ]));
    }

    Err(HandlerError::new(
        "invalid_payload",
        format!("unknown operation {operation:?}; expected list, describe or call"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_local_api_keys_fail_at_config_boundary() {
        for text in [
            "transport: unix
protocol: jsonrpc
path: /tmp/x.sock
timeot_s: 2
actions:
  a: { method: a }
",
            "transport: unix
protocol: jsonrpc
path: /tmp/x.sock
actions:
  a: { method: a, descrption: nope }
",
            "transport: unix
protocol: jsonrpc
path: /tmp/x.sock
compatibility:
  probe: { method: version, methd: typo }
  extract: protocol
  accept: { exact: 1 }
actions:
  a: { method: a }
",
            "transport: unix
protocol: jsonrpc
path: /tmp/x.sock
compatibility:
  probe: { method: version }
  extract: protocol
  accept: { exact: 1, typo: 2 }
actions:
  a: { method: a }
",
        ] {
            let raw: yaml_serde::Value = yaml_serde::from_str(text).unwrap();
            assert!(
                endpoint_from_raw("x", &raw).is_err(),
                "unknown local_api key unexpectedly parsed: {text:?}"
            );
        }
    }

    #[test]
    fn half_written_compatibility_constraint_is_rejected() {
        let raw: yaml_serde::Value = yaml_serde::from_str(
            "transport: unix\nprotocol: jsonrpc\npath: /tmp/x.sock\ncompatibility:\n  accept: { exact: 20 }\nactions:\n  a: { method: a }\n",
        )
        .unwrap();
        let error = endpoint_from_raw("x", &raw).unwrap_err();
        assert!(error.contains("compatibility.probe"));
    }

    #[test]
    fn run_as_endpoint_remains_usable_and_relay_has_no_shell() {
        let raw: yaml_serde::Value = yaml_serde::from_str(
            "transport: unix\nprotocol: jsonrpc\npath: /run/user/1002/x.sock\nrun_as: userx\nactions:\n  a: { method: a }\n",
        )
        .unwrap();
        let endpoint = endpoint_from_raw("ep", &raw).unwrap();
        let policy = Policy::default();
        let sudo = policy.tooling.command("sudo").display().to_string();
        let argv = relay_command(
            &policy,
            &endpoint,
            Path::new("/usr/local/bin/sentinelx-core"),
        )
        .unwrap();
        assert_eq!(
            &argv[..5],
            &[
                sudo,
                "-n".to_owned(),
                "-u".to_owned(),
                "userx".to_owned(),
                "/usr/local/bin/sentinelx-core".to_owned(),
            ]
        );
        assert_eq!(argv[5], "--local-api-relay");
        assert_eq!(argv[6], "/run/user/1002/x.sock");
        assert_eq!(argv[7], "--relay-timeout");
        assert!(
            !argv
                .iter()
                .any(|arg| arg.contains(';') || arg.contains("&&"))
        );

        let policy = Policy {
            local_apis: BTreeMap::from([("ep".into(), raw)]),
            ..Policy::default()
        };
        assert!(has_usable_endpoints(&policy));
    }

    #[test]
    fn projection_supports_dotted_paths_and_arrays() {
        let value = json!([
            {"Config": {"Image": "a"}, "Name": "one"},
            {"Config": {"Image": "b"}, "Name": "two"}
        ]);
        let projected = project(value, &["Config.Image".into(), "Name".into()]);
        assert_eq!(projected[0]["Config.Image"], "a");
        assert_eq!(projected[1]["Name"], "two");
    }

    #[test]
    fn missing_template_param_is_explicit() {
        let error = render("/containers/{id}/json", &Map::new()).unwrap_err();
        assert_eq!(error.code, "missing_param");
    }
}
