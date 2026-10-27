use crate::{
    handler_error::{HandlerError, HandlerResult},
    policy::Policy,
    process_output::CapturedOutput,
    process_runner::{
        ProcessFailure, ProcessGroupGuard, ProcessGroupKill, ProcessOutcome, RunOptions,
        run_argv_with_limits,
    },
};
use serde_json::{Map, Value, json};
use std::{
    collections::BTreeMap,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command},
    time::timeout,
};

const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const STDIO_EXIT_GRACE: Duration = Duration::from_secs(2);
const STDIO_KILL_GRACE: Duration = Duration::from_secs(5);
const STDERR_TAIL_BYTES: usize = 8 * 1024;
const MAX_SKIPPED_MESSAGES: usize = 1000;
const MCP_PROTOCOL_VERSION: &str = "2025-06-18";

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

#[must_use]
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
        let mut chunk = vec![0_u8; 65_536];
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
struct EndpointProcessOptions {
    args: Vec<String>,
    cwd: Option<PathBuf>,
    env: Map<String, Value>,
    handshake: String,
}

#[derive(Debug, Clone)]
struct Endpoint {
    name: String,
    transport: String,
    protocol: String,
    path: String,
    timeout: Duration,
    run_as: Option<String>,
    args: Vec<String>,
    cwd: Option<PathBuf>,
    env: Map<String, Value>,
    handshake: String,
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

fn parse_action(
    endpoint_name: &str,
    action_name: &str,
    raw_action: &Value,
    protocol: &str,
) -> Result<Action, String> {
    let action = raw_action.as_object().ok_or_else(|| {
        format!("local_apis.{endpoint_name}.actions.{action_name} must be an object")
    })?;
    reject_unknown_keys(
        action,
        &["request", "method", "select", "description", "params"],
        &format!("local_apis.{endpoint_name}.actions.{action_name}"),
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
            "local_apis.{endpoint_name}.actions.{action_name}.request is required for HTTP"
        ));
    }
    if protocol == "jsonrpc"
        && method
            .as_deref()
            .is_none_or(|method| method.trim().is_empty())
    {
        return Err(format!(
            "local_apis.{endpoint_name}.actions.{action_name}.method is required for JSON-RPC"
        ));
    }
    let select = match action.get("select") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str().map(str::to_owned).ok_or_else(|| {
                    format!(
                        "local_apis.{endpoint_name}.actions.{action_name}.select must contain only strings"
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => {
            return Err(format!(
                "local_apis.{endpoint_name}.actions.{action_name}.select must be an array"
            ));
        }
    };
    let params_schema = match action.get("params") {
        None | Some(Value::Null) => None,
        Some(Value::Object(_)) => action.get("params").cloned(),
        Some(_) => {
            return Err(format!(
                "local_apis.{endpoint_name}.actions.{action_name}.params must be an object"
            ));
        }
    };
    let description = match action.get("description") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.clone()),
        Some(_) => {
            return Err(format!(
                "local_apis.{endpoint_name}.actions.{action_name}.description must be a string"
            ));
        }
    };
    Ok(Action {
        request,
        method,
        select,
        description,
        params_schema,
    })
}

fn scalar_text(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn required_endpoint_text(
    name: &str,
    map: &Map<String, Value>,
    field: &str,
) -> Result<String, String> {
    map.get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("local_apis.{name}.{field} is required"))
}

fn parse_endpoint_basics(
    name: &str,
    map: &Map<String, Value>,
) -> Result<(String, String, String), String> {
    let transport = required_endpoint_text(name, map, "transport")?;
    if !matches!(transport.as_str(), "unix" | "stdio") {
        return Err(format!(
            "local_apis.{name}.transport must be unix or stdio, got {transport:?}"
        ));
    }
    let protocol = required_endpoint_text(name, map, "protocol")?;
    if !matches!(protocol.as_str(), "http" | "jsonrpc") {
        return Err(format!(
            "local_apis.{name}.protocol must be http or jsonrpc, got {protocol:?}"
        ));
    }
    let path = required_endpoint_text(name, map, "path")?;
    if transport == "stdio" && protocol != "jsonrpc" {
        return Err(format!(
            "local_apis.{name} transport stdio needs protocol jsonrpc, got {protocol:?}"
        ));
    }
    if transport == "stdio" && !Path::new(&path).is_absolute() {
        return Err(format!(
            "local_apis.{name} transport stdio needs an absolute path to the binary, got {path:?}"
        ));
    }
    Ok((transport, protocol, path))
}

fn parse_endpoint_args(name: &str, map: &Map<String, Value>) -> Result<Vec<String>, String> {
    match map.get("args") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                scalar_text(value).ok_or_else(|| {
                    format!("local_apis.{name}.args must be a list of strings or numeric scalars")
                })
            })
            .collect(),
        Some(_) => Err(format!(
            "local_apis.{name}.args must be a list of strings or numeric scalars"
        )),
    }
}

fn parse_endpoint_env(name: &str, map: &Map<String, Value>) -> Result<Map<String, Value>, String> {
    match map.get("env") {
        None | Some(Value::Null) => Ok(Map::new()),
        Some(Value::Object(values)) => values
            .iter()
            .map(|(key, value)| {
                if key.is_empty() || key.contains('=') {
                    return Err(format!(
                        "local_apis.{name}.env must map variable names to strings or numeric scalars"
                    ));
                }
                scalar_text(value)
                    .map(|value| (key.clone(), Value::String(value)))
                    .ok_or_else(|| {
                        format!(
                            "local_apis.{name}.env must map variable names to strings or numeric scalars"
                        )
                    })
            })
            .collect(),
        Some(_) => Err(format!(
            "local_apis.{name}.env must map variable names to strings or numeric scalars"
        )),
    }
}

fn parse_endpoint_process_options(
    name: &str,
    map: &Map<String, Value>,
) -> Result<EndpointProcessOptions, String> {
    let args = parse_endpoint_args(name, map)?;
    let cwd = match map.get("cwd") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) if Path::new(value).is_absolute() => Some(PathBuf::from(value)),
        Some(_) => return Err(format!("local_apis.{name}.cwd must be an absolute path")),
    };
    let env = parse_endpoint_env(name, map)?;
    let handshake = match map.get("handshake") {
        None | Some(Value::Null) => "none".to_owned(),
        Some(Value::String(value))
            if matches!(value.trim().to_ascii_lowercase().as_str(), "none" | "mcp") =>
        {
            value.trim().to_ascii_lowercase()
        }
        Some(_) => return Err(format!("local_apis.{name}.handshake must be none or mcp")),
    };
    Ok(EndpointProcessOptions {
        args,
        cwd,
        env,
        handshake,
    })
}

fn parse_endpoint_actions(
    name: &str,
    map: &Map<String, Value>,
    protocol: &str,
) -> Result<BTreeMap<String, Action>, String> {
    let raw_actions = map
        .get("actions")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("local_apis.{name}.actions must be an object"))?;
    if raw_actions.is_empty() {
        return Err(format!("local_apis.{name}.actions must not be empty"));
    }
    raw_actions
        .iter()
        .map(|(action_name, raw_action)| {
            parse_action(name, action_name, raw_action, protocol)
                .map(|action| (action_name.clone(), action))
        })
        .collect()
}

fn parse_endpoint_timeout(name: &str, map: &Map<String, Value>) -> Result<Duration, String> {
    let seconds = match map.get("timeout_s") {
        None | Some(Value::Null) => 30.0,
        Some(value) => value
            .as_f64()
            .filter(|value| value.is_finite() && *value >= 0.1 && *value <= 300.0)
            .ok_or_else(|| {
                format!("local_apis.{name}.timeout_s must be between 0.1 and 300 seconds")
            })?,
    };
    Ok(Duration::from_secs_f64(seconds))
}

fn parse_endpoint_run_as(name: &str, map: &Map<String, Value>) -> Result<Option<String>, String> {
    match map.get("run_as") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => {
            Ok((!value.trim().is_empty()).then(|| value.trim().to_owned()))
        }
        Some(_) => Err(format!("local_apis.{name}.run_as must be a string")),
    }
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
            "args",
            "cwd",
            "env",
            "handshake",
            "compatibility",
            "actions",
        ],
        &format!("local_apis.{name}"),
    )?;
    let (transport, protocol, path) = parse_endpoint_basics(name, map)?;
    let process = parse_endpoint_process_options(name, map)?;
    let actions = parse_endpoint_actions(name, map, &protocol)?;
    let timeout = parse_endpoint_timeout(name, map)?;
    let compatibility = valid_compatibility(map.get("compatibility"), &protocol)
        .map_err(|error| format!("local_apis.{name}.{error}"))?;
    let run_as = parse_endpoint_run_as(name, map)?;
    if transport == "stdio" && run_as.is_some() && !process.env.is_empty() {
        return Err(format!(
            "local_apis.{name} sets both env and run_as; sudo would drop the variables"
        ));
    }
    Ok(Endpoint {
        name: name.to_owned(),
        transport,
        protocol,
        path,
        timeout,
        run_as,
        args: process.args,
        cwd: process.cwd,
        env: process.env,
        handshake: process.handshake,
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
            .map_or_else(Vec::new, |items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|name| properties.contains_key(*name))
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            });
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
            .map_or_else(|| value.to_string(), str::to_owned);
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

fn http_error(endpoint: &Endpoint, error: &reqwest::Error) -> HandlerError {
    if error.is_timeout() {
        HandlerError::new(
            "timeout",
            format!("{} did not answer in time", endpoint.name),
        )
    } else if error.is_connect() {
        HandlerError::new(
            "endpoint_unreachable",
            format!("cannot open {}: {error}", endpoint.path),
        )
    } else {
        HandlerError::new("bad_response", error.to_string())
    }
}

async fn decode_http_response(
    endpoint: &Endpoint,
    mut response: reqwest::Response,
) -> Result<Value, HandlerError> {
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(HandlerError::new(
            "too_large",
            "endpoint response exceeded the cap",
        ));
    }

    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| http_error(endpoint, &error))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(HandlerError::new(
                "too_large",
                "endpoint response exceeded the cap",
            ));
        }
        body.extend_from_slice(&chunk);
    }

    if status.is_client_error() || status.is_server_error() {
        return Err(HandlerError::new(
            "endpoint_error",
            format!(
                "endpoint answered HTTP {}: {}",
                status.as_u16(),
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
    if endpoint.transport != "unix" {
        return Err(HandlerError::new(
            "endpoint_unreachable",
            format!(
                "transport {:?} is not available in the Rust compatibility agent",
                endpoint.transport
            ),
        ));
    }

    let request = action.request.as_deref().unwrap_or("").trim();
    let (method, target) = request.split_once(' ').ok_or_else(|| {
        HandlerError::new(
            "bad_action",
            format!("request must look like 'GET /path', got {request:?}"),
        )
    })?;
    let method = reqwest::Method::from_bytes(method.as_bytes()).map_err(|error| {
        HandlerError::new(
            "bad_action",
            format!("invalid HTTP method {method:?}: {error}"),
        )
    })?;
    let target = render(target.trim(), params)?;
    let url = format!("http://localhost{target}");
    let client = reqwest::Client::builder()
        .unix_socket(Path::new(&endpoint.path))
        .timeout(endpoint.timeout)
        .no_proxy()
        .build()
        .map_err(|error| HandlerError::new("internal_error", error.to_string()))?;
    let response = client
        .request(method, url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|error| http_error(endpoint, &error))?;
    decode_http_response(endpoint, response).await
}

fn interpret_relay_output(
    endpoint: &Endpoint,
    executable: &Path,
    captured: &CapturedOutput,
) -> Result<Vec<u8>, HandlerError> {
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

async fn call_via_run_as(
    policy: &Policy,
    endpoint: &Endpoint,
    payload: &[u8],
) -> Result<Vec<u8>, HandlerError> {
    const RELAY_STDERR_BYTES: usize = 64 * 1024;

    let executable = std::env::current_exe()
        .map_err(|error| HandlerError::new("internal_error", error.to_string()))?;
    let argv = relay_command(policy, endpoint, &executable)?;
    let outcome = run_argv_with_limits(
        policy,
        &argv,
        endpoint.timeout + Duration::from_secs(5),
        RunOptions {
            cwd: None,
            env: None,
            stdin: Some(payload),
            stdout_limit: MAX_RESPONSE_BYTES,
            stderr_limit: RELAY_STDERR_BYTES,
            killer: ProcessGroupKill::Direct,
        },
    )
    .await;

    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(ProcessFailure::Setup(error)) => return Err(error),
        Err(ProcessFailure::Spawn(error)) => {
            return Err(HandlerError::new(
                "run_as_not_permitted",
                format!("could not start run_as relay: {error}"),
            ));
        }
        Err(ProcessFailure::Capture {
            error,
            cleanup_error,
        }) => {
            let mut details = Map::new();
            if let Some(error) = cleanup_error {
                details.insert("cleanup_error".into(), Value::String(error));
            }
            return Err(HandlerError::with_details(
                "bad_response",
                format!("local-api relay I/O failed: {error}"),
                details,
            ));
        }
    };

    match outcome {
        ProcessOutcome::Completed { captured, .. } => {
            interpret_relay_output(endpoint, &executable, &captured)
        }
        ProcessOutcome::TimedOut {
            captured,
            cleanup_error,
            ..
        } => {
            let mut details = Map::new();
            if captured.left_running {
                details.insert("left_running".into(), Value::Bool(true));
            }
            if let Some(error) = cleanup_error {
                details.insert("cleanup_error".into(), Value::String(error));
            }
            Err(HandlerError::with_details(
                "timeout",
                format!("{} did not answer in time", endpoint.name),
                details,
            ))
        }
    }
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

fn stdio_argv(policy: &Policy, endpoint: &Endpoint) -> Vec<String> {
    let mut declared = Vec::with_capacity(endpoint.args.len() + 1);
    declared.push(endpoint.path.clone());
    declared.extend(endpoint.args.iter().cloned());
    if let Some(user) = endpoint.run_as.as_deref() {
        let mut argv = vec![
            policy.tooling.command("sudo").display().to_string(),
            "-n".into(),
            "-u".into(),
            user.into(),
            "--".into(),
        ];
        argv.extend(declared);
        argv
    } else {
        declared
    }
}

fn configure_stdio_environment(
    policy: &Policy,
    endpoint: &Endpoint,
    command: &mut Command,
) -> Result<(), HandlerError> {
    const POSIX_KEYS: &[&str] = &[
        "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR", "USER", "LOGNAME",
    ];
    const WINDOWS_KEYS: &[&str] = &[
        "PATHEXT",
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "WINDIR",
        "COMSPEC",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "COMPUTERNAME",
        "USERNAME",
    ];
    command.env_clear();
    command.env("PATH", policy.tooling.path_env()?);
    let keys = if cfg!(windows) {
        WINDOWS_KEYS
    } else {
        POSIX_KEYS
    };
    for key in keys {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    #[cfg(not(windows))]
    if std::env::var_os("LANG").is_none() {
        command.env("LANG", "C.UTF-8");
    }
    for (key, value) in &endpoint.env {
        if let Some(value) = value.as_str() {
            command.env(key, value);
        }
    }
    Ok(())
}

fn stdio_binary_problem(path: &Path, run_as: bool) -> Option<(&'static str, String)> {
    if !path.is_absolute() {
        return Some((
            "endpoint_unreachable",
            format!("{} is not an absolute path", path.display()),
        ));
    }
    let real = match path.canonicalize() {
        Ok(real) => real,
        Err(error) => {
            return Some((
                "endpoint_unreachable",
                format!("cannot inspect {}: {error}", path.display()),
            ));
        }
    };
    let metadata = match std::fs::metadata(&real) {
        Ok(metadata) => metadata,
        Err(error) => {
            return Some((
                "endpoint_unreachable",
                format!("cannot inspect {}: {error}", path.display()),
            ));
        }
    };
    if !metadata.is_file() {
        return Some((
            "endpoint_unreachable",
            format!("{} is not a regular file", path.display()),
        ));
    }
    #[cfg(unix)]
    {
        use nix::unistd::{Gid, Group, Uid, User};
        use std::os::unix::fs::MetadataExt as _;
        let private_group = |metadata: &std::fs::Metadata| {
            let uid = Uid::from_raw(metadata.uid());
            let gid = Gid::from_raw(metadata.gid());
            let Ok(Some(user)) = User::from_uid(uid) else {
                return false;
            };
            let Ok(Some(group)) = Group::from_gid(gid) else {
                return false;
            };
            group.name == user.name
                && user.gid == gid
                && group.mem.iter().all(|member| member == &user.name)
        };
        let replaceable = |metadata: &std::fs::Metadata| {
            let mode = metadata.mode();
            let world = mode & 0o002 != 0;
            let group = mode & 0o020 != 0 && !private_group(metadata);
            let sticky_dir = metadata.is_dir() && mode & 0o1000 != 0;
            !sticky_dir && (world || group)
        };
        if replaceable(&metadata) {
            return Some((
                "unsafe_binary",
                format!(
                    "{} is writable by users other than its owner",
                    real.display()
                ),
            ));
        }
        for directory in [real.parent(), path.parent()].into_iter().flatten() {
            if let Ok(metadata) = std::fs::metadata(directory)
                && replaceable(&metadata)
            {
                return Some((
                    "unsafe_binary",
                    format!(
                        "{} can be replaced because {} is writable by other users",
                        real.display(),
                        directory.display()
                    ),
                ));
            }
        }
        if !run_as && metadata.mode() & 0o111 == 0 {
            return Some((
                "endpoint_unreachable",
                format!("{} is not executable", path.display()),
            ));
        }
    }
    None
}

async fn stdio_send(stdin: &mut ChildStdin, message: &Value) -> Result<(), HandlerError> {
    let mut encoded = serde_json::to_vec(message)
        .map_err(|error| HandlerError::new("internal_error", error.to_string()))?;
    encoded.push(b'\n');
    stdin.write_all(&encoded).await.map_err(|error| {
        HandlerError::new("bad_response", format!("endpoint stdin closed: {error}"))
    })
}

async fn stdio_receive(
    stdin: &mut ChildStdin,
    stdout: &mut BufReader<ChildStdout>,
    endpoint: &Endpoint,
    want_id: &str,
    total_bytes: &mut usize,
) -> Result<Value, HandlerError> {
    for _ in 0..=MAX_SKIPPED_MESSAGES {
        let remaining = MAX_RESPONSE_BYTES.saturating_sub(*total_bytes);
        if remaining == 0 {
            return Err(HandlerError::new(
                "too_large",
                "stdio endpoint stdout exceeded the cap",
            ));
        }
        let line = read_until_bounded(stdout, b'\n', remaining, "stdio JSON-RPC response").await?;
        if line.is_empty() {
            return Err(HandlerError::new(
                "bad_response",
                "endpoint exited before answering",
            ));
        }
        *total_bytes = total_bytes.saturating_add(line.len());
        let text = line
            .iter()
            .copied()
            .skip_while(u8::is_ascii_whitespace)
            .collect::<Vec<_>>();
        if text.is_empty() {
            continue;
        }
        let message: Value = serde_json::from_slice(&text).map_err(|_| {
            HandlerError::new(
                "bad_response",
                format!("{} wrote non-JSON data to stdout", endpoint.name),
            )
        })?;
        if message.get("id").and_then(Value::as_str) == Some(want_id)
            && (message.get("result").is_some() || message.get("error").is_some())
        {
            return Ok(message);
        }
        if message.get("method").and_then(Value::as_str).is_some()
            && let Some(id) = message.get("id").filter(|value| !value.is_null())
        {
            stdio_send(
                stdin,
                &json!({
                    "jsonrpc": "2.0", "id": id,
                    "error": {"code": -32601, "message": "not supported by the SentinelX agent"},
                }),
            )
            .await?;
        }
    }
    Err(HandlerError::new(
        "bad_response",
        format!("{} sent too many messages without answering", endpoint.name),
    ))
}

fn unwrap_jsonrpc(message: Value) -> Result<Value, HandlerError> {
    if let Some(error) = message.get("error").filter(|value| !value.is_null()) {
        return Err(HandlerError::new("endpoint_error", error.to_string()));
    }
    Ok(message.get("result").cloned().unwrap_or(message))
}

async fn stop_stdio_child(
    child: &mut Child,
    guard: &mut ProcessGroupGuard,
) -> (Option<String>, Option<i32>) {
    let (exited, mut exit_code) = match timeout(STDIO_EXIT_GRACE, child.wait()).await {
        Ok(Ok(status)) => (true, status.code()),
        Ok(Err(error)) => {
            return (
                Some(format!("failed waiting for stdio endpoint: {error}")),
                None,
            );
        }
        Err(_) => (false, None),
    };
    let cleanup_error = guard.kill().await;
    if !exited && child.try_wait().ok().flatten().is_none() {
        let _ = child.kill().await;
        if let Ok(Ok(status)) = timeout(STDIO_KILL_GRACE, child.wait()).await {
            exit_code = status.code();
        }
    }
    (cleanup_error, exit_code)
}

async fn read_stderr_tail(mut stderr: ChildStderr) -> Vec<u8> {
    let mut tail = Vec::new();
    let mut buf = [0_u8; 4096];
    while let Ok(read) = stderr.read(&mut buf).await {
        if read == 0 {
            break;
        }
        tail.extend_from_slice(&buf[..read]);
        if tail.len() > STDERR_TAIL_BYTES {
            tail.drain(..tail.len() - STDERR_TAIL_BYTES);
        }
    }
    tail
}

async fn stdio_conversation(
    stdin: &mut ChildStdin,
    stdout: &mut BufReader<ChildStdout>,
    endpoint: &Endpoint,
    action: &Action,
    params: &Map<String, Value>,
) -> Result<Value, HandlerError> {
    let mut total_bytes = 0_usize;
    if endpoint.handshake == "mcp" {
        let id = format!("sentinel-local-api-init-{:08x}", rand::random::<u32>());
        stdio_send(
            stdin,
            &json!({
                "jsonrpc": "2.0", "id": id, "method": "initialize",
                "params": {"protocolVersion": MCP_PROTOCOL_VERSION, "capabilities": {},
                    "clientInfo": {"name": "sentinelx-agent", "version": env!("CARGO_PKG_VERSION")}},
            }),
        )
        .await?;
        let reply = stdio_receive(stdin, stdout, endpoint, &id, &mut total_bytes).await?;
        unwrap_jsonrpc(reply).map_err(|error| {
            HandlerError::new(
                "endpoint_error",
                format!("initialize was refused: {}", error.message),
            )
        })?;
        stdio_send(
            stdin,
            &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        )
        .await?;
    }
    let id = format!("sentinel-local-api-{:08x}", rand::random::<u32>());
    stdio_send(
        stdin,
        &json!({"jsonrpc": "2.0", "id": id, "method": action.method, "params": params}),
    )
    .await?;
    let reply = stdio_receive(stdin, stdout, endpoint, &id, &mut total_bytes).await?;
    unwrap_jsonrpc(reply)
}

fn add_stdio_error_context(
    mut error: HandlerError,
    stderr_tail: &[u8],
    cleanup_error: Option<String>,
    exit_code: Option<i32>,
) -> HandlerError {
    if !stderr_tail.is_empty() {
        error.details.insert(
            "stderr_tail".into(),
            Value::String(String::from_utf8_lossy(stderr_tail).trim().to_owned()),
        );
    }
    if let Some(cleanup_error) = cleanup_error {
        error
            .details
            .insert("cleanup_error".into(), Value::String(cleanup_error));
    }
    if error.code == "bad_response"
        && let Some(exit_code) = exit_code
    {
        error
            .details
            .insert("exit_code".into(), Value::from(exit_code));
    }
    error
}

async fn call_stdio_jsonrpc(
    policy: &Policy,
    endpoint: &Endpoint,
    action: &Action,
    params: &Map<String, Value>,
) -> Result<Value, HandlerError> {
    if let Some((code, message)) =
        stdio_binary_problem(Path::new(&endpoint.path), endpoint.run_as.is_some())
    {
        return Err(HandlerError::new(code, message));
    }
    let argv = stdio_argv(policy, endpoint);
    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    configure_stdio_environment(policy, endpoint, &mut command)?;
    if let Some(cwd) = endpoint.cwd.as_deref() {
        command.current_dir(cwd);
    }
    #[cfg(unix)]
    command.process_group(0);
    let mut child = command.spawn().map_err(|error| {
        HandlerError::new(
            "endpoint_unreachable",
            format!("cannot start {}: {error}", endpoint.path),
        )
    })?;
    let mut guard = ProcessGroupGuard::new(child.id(), ProcessGroupKill::Direct);
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| HandlerError::new("internal_error", "missing stdio stdin"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| HandlerError::new("internal_error", "missing stdio stdout"))?;
    let mut stdout = BufReader::new(stdout);
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| HandlerError::new("internal_error", "missing stdio stderr"))?;
    let stderr_task = tokio::spawn(read_stderr_tail(stderr));
    let result = timeout(
        endpoint.timeout,
        stdio_conversation(&mut stdin, &mut stdout, endpoint, action, params),
    )
    .await
    .unwrap_or_else(|_| {
        Err(HandlerError::new(
            "timeout",
            format!("{} did not answer in time", endpoint.name),
        ))
    });
    drop(stdin);
    let (cleanup_error, exit_code) = stop_stdio_child(&mut child, &mut guard).await;
    let stderr_tail = timeout(Duration::from_millis(500), stderr_task)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
    result.map_err(|error| add_stdio_error_context(error, &stderr_tail, cleanup_error, exit_code))
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
    let response = match if endpoint.transport == "stdio" {
        call_stdio_jsonrpc(policy, endpoint, &probe_action, &Map::new()).await
    } else if endpoint.protocol == "http" {
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

    let accepted = accept.get("exact").map_or_else(
        || {
            accept
                .get("allowed")
                .and_then(Value::as_array)
                .is_some_and(|allowed| allowed.iter().any(|value| value == found))
        },
        |exact| found == exact,
    );

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
    let raw = match if endpoint.transport == "stdio" {
        call_stdio_jsonrpc(policy, endpoint, action, params).await
    } else if endpoint.protocol == "http" {
        call_http(endpoint, action, params).await
    } else {
        call_jsonrpc(policy, endpoint, action, params).await
    } {
        Ok(raw) => raw,
        Err(error) => return Err(error),
    };
    Ok(project(raw, &action.select))
}

fn list_endpoints(endpoints: &BTreeMap<String, Endpoint>) -> BTreeMap<String, Value> {
    let listed = endpoints
        .values()
        .map(|endpoint| {
            json!({
                "name": endpoint.name,
                "protocol": endpoint.protocol,
                "transport": endpoint.transport,
                "action_count": endpoint.actions.len(),
            })
        })
        .collect::<Vec<_>>();
    BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("operation".into(), Value::String("list".into())),
        ("endpoints".into(), Value::Array(listed)),
    ])
}

fn describe_endpoint(endpoint: &Endpoint) -> BTreeMap<String, Value> {
    let actions = endpoint
        .actions
        .iter()
        .map(|(name, action)| {
            let mut value = Map::from_iter([
                (
                    "request".into(),
                    action.request.clone().map_or(Value::Null, Value::String),
                ),
                (
                    "method".into(),
                    action.method.clone().map_or(Value::Null, Value::String),
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
                        .map_or(Value::Null, Value::String),
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
    BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("operation".into(), Value::String("describe".into())),
        ("endpoint".into(), Value::String(endpoint.name.clone())),
        ("protocol".into(), Value::String(endpoint.protocol.clone())),
        ("actions".into(), Value::Object(actions)),
    ])
}

async fn call_endpoint(
    policy: &Policy,
    endpoint: &Endpoint,
    payload: &Map<String, Value>,
) -> HandlerResult {
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
    Ok(BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("operation".into(), Value::String("call".into())),
        ("endpoint".into(), Value::String(endpoint.name.clone())),
        ("action".into(), Value::String(action.into())),
        ("result".into(), result),
    ]))
}

/// # Errors
/// Returns an error when the local API request is invalid, disallowed, times out, or fails.
pub async fn handle(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let endpoints = endpoints(policy)?;
    let operation = payload
        .get("operation")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if operation == "list" {
        return Ok(list_endpoints(&endpoints));
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

    match operation {
        "describe" => Ok(describe_endpoint(endpoint)),
        "call" => call_endpoint(policy, endpoint, payload).await,
        _ => Err(HandlerError::new(
            "invalid_payload",
            format!("unknown operation {operation:?}; expected list, describe or call"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TestError as _, TestResult, TestValue as _};
    use tempfile::tempdir;

    #[test]
    fn unknown_local_api_keys_fail_at_config_boundary() -> TestResult {
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
            let raw: yaml_serde::Value = yaml_serde::from_str(text).test_value()?;
            assert!(
                endpoint_from_raw("x", &raw).is_err(),
                "unknown local_api key unexpectedly parsed: {text:?}"
            );
        }

        Ok(())
    }

    #[test]
    fn half_written_compatibility_constraint_is_rejected() -> TestResult {
        let raw: yaml_serde::Value = yaml_serde::from_str(
            "transport: unix\nprotocol: jsonrpc\npath: /tmp/x.sock\ncompatibility:\n  accept: { exact: 20 }\nactions:\n  a: { method: a }\n",
        )
        .test_value()?;
        let error = endpoint_from_raw("x", &raw).test_error()?;
        assert!(error.contains("compatibility.probe"));

        Ok(())
    }

    #[test]
    fn run_as_endpoint_remains_usable_and_relay_has_no_shell() -> TestResult {
        let raw: yaml_serde::Value = yaml_serde::from_str(
            "transport: unix\nprotocol: jsonrpc\npath: /run/user/1002/x.sock\nrun_as: userx\nactions:\n  a: { method: a }\n",
        )
        .test_value()?;
        let endpoint = endpoint_from_raw("ep", &raw).test_value()?;
        let policy = Policy::default();
        let sudo = policy.tooling.command("sudo").display().to_string();
        let argv = relay_command(
            &policy,
            &endpoint,
            Path::new("/usr/local/bin/sentinelx-core"),
        )
        .test_value()?;
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

        Ok(())
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

    #[cfg(unix)]
    #[tokio::test]
    async fn http_over_unix_socket_decodes_chunked_json() -> TestResult {
        use tokio::net::UnixListener;

        let dir = tempfile::tempdir().test_value()?;
        let socket = dir.path().join("http.sock");
        let listener = UnixListener::bind(&socket).test_value()?;
        let server = tokio::spawn(async move {
            use tokio::io::AsyncReadExt as _;
            let (mut stream, _) = listener.accept().await?;
            let mut request = [0_u8; 4096];
            let count = stream.read(&mut request).await?;
            assert!(request[..count].starts_with(b"GET /"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n8\r\n{\"ok\":1}\r\n0\r\nX-Test: yes\r\n\r\n",
                )
                .await?;
            Ok::<(), std::io::Error>(())
        });
        let endpoint = Endpoint {
            name: "fixture".into(),
            transport: "unix".into(),
            protocol: "http".into(),
            path: socket.display().to_string(),
            timeout: Duration::from_secs(2),
            run_as: None,
            args: Vec::new(),
            cwd: None,
            env: Map::new(),
            handshake: "none".into(),
            actions: BTreeMap::new(),
            compatibility: None,
        };
        let action = Action {
            request: Some("GET /status".into()),
            method: None,
            select: Vec::new(),
            description: None,
            params_schema: None,
        };

        let response = call_http(&endpoint, &action, &Map::new())
            .await
            .test_value()?;
        assert_eq!(response, json!({"ok": 1}));
        server.await.test_value()?.test_value()?;
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn http_over_unix_socket_rejects_oversized_body_before_reading_it() -> TestResult {
        use tokio::net::UnixListener;

        let dir = tempfile::tempdir().test_value()?;
        let socket = dir.path().join("http.sock");
        let listener = UnixListener::bind(&socket).test_value()?;
        let server = tokio::spawn(async move {
            use tokio::io::AsyncReadExt as _;
            let (mut stream, _) = listener.accept().await?;
            let mut request = [0_u8; 4096];
            let count = stream.read(&mut request).await?;
            assert!(request[..count].starts_with(b"GET /"));
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        MAX_RESPONSE_BYTES + 1
                    )
                    .as_bytes(),
                )
                .await?;
            Ok::<(), std::io::Error>(())
        });
        let endpoint = Endpoint {
            name: "fixture".into(),
            transport: "unix".into(),
            protocol: "http".into(),
            path: socket.display().to_string(),
            timeout: Duration::from_secs(2),
            run_as: None,
            args: Vec::new(),
            cwd: None,
            env: Map::new(),
            handshake: "none".into(),
            actions: BTreeMap::new(),
            compatibility: None,
        };
        let action = Action {
            request: Some("GET /large".into()),
            method: None,
            select: Vec::new(),
            description: None,
            params_schema: None,
        };

        let error = call_http(&endpoint, &action, &Map::new())
            .await
            .test_error()?;
        assert_eq!(error.code, "too_large");
        server.await.test_value()?.test_value()?;
        Ok(())
    }

    #[test]
    fn missing_template_param_is_explicit() -> TestResult {
        let error = render("/containers/{id}/json", &Map::new()).test_error()?;
        assert_eq!(error.code, "missing_param");

        Ok(())
    }

    #[cfg(unix)]
    fn stdio_fixture(mode: &str) -> TestResult<(tempfile::TempDir, Endpoint)> {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempdir().test_value()?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .test_value()?;
        let script = dir.path().join("server.py");
        std::fs::write(
            &script,
            r"#!/usr/bin/env python3
import json, os, subprocess, sys, time
mode = sys.argv[1]
def read(): return json.loads(sys.stdin.readline())
def out(v):
    print(json.dumps(v), flush=True)
if mode == 'exit_early':
    print('boom: no config file', file=sys.stderr, flush=True)
    sys.exit(3)
if mode == 'hang':
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(600)'])
    with open(os.environ['PIDFILE'], 'w') as f:
        f.write(f'{os.getpid()} {child.pid}')
    time.sleep(600)
if mode == 'mcp':
    init = read()
    out({'jsonrpc':'2.0','id':init['id'],'result':{'protocolVersion':init['params']['protocolVersion']}})
    note = read()
req = read()
if mode == 'huge':
    out({'jsonrpc':'2.0','id':req['id'],'result':'x' * (9 * 1024 * 1024)})
    sys.exit(0)
if mode == 'chatty':
    out({'jsonrpc':'2.0','method':'notifications/progress','params':{}})
    out({'jsonrpc':'2.0','id':99,'method':'ping'})
    reply = read()
    result = {'ping': reply['error']['code'], 'params': req['params'], 'argv': sys.argv[1:]}
elif mode == 'env':
    result = {'params': req['params'], 'argv': sys.argv[1:],
              'declared': os.environ.get('DECLARED_ONLY'),
              'leak': os.environ.get('CARGO_MANIFEST_DIR')}
else:
    result = {'params': req['params'], 'argv': sys.argv[1:]}
out({'jsonrpc':'2.0','id':req['id'],'result':result})
",
        ).test_value()?;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).test_value()?;
        let endpoint = Endpoint {
            name: "fixture".into(),
            transport: "stdio".into(),
            protocol: "jsonrpc".into(),
            path: script.display().to_string(),
            timeout: Duration::from_secs(5),
            run_as: None,
            args: vec![mode.into()],
            cwd: None,
            env: Map::new(),
            handshake: if mode == "mcp" {
                "mcp".into()
            } else {
                "none".into()
            },
            actions: BTreeMap::from([(
                "echo".into(),
                Action {
                    request: None,
                    method: Some("echo".into()),
                    select: Vec::new(),
                    description: None,
                    params_schema: None,
                },
            )]),
            compatibility: None,
        };
        Ok((dir, endpoint))
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stdio_round_trip_keeps_call_parameters_out_of_argv() -> TestResult {
        let (_dir, endpoint) = stdio_fixture("echo")?;
        let result = call_action(
            &Policy::default(),
            &endpoint,
            "echo",
            &Map::from_iter([("target".into(), Value::String("--evil; rm -rf /".into()))]),
        )
        .await
        .test_value()?;
        assert_eq!(result["params"]["target"], "--evil; rm -rf /");
        assert_eq!(result["argv"], json!(["echo"]));
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stdio_mcp_handshake_and_server_requests_are_supported() -> TestResult {
        let (_dir, endpoint) = stdio_fixture("mcp")?;
        let result = call_action(&Policy::default(), &endpoint, "echo", &Map::new())
            .await
            .test_value()?;
        assert_eq!(result["argv"], json!(["mcp"]));

        let (_dir, endpoint) = stdio_fixture("chatty")?;
        let result = call_action(&Policy::default(), &endpoint, "echo", &Map::new())
            .await
            .test_value()?;
        assert_eq!(result["ping"], -32601);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stdio_world_writable_binary_is_refused() -> TestResult {
        use std::os::unix::fs::PermissionsExt as _;
        let (_dir, endpoint) = stdio_fixture("echo")?;
        std::fs::set_permissions(&endpoint.path, std::fs::Permissions::from_mode(0o702))
            .test_value()?;
        let error = call_action(&Policy::default(), &endpoint, "echo", &Map::new())
            .await
            .test_error()?;
        assert_eq!(error.code, "unsafe_binary");
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stdio_environment_is_minimal_and_declared_values_arrive() -> TestResult {
        let (_dir, mut endpoint) = stdio_fixture("env")?;
        endpoint
            .env
            .insert("DECLARED_ONLY".into(), Value::String("visible".into()));
        let result = call_action(&Policy::default(), &endpoint, "echo", &Map::new())
            .await
            .test_value()?;
        assert_eq!(result["declared"], "visible");
        assert!(result["leak"].is_null());
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stdio_early_exit_reports_stderr_and_exit_code() -> TestResult {
        let (_dir, endpoint) = stdio_fixture("exit_early")?;
        let error = call_action(&Policy::default(), &endpoint, "echo", &Map::new())
            .await
            .test_error()?;
        assert_eq!(error.code, "bad_response");
        assert_eq!(error.details["exit_code"], 3);
        assert!(
            error.details["stderr_tail"]
                .as_str()
                .is_some_and(|text| text.contains("boom: no config file"))
        );
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stdio_stdout_cap_is_enforced() -> TestResult {
        let (_dir, endpoint) = stdio_fixture("huge")?;
        let error = call_action(&Policy::default(), &endpoint, "echo", &Map::new())
            .await
            .test_error()?;
        assert_eq!(error.code, "too_large");
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stdio_timeout_kills_the_process_group() -> TestResult {
        use nix::{errno::Errno, sys::signal, unistd::Pid};
        let (dir, mut endpoint) = stdio_fixture("hang")?;
        let pidfile = dir.path().join("pids");
        endpoint.timeout = Duration::from_millis(500);
        endpoint.env.insert(
            "PIDFILE".into(),
            Value::String(pidfile.display().to_string()),
        );
        let error = call_action(&Policy::default(), &endpoint, "echo", &Map::new())
            .await
            .test_error()?;
        assert_eq!(error.code, "timeout");
        let pids = std::fs::read_to_string(&pidfile)
            .test_value()?
            .split_whitespace()
            .map(str::parse::<i32>)
            .collect::<Result<Vec<_>, _>>()
            .test_value()?;
        for _ in 0..50 {
            if pids
                .iter()
                .all(|pid| signal::kill(Pid::from_raw(*pid), None) == Err(Errno::ESRCH))
            {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Err(std::io::Error::other(format!("stdio descendants still alive: {pids:?}")).into())
    }

    #[test]
    fn stdio_config_is_strict_about_protocol_paths_and_options() -> TestResult {
        let good: yaml_serde::Value = yaml_serde::from_str(
            "transport: stdio\nprotocol: jsonrpc\npath: /usr/bin/example\nargs: [--stdio, 7]\ncwd: /tmp\nenv: {PORT: 8080}\nhandshake: mcp\nactions:\n  x: {method: x}\n",
        ).test_value()?;
        let endpoint = endpoint_from_raw("x", &good).test_value()?;
        assert_eq!(endpoint.args, ["--stdio", "7"]);
        assert_eq!(endpoint.handshake, "mcp");
        for bad in [
            "transport: stdio\nprotocol: http\npath: /x\nactions:\n  x: {request: 'GET /'}\n",
            "transport: stdio\nprotocol: jsonrpc\npath: relative\nactions:\n  x: {method: x}\n",
            "transport: stdio\nprotocol: jsonrpc\npath: /x\nhandshake: nope\nactions:\n  x: {method: x}\n",
        ] {
            let raw: yaml_serde::Value = yaml_serde::from_str(bad).test_value()?;
            assert!(endpoint_from_raw("x", &raw).is_err());
        }
        Ok(())
    }
}
