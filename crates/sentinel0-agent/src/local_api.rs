use crate::{
    handler_error::{HandlerError, HandlerResult},
    policy::Policy,
};
use serde_json::{Map, Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    io::{Read as _, Write as _},
    path::Path,
    sync::{Mutex, OnceLock},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    process::Command,
    time::timeout,
};

const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
enum CompatVerdict {
    Passed,
    Failed { code: String, message: String },
}

fn compat_cache() -> &'static Mutex<HashMap<String, CompatVerdict>> {
    static CACHE: OnceLock<Mutex<HashMap<String, CompatVerdict>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn forget_compatibility(endpoint_name: &str) {
    let mut cache = compat_cache()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    cache.remove(endpoint_name);
}

fn relay_command(endpoint: &Endpoint, executable: &Path) -> Result<Vec<String>, HandlerError> {
    let user = endpoint.run_as.as_deref().ok_or_else(|| {
        HandlerError::new("internal_error", "relay requested without run_as user")
    })?;
    Ok(vec![
        "sudo".into(),
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
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));

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
                    reply.extend_from_slice(&chunk[..count]);
                    if reply.len() > MAX_RESPONSE_BYTES {
                        eprintln!("reply exceeded the cap");
                        return 4;
                    }
                    if reply.ends_with(b"\n") {
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
        let _ = (path, timeout_seconds);
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

fn yaml_to_json(value: &yaml_serde::Value) -> Option<Value> {
    serde_json::to_value(value).ok()
}

fn valid_compatibility(value: Option<&Value>, protocol: &str) -> Option<Value> {
    let value = value?.as_object()?;
    let probe = value.get("probe")?.as_object()?;
    let extract = value.get("extract")?.as_str()?;
    if extract.trim().is_empty() {
        return None;
    }
    let accept = value.get("accept")?.as_object()?;
    let has_accept = accept.contains_key("exact")
        || accept
            .get("allowed")
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty());
    if !has_accept {
        return None;
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
    probe_ok.then(|| Value::Object(value.clone()))
}

fn endpoint_from_raw(name: &str, raw: &yaml_serde::Value) -> Option<Endpoint> {
    let value = yaml_to_json(raw)?;
    let map = value.as_object()?;
    let transport = map.get("transport")?.as_str()?.trim().to_owned();
    let protocol = map.get("protocol")?.as_str()?.trim().to_owned();
    let path = map.get("path")?.as_str()?.trim().to_owned();
    if !matches!(transport.as_str(), "unix" | "stdio")
        || !matches!(protocol.as_str(), "http" | "jsonrpc")
        || path.is_empty()
    {
        return None;
    }
    let raw_actions = map.get("actions")?.as_object()?;
    let mut actions = BTreeMap::new();
    for (action_name, raw_action) in raw_actions {
        let action = raw_action.as_object()?;
        let request = action
            .get("request")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let method = action
            .get("method")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if protocol == "http" && request.is_none() {
            continue;
        }
        if protocol == "jsonrpc" && method.is_none() {
            continue;
        }
        let select = action
            .get("select")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        actions.insert(
            action_name.clone(),
            Action {
                request,
                method,
                select,
                description: action
                    .get("description")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                params_schema: action.get("params").cloned().filter(Value::is_object),
            },
        );
    }
    if actions.is_empty() {
        return None;
    }

    let timeout_seconds = map
        .get("timeout_s")
        .and_then(Value::as_f64)
        .unwrap_or(30.0)
        .clamp(0.1, 300.0);
    let compatibility = valid_compatibility(map.get("compatibility"), &protocol);
    Some(Endpoint {
        name: name.to_owned(),
        transport,
        protocol,
        path,
        timeout: Duration::from_secs_f64(timeout_seconds),
        run_as: map.get("run_as").and_then(Value::as_str).map(str::to_owned),
        actions,
        compatibility,
    })
}

fn endpoints(policy: &Policy) -> BTreeMap<String, Endpoint> {
    policy
        .local_apis
        .iter()
        .filter_map(|(name, raw)| {
            endpoint_from_raw(name, raw).map(|endpoint| (name.clone(), endpoint))
        })
        .collect()
}

#[must_use]
pub fn has_usable_endpoints(policy: &Policy) -> bool {
    endpoints(policy)
        .values()
        .any(|endpoint| endpoint.transport == "unix")
}

fn param_names(action: &Action) -> Vec<String> {
    if let Some(schema) = action.params_schema.as_ref().and_then(Value::as_object) {
        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
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
    }
    let mut names = Vec::new();
    if let Some(request) = action.request.as_deref() {
        let bytes = request.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'{' {
                if let Some(end) = request[index + 1..].find('}') {
                    let name = &request[index + 1..index + 1 + end];
                    if !name.is_empty() && !names.iter().any(|existing| existing == name) {
                        names.push(name.to_owned());
                    }
                    index += end + 2;
                    continue;
                }
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
    if let Some(start) = output.find('{') {
        if let Some(end) = output[start + 1..].find('}') {
            let missing = &output[start + 1..start + 1 + end];
            return Err(HandlerError::new(
                "missing_param",
                format!("the action needs a value for {missing:?}"),
            ));
        }
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

async fn read_http_body(stream: UnixStream) -> Result<Value, HandlerError> {
    let mut reader = BufReader::new(stream);
    let mut header = Vec::new();
    loop {
        let mut line = Vec::new();
        let read = reader
            .read_until(b'\n', &mut line)
            .await
            .map_err(|e| HandlerError::new("bad_response", e.to_string()))?;
        if read == 0 {
            return Err(HandlerError::new(
                "bad_response",
                "endpoint closed before HTTP headers completed",
            ));
        }
        header.extend(&line);
        if header.ends_with(b"\r\n\r\n") || header.ends_with(b"\n\n") {
            break;
        }
        if header.len() > 128 * 1024 {
            return Err(HandlerError::new("too_large", "HTTP headers exceeded cap"));
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
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse::<usize>().ok();
            }
            if name.eq_ignore_ascii_case("transfer-encoding")
                && value.trim().eq_ignore_ascii_case("chunked")
            {
                chunked = true;
            }
        }
    }

    let body = if chunked {
        let mut body = Vec::new();
        loop {
            let mut size_line = String::new();
            reader
                .read_line(&mut size_line)
                .await
                .map_err(|e| HandlerError::new("bad_response", e.to_string()))?;
            let size_text = size_line.trim().split(';').next().unwrap_or("0");
            let size = usize::from_str_radix(size_text, 16)
                .map_err(|_| HandlerError::new("bad_response", "invalid chunk size"))?;
            if size == 0 {
                let mut trailer = String::new();
                let _ = reader.read_line(&mut trailer).await;
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
                .map_err(|e| HandlerError::new("bad_response", e.to_string()))?;
            let mut crlf = [0_u8; 2];
            reader
                .read_exact(&mut crlf)
                .await
                .map_err(|e| HandlerError::new("bad_response", e.to_string()))?;
        }
        body
    } else {
        let length = content_length.unwrap_or(0);
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
                .map_err(|e| HandlerError::new("bad_response", e.to_string()))?;
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

async fn call_via_run_as(endpoint: &Endpoint, payload: &[u8]) -> Result<Vec<u8>, HandlerError> {
    let executable = std::env::current_exe()
        .map_err(|error| HandlerError::new("internal_error", error.to_string()))?;
    let argv = relay_command(endpoint, &executable)?;
    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);

    let mut child = command.spawn().map_err(|error| {
        HandlerError::new(
            "run_as_not_permitted",
            format!("could not start run_as relay: {error}"),
        )
    })?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| HandlerError::new("internal_error", "run_as relay stdin was not piped"))?;
    stdin
        .write_all(payload)
        .await
        .map_err(|error| HandlerError::new("bad_response", error.to_string()))?;
    drop(stdin);

    let output = timeout(
        endpoint.timeout + Duration::from_secs(5),
        child.wait_with_output(),
    )
    .await
    .map_err(|_| {
        HandlerError::new(
            "timeout",
            format!("{} did not answer in time", endpoint.name),
        )
    })?
    .map_err(|error| HandlerError::new("bad_response", error.to_string()))?;

    if output.status.success() && !output.stdout.is_empty() {
        return Ok(output.stdout);
    }

    let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let rc = output.status.code().unwrap_or(-1);
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
        call_via_run_as(endpoint, &encoded).await?
    } else {
        let mut stream = connect(endpoint).await?;
        timeout(endpoint.timeout, stream.write_all(&encoded))
            .await
            .map_err(|_| HandlerError::new("timeout", "timed out writing request"))?
            .map_err(|e| HandlerError::new("endpoint_unreachable", e.to_string()))?;

        let mut reader = BufReader::new(stream);
        let mut line = Vec::new();
        timeout(endpoint.timeout, reader.read_until(b'\n', &mut line))
            .await
            .map_err(|_| HandlerError::new("timeout", "endpoint did not answer in time"))?
            .map_err(|e| HandlerError::new("bad_response", e.to_string()))?;
        line
    };

    if line.len() > MAX_RESPONSE_BYTES {
        return Err(HandlerError::new(
            "too_large",
            "endpoint response exceeded the cap",
        ));
    }
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

async fn ensure_compatible(endpoint: &Endpoint) -> Result<(), HandlerError> {
    let Some(constraint) = endpoint.compatibility.as_ref().and_then(Value::as_object) else {
        return Ok(());
    };
    if constraint.is_empty() {
        return Ok(());
    }

    if let Some(verdict) = compat_cache()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&endpoint.name)
        .cloned()
    {
        return match verdict {
            CompatVerdict::Passed => Ok(()),
            CompatVerdict::Failed { code, message } => Err(HandlerError::new(code, message)),
        };
    }

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
        call_jsonrpc(endpoint, &probe_action, &Map::new()).await
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
            let message = format!(
                "could not read compatibility metadata {extract_path:?} from {:?}: {}",
                endpoint.name, error.message
            );
            compat_cache()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(
                    endpoint.name.clone(),
                    CompatVerdict::Failed {
                        code: "compatibility_unknown".into(),
                        message: message.clone(),
                    },
                );
            return Err(HandlerError::new("compatibility_unknown", message));
        }
    };

    let Some(found) = extract(&response, extract_path) else {
        let message = format!(
            "{:?} did not report {extract_path:?}, so its compatibility cannot be established",
            endpoint.name
        );
        compat_cache()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                endpoint.name.clone(),
                CompatVerdict::Failed {
                    code: "compatibility_unknown".into(),
                    message: message.clone(),
                },
            );
        return Err(HandlerError::new("compatibility_unknown", message));
    };

    let accepted = if let Some(exact) = accept.get("exact") {
        found == exact
    } else if let Some(allowed) = accept.get("allowed").and_then(Value::as_array) {
        allowed.iter().any(|value| value == found)
    } else {
        false
    };

    let mut cache = compat_cache()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if accepted {
        cache.insert(endpoint.name.clone(), CompatVerdict::Passed);
        Ok(())
    } else {
        let message = format!(
            "{:?} reports {extract_path}={found}, which is not accepted by this profile",
            endpoint.name
        );
        cache.insert(
            endpoint.name.clone(),
            CompatVerdict::Failed {
                code: "compatibility_mismatch".into(),
                message: message.clone(),
            },
        );
        Err(HandlerError::new("compatibility_mismatch", message))
    }
}

async fn call_action(
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
    ensure_compatible(endpoint).await?;
    let raw = match if endpoint.protocol == "http" {
        call_http(endpoint, action, params).await
    } else {
        call_jsonrpc(endpoint, action, params).await
    } {
        Ok(raw) => raw,
        Err(error) => {
            if matches!(error.code.as_str(), "endpoint_unreachable" | "timeout") {
                forget_compatibility(&endpoint.name);
            }
            return Err(error);
        }
    };
    Ok(project(raw, &action.select))
}

pub async fn handle(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let endpoints = endpoints(policy);
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
        let result = call_action(endpoint, action, &params).await?;
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
    fn half_written_compatibility_constraint_is_dropped() {
        let raw: yaml_serde::Value = yaml_serde::from_str(
            "transport: unix\nprotocol: jsonrpc\npath: /tmp/x.sock\ncompatibility:\n  accept: { exact: 20 }\nactions:\n  a: { method: a }\n",
        )
        .unwrap();
        let endpoint = endpoint_from_raw("x", &raw).unwrap();
        assert!(endpoint.compatibility.is_none());
    }

    #[test]
    fn run_as_endpoint_remains_usable_and_relay_has_no_shell() {
        let raw: yaml_serde::Value = yaml_serde::from_str(
            "transport: unix\nprotocol: jsonrpc\npath: /run/user/1002/x.sock\nrun_as: userx\nactions:\n  a: { method: a }\n",
        )
        .unwrap();
        let endpoint = endpoint_from_raw("ep", &raw).unwrap();
        let argv = relay_command(&endpoint, Path::new("/usr/local/bin/sentinelx-core")).unwrap();
        assert_eq!(
            &argv[..5],
            &[
                "sudo".to_owned(),
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
