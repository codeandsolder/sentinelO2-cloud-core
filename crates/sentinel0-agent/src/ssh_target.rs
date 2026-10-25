use crate::process_output::read_bounded_async;
use openssh::{ControlPersist, KnownHosts, Session, SessionBuilder, Stdio};
use serde::{Deserialize, Serialize};
use std::{io, time::Duration};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};

const CAPTURE_PER_STREAM: usize = 2 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SERVER_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
const LOCAL_TIMEOUT_GRACE: u64 = 15;
const CWD_EXEC: &str = r#"cd -- "$1" || exit 126; shift; exec "$@""#;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RequestKind {
    Shell,
    Argv,
    Bash,
    Python,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    id: u64,
    kind: RequestKind,
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    argv: Vec<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    sudo: bool,
    #[serde(default = "default_timeout")]
    timeout_seconds: u64,
}

const fn default_timeout() -> u64 {
    60
}

#[derive(Debug, Serialize)]
struct Ready<'a> {
    ready: bool,
    destination: &'a str,
}

#[derive(Debug, Serialize)]
struct Response {
    id: u64,
    ok: bool,
    returncode: i32,
    stdout: String,
    stderr: String,
    stdout_bytes: u64,
    stderr_bytes: u64,
    output_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn request_program(request: &Request) -> Result<(Vec<String>, Option<&[u8]>), String> {
    let (mut argv, stdin) = match request.kind {
        RequestKind::Shell => {
            let command = request
                .command
                .as_deref()
                .ok_or_else(|| "shell request requires command".to_owned())?;
            (vec!["bash".into(), "-c".into(), command.into()], None)
        }
        RequestKind::Argv => {
            if request.argv.is_empty() {
                return Err("argv request requires a non-empty argv".into());
            }
            (request.argv.clone(), None)
        }
        RequestKind::Bash => {
            let source = request
                .source
                .as_deref()
                .ok_or_else(|| "bash request requires source".to_owned())?;
            let mut argv = vec!["bash".into(), "-s".into(), "--".into()];
            argv.extend(request.args.iter().cloned());
            (argv, Some(source.as_bytes()))
        }
        RequestKind::Python => {
            let source = request
                .source
                .as_deref()
                .ok_or_else(|| "python request requires source".to_owned())?;
            let mut argv = vec![
                "uv".into(),
                "run".into(),
                "--no-project".into(),
                "--python".into(),
                "3".into(),
                "python".into(),
                "-".into(),
            ];
            argv.extend(request.args.iter().cloned());
            (argv, Some(source.as_bytes()))
        }
    };

    if request.timeout_seconds == 0 || request.timeout_seconds > 3600 {
        return Err("timeout_seconds must be between 1 and 3600".into());
    }
    argv.splice(
        0..0,
        [
            "timeout".into(),
            "--signal=KILL".into(),
            "--kill-after=1".into(),
            format!("{}s", request.timeout_seconds),
        ],
    );
    Ok((argv, stdin))
}

fn remote_command<'a>(
    session: &'a Session,
    request: &Request,
    argv: &[String],
) -> Result<openssh::Command<'a>, String> {
    let (program, rest) = argv
        .split_first()
        .ok_or_else(|| "remote argv was unexpectedly empty".to_owned())?;

    if let Some(cwd) = request.cwd.as_deref() {
        if request.sudo {
            let mut command = session.command("sudo");
            command
                .arg("-n")
                .arg("--")
                .arg("bash")
                .arg("-c")
                .arg(CWD_EXEC)
                .arg("bash")
                .arg(cwd)
                .arg(program)
                .args(rest);
            return Ok(command);
        }
        let mut command = session.command("bash");
        command
            .arg("-c")
            .arg(CWD_EXEC)
            .arg("bash")
            .arg(cwd)
            .arg(program)
            .args(rest);
        return Ok(command);
    }

    if request.sudo {
        let mut command = session.command("sudo");
        command.arg("-n").arg("--").arg(program).args(rest);
        return Ok(command);
    }

    let mut command = session.command(program);
    command.args(rest);
    Ok(command)
}

fn error_response(id: u64, error: &(impl ToString + ?Sized)) -> Response {
    Response {
        id,
        ok: false,
        returncode: -1,
        stdout: String::new(),
        stderr: String::new(),
        stdout_bytes: 0,
        stderr_bytes: 0,
        output_truncated: false,
        error: Some(error.to_string()),
    }
}

async fn execute(session: &Session, request: &Request) -> Response {
    let (argv, input) = match request_program(request) {
        Ok(parts) => parts,
        Err(error) => return error_response(request.id, &error),
    };
    let mut command = match remote_command(session, request, &argv) {
        Ok(command) => command,
        Err(error) => return error_response(request.id, &error),
    };
    command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = match command.spawn().await {
        Ok(child) => child,
        Err(error) => return error_response(request.id, &error),
    };
    let stdin = child.stdin().take();
    let stdout = child.stdout().take();
    let stderr = child.stderr().take();
    let Some(stdout) = stdout else {
        return error_response(request.id, "SSH child stdout was not piped");
    };
    let Some(stderr) = stderr else {
        return error_response(request.id, "SSH child stderr was not piped");
    };

    let stdout_task = tokio::spawn(read_bounded_async(stdout, CAPTURE_PER_STREAM));
    let stderr_task = tokio::spawn(read_bounded_async(stderr, CAPTURE_PER_STREAM));
    let input_owned = input.map(<[u8]>::to_vec);
    let stdin_task = tokio::spawn(async move {
        match (stdin, input_owned) {
            (Some(mut stdin), Some(input)) => stdin.write_all(&input).await,
            (None, Some(_)) => Err(io::Error::other("SSH child stdin was not piped")),
            (_, None) => Ok(()),
        }
    });

    let local_limit =
        Duration::from_secs(request.timeout_seconds.saturating_add(LOCAL_TIMEOUT_GRACE));
    let collect = async move {
        let stdin_result = stdin_task
            .await
            .map_err(|error| format!("SSH stdin task failed: {error}"))?
            .map_err(|error| format!("SSH stdin write failed: {error}"));
        stdin_result?;
        let stdout = stdout_task
            .await
            .map_err(|error| format!("SSH stdout task failed: {error}"))?
            .map_err(|error| format!("SSH stdout read failed: {error}"))?;
        let stderr = stderr_task
            .await
            .map_err(|error| format!("SSH stderr task failed: {error}"))?
            .map_err(|error| format!("SSH stderr read failed: {error}"))?;
        // openssh documents that wait() can terminate its local ssh process before
        // separately-held pipe readers consume their final bytes. Drain both pipes
        // to EOF first, then reap the remote child.
        let status = child
            .wait()
            .await
            .map_err(|error| format!("SSH child wait failed: {error}"))?;
        Ok::<_, String>((status, stdout, stderr))
    };
    let (status, stdout, stderr) = match tokio::time::timeout(local_limit, collect).await {
        Ok(Ok(captured)) => captured,
        Ok(Err(error)) => return error_response(request.id, &error),
        Err(_) => {
            let message = format!(
                "SSH command exceeded local timeout after remote timeout of {}s",
                request.timeout_seconds
            );
            return error_response(request.id, &message);
        }
    };
    let returncode = status.code().unwrap_or(-1);
    Response {
        id: request.id,
        ok: returncode == 0,
        returncode,
        stdout: String::from_utf8_lossy(&stdout.rendered()).into_owned(),
        stderr: String::from_utf8_lossy(&stderr.rendered()).into_owned(),
        stdout_bytes: stdout.total_bytes(),
        stderr_bytes: stderr.total_bytes(),
        output_truncated: stdout.truncated() || stderr.truncated(),
        error: None,
    }
}

async fn write_json_line<T: Serialize + Sync>(
    stdout: &mut tokio::io::Stdout,
    value: &T,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut encoded = serde_json::to_vec(value)?;
    encoded.push(b'\n');
    stdout.write_all(&encoded).await?;
    stdout.flush().await?;
    Ok(())
}

/// Run the hidden NDJSON SSH execution-target helper used by staged Python scripts.
///
/// # Errors
/// Returns an error if the OpenSSH session or helper protocol fails.
pub async fn run_helper(destination: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut builder = SessionBuilder::default();
    builder
        .known_hosts_check(KnownHosts::Add)
        .connect_timeout(CONNECT_TIMEOUT)
        .server_alive_interval(SERVER_ALIVE_INTERVAL)
        .control_persist(ControlPersist::ClosedAfterInitialConnection);
    let session = builder.connect(destination).await?;

    let stdin = tokio::io::stdin();
    let mut lines = BufReader::new(stdin).lines();
    let mut stdout = tokio::io::stdout();
    write_json_line(
        &mut stdout,
        &Ready {
            ready: true,
            destination,
        },
    )
    .await?;

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let request = match serde_json::from_str::<Request>(&line) {
            Ok(request) => request,
            Err(error) => {
                write_json_line(&mut stdout, &error_response(0, &error)).await?;
                continue;
            }
        };
        let response = execute(&session, &request).await;
        write_json_line(&mut stdout, &response).await?;
    }
    session.close().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TestResult, TestValue as _};

    #[test]
    fn argv_request_keeps_data_as_argv() -> TestResult {
        let request: Request = serde_json::from_value(serde_json::json!({
            "id": 1,
            "kind": "argv",
            "argv": ["printf", "%s", "$(touch /tmp/nope); ' quoted"],
            "timeout_seconds": 30
        }))
        .test_value()?;
        let (argv, input) = request_program(&request).test_value()?;
        assert!(input.is_none());
        assert_eq!(
            &argv[..4],
            &["timeout", "--signal=KILL", "--kill-after=1", "30s"]
        );
        assert_eq!(
            &argv[4..],
            &["printf", "%s", "$(touch /tmp/nope); ' quoted"]
        );
        Ok(())
    }

    #[test]
    fn source_request_uses_stdin() -> TestResult {
        let request: Request = serde_json::from_value(serde_json::json!({
            "id": 2,
            "kind": "bash",
            "source": "printf '%s\\n' hello",
            "args": ["literal $()"],
        }))
        .test_value()?;
        let (argv, input) = request_program(&request).test_value()?;
        assert_eq!(&argv[4..7], &["bash", "-s", "--"]);
        assert_eq!(input, Some(b"printf '%s\\n' hello".as_slice()));
        Ok(())
    }

    #[test]
    fn invalid_timeout_is_rejected() {
        let request = Request {
            id: 3,
            kind: RequestKind::Argv,
            command: None,
            argv: vec!["true".into()],
            source: None,
            args: Vec::new(),
            cwd: None,
            sudo: false,
            timeout_seconds: 0,
        };
        assert!(request_program(&request).is_err());
    }
}
