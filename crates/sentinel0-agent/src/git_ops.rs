use crate::{
    handler_error::{HandlerError, HandlerResult, require_str},
    policy::Policy,
    process_output::capture_bounded,
};
use serde_json::{Map, Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{io::AsyncWriteExt, process::Command, time::timeout};

const LOCAL_TIMEOUT: Duration = Duration::from_secs(15);
const NET_TIMEOUT: Duration = Duration::from_secs(50);
const MAX_PATCH: usize = 5 * 1024 * 1024;
const MAX_DIFF_PATCH: usize = 128 * 1024;
const MAX_GIT_STDOUT: usize = 32 * 1024 * 1024;
const MAX_GIT_STDERR: usize = 1024 * 1024;

async fn cleanup_git_child(
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
                "failed checking git child state after {reason}: {error}; refusing PID-based group signal"
            );
            tracing::warn!(%message);
            cleanup_error = Some(message);
            false
        }
    };

    #[cfg(unix)]
    if should_kill {
        if let Some(pid) = pid {
            let process_group = nix::unistd::Pid::from_raw(pid.cast_signed());
            if let Err(error) =
                nix::sys::signal::killpg(process_group, nix::sys::signal::Signal::SIGKILL)
                && error != nix::errno::Errno::ESRCH
            {
                let message = format!("failed killing git process group: {error}");
                tracing::warn!(pid, %message);
                cleanup_error.get_or_insert(message);
            }
        } else {
            cleanup_error
                .get_or_insert_with(|| "git PID unavailable; process group not killed".into());
        }
    }

    #[cfg(not(unix))]
    if should_kill && let Err(error) = child.kill().await {
        let message = format!("failed killing git child: {error}");
        tracing::warn!(%message);
        cleanup_error.get_or_insert(message);
    }

    if let Err(error) = child.wait().await {
        let message = format!("failed reaping git child: {error}");
        tracing::warn!(%message);
        cleanup_error.get_or_insert(message);
    }
    cleanup_error
}

async fn run_git(
    policy: &Policy,
    root: &Path,
    args: &[String],
    stdin: Option<&[u8]>,
    limit: Duration,
) -> Result<(i32, Vec<u8>, Vec<u8>), HandlerError> {
    let mut command = Command::new(policy.tooling.command("git"));
    command
        .arg("-C")
        .arg(root)
        .arg("-c")
        .arg("core.fsmonitor=false")
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_PAGER", "cat")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("LC_ALL", "C")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    policy.tooling.configure_tokio(&mut command)?;

    if stdin.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }

    let mut child = command
        .spawn()
        .map_err(|e| HandlerError::new("git_failed", format!("failed to start git: {e}")))?;
    let pid = child.id();
    let mut stdin_pipe = child.stdin.take();

    let work = async {
        let capture = capture_bounded(&mut child, MAX_GIT_STDOUT, MAX_GIT_STDERR);
        if let Some(input) = stdin {
            let mut pipe = stdin_pipe
                .take()
                .ok_or_else(|| std::io::Error::other("git stdin was unavailable"))?;
            let write = async move {
                pipe.write_all(input).await?;
                drop(pipe);
                Ok::<(), std::io::Error>(())
            };
            let ((), captured) = tokio::try_join!(write, capture)?;
            Ok::<_, std::io::Error>(captured)
        } else {
            capture.await
        }
    };

    let captured = match timeout(limit, work).await {
        Ok(Ok(captured)) => captured,
        Ok(Err(error)) => {
            let cleanup_error = cleanup_git_child(&mut child, pid, "I/O failure").await;
            let mut details = Map::new();
            if let Some(error) = cleanup_error {
                details.insert("cleanup_error".into(), Value::String(error));
            }
            return Err(HandlerError::with_details(
                "git_failed",
                format!("git I/O failed: {error}"),
                details,
            ));
        }
        Err(_) => {
            let cleanup_error = cleanup_git_child(&mut child, pid, "timeout").await;
            let mut details = Map::new();
            if let Some(error) = cleanup_error {
                details.insert("cleanup_error".into(), Value::String(error));
            }
            return Err(HandlerError::with_details(
                "git_timeout",
                format!("git {} timed out", args.first().map_or("?", String::as_str)),
                details,
            ));
        }
    };

    if captured.stdout.truncated() {
        return Err(HandlerError::with_details(
            "git_output_too_large",
            format!(
                "git {} stdout exceeded the {MAX_GIT_STDOUT} byte capture ceiling",
                args.first().map_or("?", String::as_str)
            ),
            Map::from_iter([(
                "stdout_bytes".into(),
                Value::from(captured.stdout.total_bytes()),
            )]),
        ));
    }

    Ok((
        captured.status.code().unwrap_or(-1),
        captured.stdout.rendered(),
        captured.stderr.rendered(),
    ))
}

async fn run_git_capped_stdout(
    policy: &Policy,
    root: &Path,
    args: &[String],
    cap: usize,
    limit: Duration,
) -> Result<(i32, Vec<u8>, Vec<u8>, bool), HandlerError> {
    let mut command = Command::new(policy.tooling.command("git"));
    command
        .arg("-C")
        .arg(root)
        .arg("-c")
        .arg("core.fsmonitor=false")
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_PAGER", "cat")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    policy.tooling.configure_tokio(&mut command)?;

    let mut child = command
        .spawn()
        .map_err(|e| HandlerError::new("git_failed", format!("failed to start git: {e}")))?;
    let pid = child.id();
    let captured = match timeout(
        limit,
        capture_bounded(&mut child, cap.saturating_add(1), MAX_GIT_STDERR),
    )
    .await
    {
        Ok(Ok(captured)) => captured,
        Ok(Err(error)) => {
            let cleanup_error = cleanup_git_child(&mut child, pid, "I/O failure").await;
            let mut details = Map::new();
            if let Some(error) = cleanup_error {
                details.insert("cleanup_error".into(), Value::String(error));
            }
            return Err(HandlerError::with_details(
                "git_failed",
                format!("git I/O failed: {error}"),
                details,
            ));
        }
        Err(_) => {
            let cleanup_error = cleanup_git_child(&mut child, pid, "timeout").await;
            let mut details = Map::new();
            if let Some(error) = cleanup_error {
                details.insert("cleanup_error".into(), Value::String(error));
            }
            return Err(HandlerError::with_details(
                "git_timeout",
                format!("git {} timed out", args.first().map_or("?", String::as_str)),
                details,
            ));
        }
    };

    let exceeded = captured.stdout.total_bytes() > cap as u64;
    Ok((
        captured.status.code().unwrap_or(-1),
        captured.stdout.rendered(),
        captured.stderr.rendered(),
        exceeded,
    ))
}

fn scrub(bytes: &[u8], root: &Path) -> String {
    let root = root.display().to_string();
    String::from_utf8_lossy(bytes)
        .replace(&(root.clone() + "/"), "")
        .replace(&root, "")
        .trim()
        .chars()
        .take(2000)
        .collect()
}

async fn git_root(policy: &Policy, requested: &str, write: bool) -> Result<PathBuf, HandlerError> {
    let Some(start) = policy.resolve_path(requested, write) else {
        return Err(HandlerError::new(
            "path_not_allowed",
            format!("git path {requested:?} is outside the file_ops allowlist"),
        ));
    };
    if !start.exists() {
        return Err(HandlerError::new(
            "not_found",
            format!("path does not exist: {requested:?}"),
        ));
    }
    if !start.is_dir() {
        return Err(HandlerError::new(
            "is_file",
            "git expects a directory or a path inside a repository",
        ));
    }
    let args = vec!["rev-parse".into(), "--show-toplevel".into()];
    let (rc, out, err) = run_git(policy, &start, &args, None, LOCAL_TIMEOUT).await?;
    if rc != 0 || out.is_empty() {
        let text = String::from_utf8_lossy(&err).to_lowercase();
        if text.contains("dubious ownership") {
            return Err(HandlerError::new(
                "git_dubious_ownership",
                "git refuses this repository because of dubious ownership; fix ownership or configure safe.directory for the agent account",
            ));
        }
        if text.contains("permission denied") && !text.contains("publickey") {
            return Err(HandlerError::new(
                "permission_denied",
                "the agent account cannot read this repository",
            ));
        }
        return Err(HandlerError::new(
            "not_a_git_repo",
            format!(
                "{requested:?} is not inside a git repository; retrying the same path will not change that"
            ),
        ));
    }
    let root_text = String::from_utf8_lossy(&out).trim().to_owned();
    policy.resolve_path(&root_text, write).ok_or_else(|| {
        HandlerError::new(
            "git_root_outside_allowlist",
            format!("repository root {root_text:?} lies outside the required file_ops boundary"),
        )
    })
}

fn parse_numstat(raw: &[u8]) -> (u64, u64, u64) {
    let mut files = 0;
    let mut ins = 0;
    let mut dels = 0;
    for token in raw.split(|byte| *byte == 0) {
        let line = String::from_utf8_lossy(token);
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() < 2 {
            continue;
        }
        if fields[0].parse::<u64>().is_ok() || fields[0] == "-" {
            files += 1;
            ins += fields[0].parse::<u64>().unwrap_or(0);
            dels += fields[1].parse::<u64>().unwrap_or(0);
        }
    }
    (files, ins, dels)
}

const fn status_name(letter: char) -> &'static str {
    match letter {
        'A' => "added",
        'M' => "modified",
        'D' => "deleted",
        'R' => "renamed",
        'C' => "copied",
        'T' => "typechange",
        'U' => "unmerged",
        _ => "changed",
    }
}

fn parse_name_status(raw: &[u8], keep: usize) -> (Vec<(String, String, Option<String>)>, usize) {
    let mut tokens = raw.split(|byte| *byte == 0);
    let mut out = Vec::with_capacity(keep);
    let mut total = 0_usize;

    while let Some(status_raw) = tokens.next() {
        if status_raw.is_empty() {
            continue;
        }
        let status = String::from_utf8_lossy(status_raw);
        let letter = status.chars().next().unwrap_or('?');

        let (path, old_path) = if matches!(letter, 'R' | 'C') {
            let Some(old_raw) = tokens.next() else { break };
            let Some(path_raw) = tokens.next() else { break };
            (
                String::from_utf8_lossy(path_raw).into_owned(),
                Some(String::from_utf8_lossy(old_raw).into_owned()),
            )
        } else {
            let Some(path_raw) = tokens.next() else { break };
            (String::from_utf8_lossy(path_raw).into_owned(), None)
        };

        total += 1;
        if out.len() < keep {
            out.push((path, status_name(letter).into(), old_path));
        }
    }

    (out, total)
}

struct DiffOptions<'a> {
    base_ref: &'a str,
    staged: bool,
    unstaged: bool,
    include_untracked: bool,
    context: u64,
    max_files: usize,
    max_patch: usize,
}

fn diff_options(payload: &Map<String, Value>) -> Result<DiffOptions<'_>, HandlerError> {
    let base_ref = payload
        .get("base_ref")
        .and_then(Value::as_str)
        .unwrap_or("HEAD");
    let staged = payload
        .get("staged")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let unstaged = payload
        .get("unstaged")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    if !staged && !unstaged {
        return Err(HandlerError::new(
            "invalid_payload",
            "at least one of staged / unstaged must be true",
        ));
    }
    let include_untracked = payload
        .get("include_untracked")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let context = payload
        .get("context_lines")
        .and_then(Value::as_u64)
        .unwrap_or(3)
        .min(10);
    let max_files = payload
        .get("max_files")
        .and_then(Value::as_u64)
        .unwrap_or(50)
        .clamp(1, 50);
    let max_files = usize::try_from(max_files).unwrap_or(50);
    let max_patch_limit = u64::try_from(MAX_DIFF_PATCH).unwrap_or(u64::MAX);
    let max_patch = payload
        .get("max_patch_bytes")
        .and_then(Value::as_u64)
        .unwrap_or(max_patch_limit)
        .clamp(1024, max_patch_limit);
    let max_patch = usize::try_from(max_patch).unwrap_or(MAX_DIFF_PATCH);
    Ok(DiffOptions {
        base_ref,
        staged,
        unstaged,
        include_untracked,
        context,
        max_files,
        max_patch,
    })
}

async fn collect_untracked(
    policy: &Policy,
    root: &Path,
    max_files: usize,
    include: bool,
) -> Result<(Vec<String>, usize), HandlerError> {
    if !include {
        return Ok((Vec::new(), 0));
    }
    let args = vec![
        "ls-files".into(),
        "--others".into(),
        "--exclude-standard".into(),
        "-z".into(),
    ];
    let (_, out, _) = run_git(policy, root, &args, None, LOCAL_TIMEOUT).await?;
    let decoded = String::from_utf8_lossy(&out);
    let mut kept = Vec::with_capacity(max_files);
    let mut total = 0_usize;
    for path in decoded.split(char::from(0)).filter(|path| !path.is_empty()) {
        total += 1;
        if kept.len() < max_files {
            kept.push(path.to_owned());
        }
    }
    Ok((kept, total))
}

async fn diff(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let requested = require_str(payload, "path")?;
    let root = git_root(policy, requested, false).await?;
    let options = diff_options(payload)?;
    let selector = if options.staged && options.unstaged {
        vec!["diff".into(), options.base_ref.into()]
    } else if options.staged {
        vec!["diff".into(), "--cached".into(), options.base_ref.into()]
    } else {
        vec!["diff".into()]
    };

    let mut args = selector.clone();
    args.extend(["--no-ext-diff".into(), "--numstat".into(), "-z".into()]);
    let (_, numstat, _) = run_git(policy, &root, &args, None, LOCAL_TIMEOUT).await?;
    let (files_total, insertions, deletions) = parse_numstat(&numstat);

    let mut args = selector.clone();
    args.extend(["--no-ext-diff".into(), "--name-status".into(), "-z".into()]);
    let (_, names, _) = run_git(policy, &root, &args, None, LOCAL_TIMEOUT).await?;
    let (changed, changed_total) = parse_name_status(&names, options.max_files);

    let (untracked, untracked_total) =
        collect_untracked(policy, &root, options.max_files, options.include_untracked).await?;
    let mut entries = Vec::new();
    let mut truncated_files = changed_total > options.max_files;
    let mut truncated_patch = false;
    for (path, status, old_path) in changed {
        let mut patch_args = selector.clone();
        patch_args.extend([
            "--no-ext-diff".into(),
            format!("--unified={}", options.context),
            "--".into(),
        ]);
        if let Some(old) = old_path.as_ref() {
            patch_args.push(old.clone());
        }
        patch_args.push(path.clone());
        // The API already promises to omit patches larger than max_patch.
        // Do not first buffer an arbitrarily large diff just to discover that
        // it exceeds that limit: retain at most max_patch + 1 bytes while
        // continuing to drain git to completion.
        let (_, patch, _, patch_exceeded) =
            run_git_capped_stdout(policy, &root, &patch_args, options.max_patch, LOCAL_TIMEOUT)
                .await?;
        let patch_value = if patch_exceeded {
            truncated_patch = true;
            Value::Null
        } else {
            Value::String(String::from_utf8_lossy(&patch).into_owned())
        };
        let mut entry = Map::from_iter([
            ("path".into(), Value::String(path)),
            ("status".into(), Value::String(status)),
            ("patch".into(), patch_value),
        ]);
        if let Some(old) = old_path {
            entry.insert("old_path".into(), Value::String(old));
        }
        entries.push(Value::Object(entry));
    }

    let remaining_slots = options.max_files.saturating_sub(entries.len());
    for path in untracked.iter().take(remaining_slots) {
        entries.push(json!({
            "path": path,
            "status": "untracked",
            "insertions": 0,
            "deletions": 0,
            "binary": false,
            "patch": null,
        }));
    }
    if untracked_total > remaining_slots {
        truncated_files = true;
    }

    Ok(BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("version".into(), Value::from(1)),
        ("root".into(), Value::String(root.display().to_string())),
        ("base_ref".into(), Value::String(options.base_ref.into())),
        (
            "summary".into(),
            json!({
                "files": files_total,
                "insertions": insertions,
                "deletions": deletions,
                "untracked": untracked_total,
            }),
        ),
        ("files".into(), Value::Array(entries)),
        (
            "truncated".into(),
            json!({"files": truncated_files, "patch": truncated_patch}),
        ),
    ]))
}

fn patch_paths(patch: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in patch.lines() {
        let raw = line
            .strip_prefix("--- ")
            .or_else(|| line.strip_prefix("+++ "));
        let Some(raw) = raw else { continue };
        let mut file_path = raw.split('\t').next().unwrap_or("").trim();
        if file_path == "/dev/null" || file_path.is_empty() {
            continue;
        }
        if let Some(rest) = file_path
            .strip_prefix("a/")
            .or_else(|| file_path.strip_prefix("b/"))
        {
            file_path = rest;
        }
        if !out.iter().any(|existing| existing == file_path) {
            out.push(file_path.to_owned());
        }
    }
    out
}

fn validate_patch_paths(
    policy: &Policy,
    root: &Path,
    paths: &[String],
) -> Result<(), HandlerError> {
    for path in paths {
        let rel = Path::new(path);
        if rel.is_absolute()
            || rel
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(HandlerError::new(
                "patch_unsafe_path",
                format!("unsafe patch path: {path:?}"),
            ));
        }
        let candidate = root.join(rel);
        let Some(resolved) = policy.resolve_path(candidate.to_string_lossy().as_ref(), true) else {
            return Err(HandlerError::new(
                "path_not_allowed",
                format!("patch touches a path outside the rw allowlist: {path:?}"),
            ));
        };
        if resolved != root && !resolved.starts_with(root) {
            return Err(HandlerError::new(
                "patch_unsafe_path",
                format!("patch path escapes repository root: {path:?}"),
            ));
        }
    }
    Ok(())
}

async fn patch_numstat(
    policy: &Policy,
    root: &Path,
    patch: &str,
) -> Result<(bool, Vec<u8>), HandlerError> {
    let invoke = |extra: Vec<String>| {
        let mut args = vec!["apply".into()];
        args.extend(extra);
        args.extend(["--no-3way".into(), "-".into()]);
        args
    };
    let num_args = invoke(vec!["--numstat".into()]);
    let (mut rc, mut out, err) = run_git(
        policy,
        root,
        &num_args,
        Some(patch.as_bytes()),
        LOCAL_TIMEOUT,
    )
    .await?;
    let recounted = if rc != 0 && String::from_utf8_lossy(&err).contains("corrupt patch") {
        let args = invoke(vec!["--recount".into(), "--numstat".into()]);
        let (retry_rc, retry_out, _) =
            run_git(policy, root, &args, Some(patch.as_bytes()), LOCAL_TIMEOUT).await?;
        rc = retry_rc;
        out = retry_out;
        rc == 0
    } else {
        false
    };
    Ok((recounted, out))
}

async fn apply_patch(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let requested = payload
        .get("root")
        .or_else(|| payload.get("path"))
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| HandlerError::new("invalid_payload", "apply_patch requires root or path"))?;
    let patch = require_str(payload, "patch")?;
    if patch.len() > MAX_PATCH {
        return Err(HandlerError::new(
            "invalid_payload",
            "patch exceeds 5 MiB ceiling",
        ));
    }
    let dry_run = payload
        .get("dry_run")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let root = git_root(policy, requested, true).await?;
    let paths = patch_paths(patch);
    if paths.is_empty() {
        return Err(HandlerError::new(
            "invalid_payload",
            "could not find target paths in unified diff",
        ));
    }
    validate_patch_paths(policy, &root, &paths)?;

    let (recounted, numstat) = patch_numstat(policy, &root, patch).await?;
    let (_, insertions, deletions) = parse_numstat(&numstat);
    let files = patch_paths(patch).len() as u64;

    let mut check_args = vec!["apply".into()];
    if recounted {
        check_args.push("--recount".into());
    }
    check_args.extend(["--check".into(), "--no-3way".into(), "-".into()]);
    let (rc, _, err) = run_git(
        policy,
        &root,
        &check_args,
        Some(patch.as_bytes()),
        LOCAL_TIMEOUT,
    )
    .await?;
    if rc != 0 {
        return Err(HandlerError::new(
            "patch_does_not_apply",
            scrub(&err, &root),
        ));
    }

    if !dry_run {
        let mut apply_args = vec!["apply".into()];
        if recounted {
            apply_args.push("--recount".into());
        }
        apply_args.extend(["--no-3way".into(), "-".into()]);
        let (rc, _, err) = run_git(
            policy,
            &root,
            &apply_args,
            Some(patch.as_bytes()),
            LOCAL_TIMEOUT,
        )
        .await?;
        if rc != 0 {
            return Err(HandlerError::new(
                "patch_does_not_apply",
                scrub(&err, &root),
            ));
        }
    }

    let mut result = BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("version".into(), Value::from(1)),
        ("applied".into(), Value::Bool(!dry_run)),
        ("dry_run".into(), Value::Bool(dry_run)),
        ("root".into(), Value::String(root.display().to_string())),
        (
            "summary".into(),
            json!({"files": files, "insertions": insertions, "deletions": deletions}),
        ),
    ]);
    if recounted {
        result.insert("recounted".into(), Value::Bool(true));
    }
    Ok(result)
}

async fn ls_remote(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let remote = payload
        .get("remote")
        .and_then(Value::as_str)
        .unwrap_or("origin");
    let root = if let Some(path) = payload.get("path").and_then(Value::as_str) {
        git_root(policy, path, false).await?
    } else {
        std::env::current_dir().map_err(|e| HandlerError::new("io_error", e.to_string()))?
    };
    let mut args = vec!["ls-remote".into(), remote.into()];
    if let Some(pattern) = payload.get("ref_pattern").and_then(Value::as_str) {
        args.push(pattern.into());
    }
    let (rc, out, err) = run_git(policy, &root, &args, None, NET_TIMEOUT).await?;
    if rc != 0 {
        return Err(HandlerError::new(
            "remote_failed",
            format!("git ls-remote failed: {}", scrub(&err, &root)),
        ));
    }
    let refs = String::from_utf8_lossy(&out)
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .take(200)
        .map(|(sha, reference)| json!({"sha": sha.trim(), "ref": reference.trim()}))
        .collect::<Vec<_>>();
    let count = refs.len();
    Ok(BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("version".into(), Value::from(1)),
        ("operation".into(), Value::String("ls_remote".into())),
        ("remote".into(), Value::String(remote.into())),
        ("refs".into(), Value::Array(refs)),
        ("count".into(), Value::from(count as u64)),
    ]))
}

async fn fetch(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let path = require_str(payload, "path")?;
    let root = git_root(policy, path, false).await?;
    let remote = payload
        .get("remote")
        .and_then(Value::as_str)
        .unwrap_or("origin");
    let mut args = vec!["fetch".into(), "--prune".into(), remote.into()];
    if let Some(reference) = payload.get("ref").and_then(Value::as_str) {
        args.push(reference.into());
    }
    let (rc, _, err) = run_git(policy, &root, &args, None, NET_TIMEOUT).await?;
    if rc != 0 {
        return Err(HandlerError::new("remote_failed", scrub(&err, &root)));
    }
    Ok(BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("version".into(), Value::from(1)),
        ("operation".into(), Value::String("fetch".into())),
        ("root".into(), Value::String(root.display().to_string())),
        ("remote".into(), Value::String(remote.into())),
        ("output".into(), Value::String(scrub(&err, &root))),
    ]))
}

fn directory_nonempty_or_unreadable(path: &Path) -> bool {
    let Ok(mut entries) = path.read_dir() else {
        return true;
    };
    entries.next().is_some()
}

async fn clone_repo(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let url = require_str(payload, "url")?;
    let dest = require_str(payload, "dest")?;
    let Some(target) = policy.resolve_path(dest, true) else {
        return Err(HandlerError::new(
            "path_not_allowed",
            "clone destination must be under a file_ops rw path",
        ));
    };
    let destination_nonempty = directory_nonempty_or_unreadable(&target);
    if target.exists() && destination_nonempty {
        return Err(HandlerError::new(
            "dest_not_empty",
            "clone refuses to write into a non-empty destination",
        ));
    }
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    let mut args = vec!["clone".into()];
    if let Some(depth) = payload.get("depth").and_then(Value::as_u64) {
        args.extend(["--depth".into(), depth.clamp(1, 1000).to_string()]);
    }
    if let Some(branch) = payload.get("branch").and_then(Value::as_str) {
        args.extend(["--branch".into(), branch.into()]);
    }
    args.extend([url.into(), target.display().to_string()]);
    let (rc, _, err) = run_git(policy, parent, &args, None, NET_TIMEOUT).await?;
    if rc != 0 {
        let mut message = scrub(&err, parent);
        if target.exists()
            && let Err(error) = std::fs::remove_dir_all(&target)
        {
            let cleanup = format!(
                "failed cleaning partial clone {}: {error}",
                target.display()
            );
            tracing::warn!(%cleanup);
            message = format!("{message}; {cleanup}");
        }
        return Err(HandlerError::new("remote_failed", message));
    }
    Ok(BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("version".into(), Value::from(1)),
        ("operation".into(), Value::String("clone".into())),
        ("root".into(), Value::String(target.display().to_string())),
        ("url".into(), Value::String(url.into())),
    ]))
}

async fn push(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let path = require_str(payload, "path")?;
    let root = git_root(policy, path, false).await?;
    let remote = payload
        .get("remote")
        .and_then(Value::as_str)
        .unwrap_or("origin");
    let branch = require_str(payload, "branch")?;
    let force = payload
        .get("force")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let expected = payload.get("expected_remote_sha").and_then(Value::as_str);
    if force && expected.is_none() {
        return Err(HandlerError::new(
            "force_requires_lease",
            "forced push requires expected_remote_sha",
        ));
    }
    let mut args = vec!["push".into()];
    if let Some(expected) = expected.filter(|_| force) {
        args.push(format!("--force-with-lease={branch}:{expected}"));
    }
    args.extend([remote.into(), branch.into()]);
    let (rc, _, err) = run_git(policy, &root, &args, None, NET_TIMEOUT).await?;
    let output = scrub(&err, &root);
    if rc != 0 {
        if output.to_lowercase().contains("stale info") {
            return Err(HandlerError::new(
                "lease_stale",
                "remote branch changed; force-with-lease refused the push",
            ));
        }
        return Err(HandlerError::new("remote_failed", output));
    }
    Ok(BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("version".into(), Value::from(1)),
        ("operation".into(), Value::String("push".into())),
        ("root".into(), Value::String(root.display().to_string())),
        ("remote".into(), Value::String(remote.into())),
        ("branch".into(), Value::String(branch.into())),
        ("forced".into(), Value::Bool(force)),
        ("output".into(), Value::String(output)),
    ]))
}

/// # Errors
/// Returns an error when the Git request is invalid, disallowed, times out, or Git fails.
pub async fn handle(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    match payload.get("operation").and_then(Value::as_str) {
        Some("diff") => diff(policy, payload).await,
        Some("apply_patch") => apply_patch(policy, payload).await,
        Some("ls_remote") => ls_remote(policy, payload).await,
        Some("fetch") => fetch(policy, payload).await,
        Some("clone") => clone_repo(policy, payload).await,
        Some("push") => push(policy, payload).await,
        other => Err(HandlerError::new(
            "invalid_payload",
            format!(
                "git operation must be diff, apply_patch, ls_remote, fetch, clone or push (got {other:?})"
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{FileAccess, FileOpsPath};
    use crate::test_support::{TestError as _, TestResult, TestValue as _};
    use tempfile::tempdir;

    fn policy(root: &Path, write: bool) -> Policy {
        Policy {
            file_ops_paths: vec![FileOpsPath {
                path: root.to_owned(),
                access: if write {
                    FileAccess::ReadWrite
                } else {
                    FileAccess::Read
                },
            }],
            ..Policy::default()
        }
    }

    #[tokio::test]
    async fn wrong_hunk_counts_are_recounted_in_dry_run() -> TestResult {
        let dir = tempdir().test_value()?;
        std::fs::write(
            dir.path().join("f.txt"),
            (1..=10).fold(String::new(), |mut output, i| {
                output.push_str("line");
                output.push_str(&i.to_string());
                output.push('\n');
                output
            }),
        )
        .test_value()?;
        for args in [
            vec!["init", "-q"],
            vec!["add", "f.txt"],
            vec![
                "-c",
                "user.email=t@t",
                "-c",
                "user.name=t",
                "commit",
                "-qm",
                "init",
            ],
        ] {
            assert!(
                std::process::Command::new("git")
                    .arg("-C")
                    .arg(dir.path())
                    .args(args)
                    .status()
                    .test_value()?
                    .success()
            );
        }
        let patch =
            "--- a/f.txt\n+++ b/f.txt\n@@ -3,9 +3,9 @@ line2\n line3\n line4\n+INSERTED\n line5\n";
        let result = handle(
            &policy(dir.path(), true),
            &Map::from_iter([
                ("operation".into(), Value::String("apply_patch".into())),
                (
                    "path".into(),
                    Value::String(dir.path().display().to_string()),
                ),
                ("patch".into(), Value::String(patch.into())),
                ("dry_run".into(), Value::Bool(true)),
            ]),
        )
        .await
        .test_value()?;
        assert_eq!(result.get("recounted"), Some(&Value::Bool(true)));

        Ok(())
    }

    #[tokio::test]
    async fn force_push_without_lease_is_refused_before_network() -> TestResult {
        let dir = tempdir().test_value()?;
        std::process::Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(["init", "-q"])
            .status()
            .test_value()?;
        let error = handle(
            &policy(dir.path(), false),
            &Map::from_iter([
                ("operation".into(), Value::String("push".into())),
                (
                    "path".into(),
                    Value::String(dir.path().display().to_string()),
                ),
                ("branch".into(), Value::String("main".into())),
                ("force".into(), Value::Bool(true)),
            ]),
        )
        .await
        .test_error()?;
        assert_eq!(error.code, "force_requires_lease");

        Ok(())
    }

    #[tokio::test]
    async fn capped_git_stdout_drains_without_retaining_the_full_patch() -> TestResult {
        let dir = tempdir().test_value()?;
        std::fs::write(dir.path().join("big.txt"), "changed line\n".repeat(10_000)).test_value()?;
        let args = vec![
            "diff".into(),
            "--no-index".into(),
            "--".into(),
            "/dev/null".into(),
            "big.txt".into(),
        ];

        let (rc, stdout, _, exceeded) = run_git_capped_stdout(
            &Policy::default(),
            dir.path(),
            &args,
            1024,
            Duration::from_secs(60),
        )
        .await
        .test_value()?;

        assert_eq!(rc, 1);
        assert!(exceeded);
        assert!(
            stdout.len() <= 1024 + 128,
            "rendered bounded output should retain roughly the cap plus a small omission marker"
        );
        assert!(
            String::from_utf8_lossy(&stdout).contains("bytes omitted by SentinelO2"),
            "truncated output should explain the omission"
        );

        Ok(())
    }

    #[test]
    fn name_status_parser_counts_all_but_keeps_only_requested_prefix() {
        let raw = b"M\0a.txt\0R100\0old.txt\0new.txt\0A\0z.txt\0";
        let (rows, total) = parse_name_status(raw, 2);
        assert_eq!(total, 3);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], ("a.txt".into(), "modified".into(), None));
        assert_eq!(
            rows[1],
            ("new.txt".into(), "renamed".into(), Some("old.txt".into()))
        );
    }
}
