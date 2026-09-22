use crate::{
    handler_error::{HandlerError, HandlerResult, require_str},
    policy::Policy,
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

async fn run_git(
    root: &Path,
    args: &[String],
    stdin: Option<&[u8]>,
    limit: Duration,
) -> Result<(i32, Vec<u8>, Vec<u8>), HandlerError> {
    let mut command = Command::new("git");
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
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }

    let mut child = command
        .spawn()
        .map_err(|e| HandlerError::new("git_failed", format!("failed to start git: {e}")))?;

    if let Some(input) = stdin {
        let Some(mut pipe) = child.stdin.take() else {
            return Err(HandlerError::new("git_failed", "git stdin was unavailable"));
        };
        pipe.write_all(input).await.map_err(|e| {
            HandlerError::new("git_failed", format!("failed writing git stdin: {e}"))
        })?;
        drop(pipe);
    }

    match timeout(limit, child.wait_with_output()).await {
        Ok(Ok(output)) => Ok((
            output.status.code().unwrap_or(-1),
            output.stdout,
            output.stderr,
        )),
        Ok(Err(e)) => Err(HandlerError::new("git_failed", format!("git failed: {e}"))),
        Err(_) => Err(HandlerError::new(
            "git_timeout",
            format!(
                "git {} timed out",
                args.first().map(String::as_str).unwrap_or("?")
            ),
        )),
    }
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
    let (rc, out, err) = run_git(&start, &args, None, LOCAL_TIMEOUT).await?;
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

fn status_name(letter: char) -> &'static str {
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

fn parse_name_status(raw: &[u8]) -> Vec<(String, String, Option<String>)> {
    let tokens = raw
        .split(|byte| *byte == 0)
        .map(|token| String::from_utf8_lossy(token).into_owned())
        .collect::<Vec<_>>();
    let mut out = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        if tokens[i].is_empty() {
            i += 1;
            continue;
        }
        let letter = tokens[i].chars().next().unwrap_or('?');
        if matches!(letter, 'R' | 'C') {
            if i + 2 >= tokens.len() {
                break;
            }
            out.push((
                tokens[i + 2].clone(),
                status_name(letter).into(),
                Some(tokens[i + 1].clone()),
            ));
            i += 3;
        } else {
            if i + 1 >= tokens.len() {
                break;
            }
            out.push((tokens[i + 1].clone(), status_name(letter).into(), None));
            i += 2;
        }
    }
    out
}

async fn diff(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let requested = require_str(payload, "path")?;
    let root = git_root(policy, requested, false).await?;
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
        .clamp(1, 50) as usize;
    let max_patch = payload
        .get("max_patch_bytes")
        .and_then(Value::as_u64)
        .unwrap_or(MAX_DIFF_PATCH as u64)
        .clamp(1024, MAX_DIFF_PATCH as u64) as usize;

    let selector = if staged && unstaged {
        vec!["diff".into(), base_ref.into()]
    } else if staged {
        vec!["diff".into(), "--cached".into(), base_ref.into()]
    } else {
        vec!["diff".into()]
    };

    let mut args = selector.clone();
    args.extend(["--no-ext-diff".into(), "--numstat".into(), "-z".into()]);
    let (_, numstat, _) = run_git(&root, &args, None, LOCAL_TIMEOUT).await?;
    let (files_total, insertions, deletions) = parse_numstat(&numstat);

    let mut args = selector.clone();
    args.extend(["--no-ext-diff".into(), "--name-status".into(), "-z".into()]);
    let (_, names, _) = run_git(&root, &args, None, LOCAL_TIMEOUT).await?;
    let changed = parse_name_status(&names);

    let untracked = if include_untracked {
        let args = vec![
            "ls-files".into(),
            "--others".into(),
            "--exclude-standard".into(),
            "-z".into(),
        ];
        let (_, out, _) = run_git(&root, &args, None, LOCAL_TIMEOUT).await?;
        String::from_utf8_lossy(&out)
            .split('\0')
            .filter(|path| !path.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    let mut entries = Vec::new();
    let mut truncated_files = changed.len() > max_files;
    let mut truncated_patch = false;
    for (path, status, old_path) in changed.into_iter().take(max_files) {
        let mut patch_args = selector.clone();
        patch_args.extend([
            "--no-ext-diff".into(),
            format!("--unified={context}"),
            "--".into(),
        ]);
        if let Some(old) = old_path.as_ref() {
            patch_args.push(old.clone());
        }
        patch_args.push(path.clone());
        let (_, patch, _) = run_git(&root, &patch_args, None, LOCAL_TIMEOUT).await?;
        let patch_value = if patch.len() <= max_patch {
            Value::String(String::from_utf8_lossy(&patch).into_owned())
        } else {
            truncated_patch = true;
            Value::Null
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

    let room = max_files.saturating_sub(entries.len());
    for path in untracked.iter().take(room) {
        entries.push(json!({
            "path": path,
            "status": "untracked",
            "insertions": 0,
            "deletions": 0,
            "binary": false,
            "patch": null,
        }));
    }
    if untracked.len() > room {
        truncated_files = true;
    }

    Ok(BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("version".into(), Value::from(1)),
        ("root".into(), Value::String(root.display().to_string())),
        ("base_ref".into(), Value::String(base_ref.into())),
        (
            "summary".into(),
            json!({
                "files": files_total,
                "insertions": insertions,
                "deletions": deletions,
                "untracked": untracked.len(),
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
        let mut path = raw.split('\t').next().unwrap_or("").trim();
        if path == "/dev/null" || path.is_empty() {
            continue;
        }
        if let Some(rest) = path.strip_prefix("a/").or_else(|| path.strip_prefix("b/")) {
            path = rest;
        }
        if !out.iter().any(|existing| existing == path) {
            out.push(path.to_owned());
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

    let mut recounted = false;
    let invoke = |extra: Vec<String>| {
        let mut args = vec!["apply".into()];
        args.extend(extra);
        args.extend(["--no-3way".into(), "-".into()]);
        args
    };

    let num_args = invoke(vec!["--numstat".into()]);
    let (mut ns_rc, mut ns_out, ns_err) =
        run_git(&root, &num_args, Some(patch.as_bytes()), LOCAL_TIMEOUT).await?;
    if ns_rc != 0 && String::from_utf8_lossy(&ns_err).contains("corrupt patch") {
        let mut args = vec!["apply".into(), "--recount".into(), "--numstat".into()];
        args.extend(["--no-3way".into(), "-".into()]);
        let (retry_rc, retry_out, _) =
            run_git(&root, &args, Some(patch.as_bytes()), LOCAL_TIMEOUT).await?;
        ns_rc = retry_rc;
        ns_out = retry_out;
        if ns_rc == 0 {
            recounted = true;
        }
    }
    let (_, insertions, deletions) = parse_numstat(&ns_out);
    let files = patch_paths(patch).len() as u64;

    let mut check_args = vec!["apply".into()];
    if recounted {
        check_args.push("--recount".into());
    }
    check_args.extend(["--check".into(), "--no-3way".into(), "-".into()]);
    let (rc, _, err) = run_git(&root, &check_args, Some(patch.as_bytes()), LOCAL_TIMEOUT).await?;
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
        let (rc, _, err) =
            run_git(&root, &apply_args, Some(patch.as_bytes()), LOCAL_TIMEOUT).await?;
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
    let (rc, out, err) = run_git(&root, &args, None, NET_TIMEOUT).await?;
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
    let (rc, _, err) = run_git(&root, &args, None, NET_TIMEOUT).await?;
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

async fn clone_repo(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let url = require_str(payload, "url")?;
    let dest = require_str(payload, "dest")?;
    let Some(target) = policy.resolve_path(dest, true) else {
        return Err(HandlerError::new(
            "path_not_allowed",
            "clone destination must be under a file_ops rw path",
        ));
    };
    if target.exists()
        && target
            .read_dir()
            .map(|mut iter| iter.next().is_some())
            .unwrap_or(true)
    {
        return Err(HandlerError::new(
            "dest_not_empty",
            "clone refuses to write into a non-empty destination",
        ));
    }
    let parent = target.parent().unwrap_or(Path::new("."));
    let mut args = vec!["clone".into()];
    if let Some(depth) = payload.get("depth").and_then(Value::as_u64) {
        args.extend(["--depth".into(), depth.clamp(1, 1000).to_string()]);
    }
    if let Some(branch) = payload.get("branch").and_then(Value::as_str) {
        args.extend(["--branch".into(), branch.into()]);
    }
    args.extend([url.into(), target.display().to_string()]);
    let (rc, _, err) = run_git(parent, &args, None, NET_TIMEOUT).await?;
    if rc != 0 {
        if target.exists() {
            let _ = std::fs::remove_dir_all(&target);
        }
        return Err(HandlerError::new("remote_failed", scrub(&err, parent)));
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
    let (rc, _, err) = run_git(&root, &args, None, NET_TIMEOUT).await?;
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
    async fn wrong_hunk_counts_are_recounted_in_dry_run() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("f.txt"),
            (1..=10).map(|i| format!("line{i}\n")).collect::<String>(),
        )
        .unwrap();
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
                    .unwrap()
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
        .unwrap();
        assert_eq!(result.get("recounted"), Some(&Value::Bool(true)));
    }

    #[tokio::test]
    async fn force_push_without_lease_is_refused_before_network() {
        let dir = tempdir().unwrap();
        std::process::Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(["init", "-q"])
            .status()
            .unwrap();
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
        .unwrap_err();
        assert_eq!(error.code, "force_requires_lease");
    }
}
