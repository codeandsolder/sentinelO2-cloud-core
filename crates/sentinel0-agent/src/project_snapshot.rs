use crate::{
    handler_error::{HandlerError, HandlerResult, require_str},
    policy::Policy,
    process_output::{WaitOutcome, wait_bounded_with_limits},
};
use serde_json::{Map, Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    path::Path,
    process::Stdio,
    time::Duration,
};
use tokio::process::Command;

const MAX_TOP_DIRS: usize = 40;
const MAX_EXTENSIONS: usize = 40;
const MAX_RECENT_COMMITS: usize = 10;
const GIT_TIMEOUT: Duration = Duration::from_secs(10);
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
                "failed checking project-snapshot git state after {reason}: {error}; refusing PID-based group signal"
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
                let message = format!("failed killing project-snapshot git process group: {error}");
                tracing::warn!(pid, %message);
                cleanup_error.get_or_insert(message);
            }
        } else {
            cleanup_error.get_or_insert_with(|| {
                "project-snapshot git PID unavailable; process group not killed".into()
            });
        }
    }

    #[cfg(not(unix))]
    if should_kill && let Err(error) = child.kill().await {
        let message = format!("failed killing project-snapshot git child: {error}");
        tracing::warn!(%message);
        cleanup_error.get_or_insert(message);
    }

    if let Err(error) = child.wait().await {
        let message = format!("failed reaping project-snapshot git child: {error}");
        tracing::warn!(%message);
        cleanup_error.get_or_insert(message);
    }
    cleanup_error
}

async fn run_git(
    policy: &Policy,
    root: &Path,
    args: &[&str],
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

    let mut child = command
        .spawn()
        .map_err(|e| HandlerError::new("git_failed", e.to_string()))?;
    let pid = child.id();
    let captured =
        match wait_bounded_with_limits(&mut child, GIT_TIMEOUT, MAX_GIT_STDOUT, MAX_GIT_STDERR)
            .await
        {
            Ok(WaitOutcome::Completed(captured)) => captured,
            Ok(WaitOutcome::TimedOut) => {
                let cleanup_error = cleanup_git_child(&mut child, pid, "timeout").await;
                let mut details = Map::new();
                if let Some(error) = cleanup_error {
                    details.insert("cleanup_error".into(), Value::String(error));
                }
                return Err(HandlerError::with_details(
                    "git_timeout",
                    "git command timed out",
                    details,
                ));
            }
            Err(error) => {
                let cleanup_error = cleanup_git_child(&mut child, pid, "I/O failure").await;
                let mut details = Map::new();
                if let Some(error) = cleanup_error {
                    details.insert("cleanup_error".into(), Value::String(error));
                }
                return Err(HandlerError::with_details(
                    "git_failed",
                    format!("git output capture failed: {error}"),
                    details,
                ));
            }
        };

    if captured.stdout.truncated() {
        return Err(HandlerError::with_details(
            "git_output_too_large",
            format!(
                "git {} output exceeded capture ceiling",
                args.first().unwrap_or(&"?")
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

fn require_git_success(operation: &str, rc: i32, stderr: &[u8]) -> Result<(), HandlerError> {
    if rc == 0 {
        return Ok(());
    }
    let detail = String::from_utf8_lossy(stderr)
        .trim()
        .chars()
        .take(2000)
        .collect::<String>();
    Err(HandlerError::new(
        "git_failed",
        format!("git {operation} failed (rc={rc}): {detail}"),
    ))
}

fn extension(name: &str) -> &str {
    if let Some((_, ext)) = name.rsplit_once('.')
        && !ext.is_empty()
        && (!name.starts_with('.') || name[1..].contains('.'))
    {
        return ext;
    }
    if name.starts_with('.') {
        "<dotfile>"
    } else {
        "<none>"
    }
}

fn top_counts<'a>(
    paths: impl IntoIterator<Item = &'a str>,
) -> (usize, Vec<String>, BTreeMap<String, Value>, bool) {
    let mut tracked = 0_usize;
    let mut top: HashMap<String, usize> = HashMap::new();
    let mut exts: HashMap<String, usize> = HashMap::new();
    for path in paths {
        tracked += 1;
        if let Some((head, _)) = path.split_once('/') {
            *top.entry(head.to_owned()).or_default() += 1;
        }
        let name = path.rsplit('/').next().unwrap_or(path);
        *exts
            .entry(extension(name).to_ascii_lowercase())
            .or_default() += 1;
    }

    let mut top_items = top.into_iter().collect::<Vec<_>>();
    top_items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let top_truncated = top_items.len() > MAX_TOP_DIRS;
    let top_dirs = top_items
        .into_iter()
        .take(MAX_TOP_DIRS)
        .map(|(name, _)| name)
        .collect::<Vec<_>>();

    let mut ext_items = exts.into_iter().collect::<Vec<_>>();
    ext_items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let ext_map = ext_items
        .into_iter()
        .take(MAX_EXTENSIONS)
        .map(|(name, count)| (name, Value::from(count as u64)))
        .collect::<BTreeMap<_, _>>();
    (tracked, top_dirs, ext_map, top_truncated)
}

fn parse_status(raw: &[u8]) -> Map<String, Value> {
    let mut branch = Value::Null;
    let mut detached = false;
    let mut head = Value::Null;
    let mut ahead = 0_u64;
    let mut behind = 0_u64;
    let mut staged = 0_u64;
    let mut unstaged = 0_u64;
    let mut untracked = 0_u64;

    let mut records = raw.split(|byte| *byte == 0);
    while let Some(record) = records.next() {
        let line = String::from_utf8_lossy(record);
        if let Some(value) = line.strip_prefix("# branch.head ") {
            let value = value.trim();
            if value == "(detached)" {
                detached = true;
            } else {
                branch = Value::String(value.into());
            }
        } else if let Some(value) = line.strip_prefix("# branch.oid ") {
            let value = value.trim();
            if value != "(initial)" {
                head = Value::String(value.chars().take(12).collect());
            }
        } else if let Some(value) = line.strip_prefix("# branch.ab ") {
            for part in value.split_whitespace() {
                if let Some(value) = part.strip_prefix('+') {
                    ahead = value.parse().unwrap_or(0);
                } else if let Some(value) = part.strip_prefix('-') {
                    behind = value.parse().unwrap_or(0);
                }
            }
        } else if line.starts_with("1 ") || line.starts_with("2 ") {
            let xy = line.split_whitespace().nth(1).unwrap_or("..").as_bytes();
            if xy.first().copied().unwrap_or(b'.') != b'.' {
                staged += 1;
            }
            if xy.get(1).copied().unwrap_or(b'.') != b'.' {
                unstaged += 1;
            }
            if line.starts_with("2 ") {
                let _ = records.next();
            }
        } else if line.starts_with("? ") {
            untracked += 1;
        }
    }

    Map::from_iter([
        ("branch".into(), branch),
        ("detached".into(), Value::Bool(detached)),
        ("head".into(), head),
        ("ahead".into(), Value::from(ahead)),
        ("behind".into(), Value::from(behind)),
        (
            "dirty".into(),
            Value::Bool(staged != 0 || unstaged != 0 || untracked != 0),
        ),
        ("staged".into(), Value::from(staged)),
        ("unstaged".into(), Value::from(unstaged)),
        ("untracked".into(), Value::from(untracked)),
    ])
}

fn sum_numstat(raw: &[u8]) -> (u64, u64, u64) {
    let mut files = 0_u64;
    let mut ins = 0_u64;
    let mut dels = 0_u64;
    for token in raw.split(|byte| *byte == 0) {
        let line = String::from_utf8_lossy(token);
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() >= 2 {
            files += 1;
            ins += fields[0].parse().unwrap_or(0);
            dels += fields[1].parse().unwrap_or(0);
        }
    }
    (files, ins, dels)
}

async fn git_snapshot(
    policy: &Policy,
    root: &Path,
) -> Result<BTreeMap<String, Value>, HandlerError> {
    let (status_rc, status_raw, status_err) = run_git(
        policy,
        root,
        &["status", "--porcelain=v2", "--branch", "-z"],
    )
    .await?;
    require_git_success("status", status_rc, &status_err)?;
    let status = parse_status(&status_raw);

    let (unstaged_rc, unstaged_raw, unstaged_err) =
        run_git(policy, root, &["diff", "--no-ext-diff", "--numstat", "-z"]).await?;
    require_git_success("diff --numstat", unstaged_rc, &unstaged_err)?;
    let (staged_rc, staged_raw, staged_err) = run_git(
        policy,
        root,
        &["diff", "--cached", "--no-ext-diff", "--numstat", "-z"],
    )
    .await?;
    require_git_success("diff --cached --numstat", staged_rc, &staged_err)?;
    let (_, ui, ud) = sum_numstat(&unstaged_raw);
    let (_, si, sd) = sum_numstat(&staged_raw);

    let (files_rc, files_raw, files_err) = run_git(policy, root, &["ls-files", "-z"]).await?;
    require_git_success("ls-files", files_rc, &files_err)?;
    let decoded_files = String::from_utf8_lossy(&files_raw);
    let (tracked_files, top_dirs, extensions, top_truncated) = top_counts(
        decoded_files
            .split(char::from(0))
            .filter(|path| !path.is_empty()),
    );

    let (log_rc, log_raw, log_err) = run_git(
        policy,
        root,
        &[
            "log",
            "-10",
            "--no-color",
            "--pretty=format:%h%x1f%s%x1f%an%x1f%ad",
            "--date=short",
        ],
    )
    .await?;
    if log_rc != 0 && !status.get("head").is_some_and(|head| head.is_null()) {
        require_git_success("log", log_rc, &log_err)?;
    }
    let commits = String::from_utf8_lossy(&log_raw)
        .lines()
        .filter_map(|line| {
            let fields = line.split('\x1f').collect::<Vec<_>>();
            (fields.len() == 4).then(|| {
                json!({
                    "hash": fields[0],
                    "subject": fields[1].chars().take(120).collect::<String>(),
                    "author": fields[2],
                    "date": fields[3],
                })
            })
        })
        .take(MAX_RECENT_COMMITS)
        .collect::<Vec<_>>();

    Ok(BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("version".into(), Value::from(1)),
        ("root".into(), Value::String(root.display().to_string())),
        ("kind".into(), Value::String("git".into())),
        (
            "git".into(),
            json!({
                "branch": status.get("branch"),
                "detached": status.get("detached"),
                "head": status.get("head"),
                "ahead": status.get("ahead"),
                "behind": status.get("behind"),
                "dirty": status.get("dirty"),
            }),
        ),
        (
            "changes".into(),
            json!({
                "staged": status.get("staged"),
                "unstaged": status.get("unstaged"),
                "untracked": status.get("untracked"),
                "insertions": ui + si,
                "deletions": ud + sd,
            }),
        ),
        (
            "repository".into(),
            json!({
                "tracked_files": tracked_files,
                "top_directories": top_dirs,
                "extensions": extensions,
            }),
        ),
        ("recent_commits".into(), Value::Array(commits)),
        (
            "truncated".into(),
            json!({
                "top_directories": top_truncated,
                "recent_commits": false,
            }),
        ),
    ]))
}

fn directory_snapshot(root: &Path) -> HandlerResult {
    const MAX_SCAN_ERRORS: usize = 32;
    let mut dirs: HashMap<String, usize> = HashMap::new();
    let mut exts: HashMap<String, usize> = HashMap::new();
    let mut files = 0_usize;
    let mut truncated = false;
    let mut scan_error_count = 0_u64;
    let mut scan_errors = Vec::new();
    for entry in fs::read_dir(root).map_err(|e| {
        HandlerError::new("permission_denied", format!("cannot read directory: {e}"))
    })? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                scan_error_count = scan_error_count.saturating_add(1);
                if scan_errors.len() < MAX_SCAN_ERRORS {
                    scan_errors.push(Value::String(format!("directory entry: {error}")));
                }
                continue;
            }
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        let kind = match entry.file_type() {
            Ok(kind) => kind,
            Err(error) => {
                scan_error_count = scan_error_count.saturating_add(1);
                if scan_errors.len() < MAX_SCAN_ERRORS {
                    scan_errors.push(Value::String(format!("{name}: {error}")));
                }
                continue;
            }
        };
        if kind.is_dir() {
            *dirs.entry(name).or_default() += 1;
        } else {
            files += 1;
            *exts
                .entry(extension(&name).to_ascii_lowercase())
                .or_default() += 1;
        }
        if files > 5000 {
            truncated = true;
            break;
        }
    }
    let mut dir_items = dirs.into_iter().collect::<Vec<_>>();
    dir_items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let mut ext_items = exts.into_iter().collect::<Vec<_>>();
    ext_items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    Ok(BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("version".into(), Value::from(1)),
        ("root".into(), Value::String(root.display().to_string())),
        ("kind".into(), Value::String("directory".into())),
        (
            "repository".into(),
            json!({
                "top_directories": dir_items.into_iter().take(MAX_TOP_DIRS).map(|x| x.0).collect::<Vec<_>>(),
                "extensions": ext_items.into_iter().take(MAX_EXTENSIONS).collect::<BTreeMap<_,_>>(),
                "file_count": files,
            }),
        ),
        ("scan_error_count".into(), Value::from(scan_error_count)),
        ("scan_errors".into(), Value::Array(scan_errors)),
        ("truncated".into(), json!({"file_count": truncated})),
    ]))
}

async fn directory_snapshot_async(root: std::path::PathBuf) -> HandlerResult {
    tokio::task::spawn_blocking(move || directory_snapshot(&root))
        .await
        .map_err(|error| {
            HandlerError::new(
                "internal_error",
                format!("directory snapshot worker failed: {error}"),
            )
        })?
}

pub async fn handle(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let requested = require_str(payload, "path")?;
    let root = policy.resolve_path(requested, false).ok_or_else(|| {
        HandlerError::new(
            "path_not_allowed",
            format!("path {requested:?} is outside file_ops paths"),
        )
    })?;
    if !root.exists() {
        return Err(HandlerError::new("not_found", "path does not exist"));
    }
    if !root.is_dir() {
        return Err(HandlerError::new(
            "is_file",
            "project_snapshot expects a directory",
        ));
    }

    let (rc, out, err) = run_git(policy, &root, &["rev-parse", "--show-toplevel"]).await?;
    if rc == 0 && !out.is_empty() {
        let git_root_text = String::from_utf8_lossy(&out).trim().to_owned();
        if let Some(git_root) = policy.resolve_path(&git_root_text, false) {
            return git_snapshot(policy, &git_root).await;
        }
    }
    let mut result = directory_snapshot_async(root.clone()).await?;
    if String::from_utf8_lossy(&err).contains("dubious ownership") {
        result.insert(
            "git_unavailable".into(),
            Value::String(
                "This is a git checkout, but git refuses it because of dubious ownership.".into(),
            ),
        );
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{FileAccess, FileOpsPath};
    use tempfile::tempdir;

    #[tokio::test]
    async fn plain_directory_gets_bounded_summary() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("a.rs"), "fn main(){}").unwrap();
        fs::create_dir(dir.path().join("src")).unwrap();
        let policy = Policy {
            file_ops_paths: vec![FileOpsPath {
                path: dir.path().to_owned(),
                access: FileAccess::Read,
            }],
            ..Policy::default()
        };
        let result = handle(
            &policy,
            &Map::from_iter([(
                "path".into(),
                Value::String(dir.path().display().to_string()),
            )]),
        )
        .await
        .unwrap();
        assert_eq!(result["kind"], "directory");
        assert_eq!(result["repository"]["file_count"], 1);
    }

    #[test]
    fn top_counts_streams_paths_without_materializing_the_inventory() {
        let paths = ["src/lib.rs", "src/main.rs", "README", ".gitignore"];
        let (tracked, top, extensions, truncated) = top_counts(paths);
        assert_eq!(tracked, 4);
        assert_eq!(top, vec!["src"]);
        assert_eq!(extensions["rs"], 2);
        assert_eq!(extensions["<none>"], 1);
        assert_eq!(extensions["<dotfile>"], 1);
        assert!(!truncated);
    }
}
