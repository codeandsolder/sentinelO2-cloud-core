use crate::{
    handler_error::{HandlerError, HandlerResult, require_str},
    policy::Policy,
};
use serde_json::{Map, Value, json};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    path::Path,
    process::Stdio,
    time::Duration,
};
use tokio::{process::Command, time::timeout};

const MAX_TOP_DIRS: usize = 40;
const MAX_EXTENSIONS: usize = 40;
const MAX_RECENT_COMMITS: usize = 10;
const GIT_TIMEOUT: Duration = Duration::from_secs(10);

async fn run_git(root: &Path, args: &[&str]) -> Result<(i32, Vec<u8>, Vec<u8>), HandlerError> {
    let child = Command::new("git")
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
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| HandlerError::new("git_failed", e.to_string()))?;
    match timeout(GIT_TIMEOUT, child.wait_with_output()).await {
        Ok(Ok(out)) => Ok((out.status.code().unwrap_or(-1), out.stdout, out.stderr)),
        Ok(Err(e)) => Err(HandlerError::new("git_failed", e.to_string())),
        Err(_) => Err(HandlerError::new("git_timeout", "git command timed out")),
    }
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

fn top_counts(paths: &[String]) -> (Vec<String>, BTreeMap<String, Value>, bool) {
    let mut top: HashMap<String, usize> = HashMap::new();
    let mut exts: HashMap<String, usize> = HashMap::new();
    for path in paths {
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
    (top_dirs, ext_map, top_truncated)
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

    let records = raw.split(|byte| *byte == 0).collect::<Vec<_>>();
    let mut index = 0;
    while index < records.len() {
        let line = String::from_utf8_lossy(records[index]);
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
                index += 1;
            }
        } else if line.starts_with("? ") {
            untracked += 1;
        }
        index += 1;
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

async fn git_snapshot(root: &Path) -> Result<BTreeMap<String, Value>, HandlerError> {
    let (_, status_raw, _) = run_git(root, &["status", "--porcelain=v2", "--branch", "-z"]).await?;
    let status = parse_status(&status_raw);

    let (_, unstaged_raw, _) = run_git(root, &["diff", "--no-ext-diff", "--numstat", "-z"]).await?;
    let (_, staged_raw, _) = run_git(
        root,
        &["diff", "--cached", "--no-ext-diff", "--numstat", "-z"],
    )
    .await?;
    let (_, ui, ud) = sum_numstat(&unstaged_raw);
    let (_, si, sd) = sum_numstat(&staged_raw);

    let (rc, files_raw, _) = run_git(root, &["ls-files", "-z"]).await?;
    let paths = if rc == 0 {
        String::from_utf8_lossy(&files_raw)
            .split('\0')
            .filter(|path| !path.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let (top_dirs, extensions, top_truncated) = top_counts(&paths);

    let (_, log_raw, _) = run_git(
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
                "tracked_files": paths.len(),
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
    let mut dirs: HashMap<String, usize> = HashMap::new();
    let mut exts: HashMap<String, usize> = HashMap::new();
    let mut files = 0_usize;
    let mut truncated = false;
    for entry in fs::read_dir(root).map_err(|e| {
        HandlerError::new("permission_denied", format!("cannot read directory: {e}"))
    })? {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        let Ok(kind) = entry.file_type() else {
            continue;
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

    let (rc, out, err) = run_git(&root, &["rev-parse", "--show-toplevel"]).await?;
    if rc == 0 && !out.is_empty() {
        let git_root_text = String::from_utf8_lossy(&out).trim().to_owned();
        if let Some(git_root) = policy.resolve_path(&git_root_text, false) {
            return git_snapshot(&git_root).await;
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
}
