use crate::{
    handler_error::{HandlerError, HandlerResult, require_str},
    policy::Policy,
};
use chrono::{DateTime, Utc};
use glob::Pattern;
use grep_matcher::Matcher;
use grep_regex::RegexMatcherBuilder;
use grep_searcher::{BinaryDetection, SearcherBuilder, sinks::Bytes};
use ignore::WalkBuilder;
use serde_json::{Map, Value};
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader, Read, Seek},
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

const PROBE: usize = 8192;
const PREVIEW_CHARS: usize = 200;
const SKIP_DIRS: &[&str] = &[
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "target",
];
const SKIP_EXTS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "pdf", "zip", "gz", "xz", "bz2", "7z", "tar", "so", "dll",
    "dylib", "exe", "bin", "woff", "woff2", "ttf", "otf", "class", "jar",
];

fn mtime(meta: &fs::Metadata) -> Option<String> {
    let dt: DateTime<Utc> = DateTime::<Utc>::from(meta.modified().ok()?);
    Some(dt.format("%Y-%m-%dT%H:%M:%S+0000").to_string())
}

fn kind(meta: &fs::Metadata) -> &'static str {
    let ty = meta.file_type();
    if ty.is_dir() {
        "dir"
    } else if ty.is_file() {
        "file"
    } else if ty.is_symlink() {
        "symlink"
    } else {
        "other"
    }
}

fn resolve(policy: &Policy, raw: &str) -> Result<PathBuf, HandlerError> {
    policy.resolve_path(raw, false).ok_or_else(|| {
        HandlerError::new(
            "path_not_allowed",
            format!("path {raw:?} is outside file_ops.paths"),
        )
    })
}

fn access_error(raw: &str, error: std::io::Error) -> HandlerError {
    match error.kind() {
        std::io::ErrorKind::NotFound => {
            HandlerError::new("not_found", format!("path does not exist: {raw:?}"))
        }
        std::io::ErrorKind::PermissionDenied => HandlerError::new(
            "permission_denied",
            format!("cannot access {raw:?}: {error}"),
        ),
        _ => HandlerError::new("io_error", format!("cannot access {raw:?}: {error}")),
    }
}

fn line_count(text: &str) -> usize {
    if text.is_empty() {
        0
    } else {
        text.lines().count()
    }
}

fn clip(mut text: String, cap: usize) -> String {
    if text.len() <= cap {
        return text;
    }
    let mut end = cap;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    text
}

fn parse_range(
    payload: &Map<String, Value>,
) -> Result<Option<(usize, Option<usize>)>, HandlerError> {
    let Some(value) = payload.get("view_range") else {
        return Ok(None);
    };
    let Some(items) = value.as_array() else {
        return Err(HandlerError::new(
            "invalid_payload",
            "view_range must be [start, end]",
        ));
    };
    if items.len() != 2 {
        return Err(HandlerError::new(
            "invalid_payload",
            "view_range must be [start, end]",
        ));
    }
    let Some(start_raw) = items[0].as_i64() else {
        return Err(HandlerError::new(
            "invalid_payload",
            "view_range values must be integers",
        ));
    };
    let Some(end_raw) = items[1].as_i64() else {
        return Err(HandlerError::new(
            "invalid_payload",
            "view_range values must be integers",
        ));
    };
    let start = usize::try_from(start_raw.max(1)).unwrap_or(1);
    let end = if end_raw == -1 {
        None
    } else {
        Some(usize::try_from(end_raw.max(start_raw.max(1))).unwrap_or(start))
    };
    Ok(Some((start, end)))
}

fn scan_utf8(
    path: &Path,
    start: usize,
    end: Option<usize>,
    cap: usize,
) -> Result<(String, usize, bool, bool, usize), HandlerError> {
    let mut file = fs::File::open(path)
        .map_err(|e| HandlerError::new("io_error", format!("failed to read file: {e}")))?;
    let mut buf = [0_u8; 16 * 1024];
    let mut out = Vec::with_capacity(cap.min(64 * 1024));
    let mut line = 1_usize;
    let mut last_selected = start.saturating_sub(1);
    let mut saw_any = false;
    let mut last_was_newline = false;
    let mut truncated = false;
    let mut stopped_early = false;

    'outer: loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| HandlerError::new("io_error", format!("failed to read file: {e}")))?;
        if n == 0 {
            break;
        }
        for &byte in &buf[..n] {
            saw_any = true;
            last_was_newline = byte == b'\n';
            let selected = line >= start && end.map(|last| line <= last).unwrap_or(true);

            if byte == b'\n' {
                if selected {
                    last_selected = line;
                    let next_line = line.saturating_add(1);
                    let next_selected =
                        next_line >= start && end.map(|last| next_line <= last).unwrap_or(true);
                    if next_selected {
                        if out.len() >= cap {
                            truncated = true;
                            stopped_early = true;
                            break 'outer;
                        }
                        out.push(b'\n');
                    }
                }
                if end.is_some_and(|last| line >= last) {
                    stopped_early = true;
                    break 'outer;
                }
                line = line.saturating_add(1);
                continue;
            }

            if selected {
                last_selected = line;
                if out.len() >= cap {
                    truncated = true;
                    stopped_early = true;
                    break 'outer;
                }
                out.push(byte);
            }
        }
    }

    let total_lines = if !saw_any {
        0
    } else if stopped_early {
        line
    } else if last_was_newline {
        line.saturating_sub(1)
    } else {
        line
    };
    let mut content = String::from_utf8_lossy(&out).into_owned();
    let before = content.len();
    content = clip(content, cap);
    truncated |= content.len() < before;
    Ok((
        content,
        total_lines,
        !stopped_early,
        truncated,
        last_selected,
    ))
}

fn scan_utf16(
    path: &Path,
    start: usize,
    end: Option<usize>,
    cap: usize,
    little_endian: bool,
) -> Result<(String, usize, bool, bool, usize), HandlerError> {
    let mut file = fs::File::open(path)
        .map_err(|e| HandlerError::new("io_error", format!("failed to read file: {e}")))?;
    let mut buf = [0_u8; 16 * 1024];
    let mut carry: Option<u8> = None;
    let mut units = Vec::<u16>::with_capacity(cap.min(64 * 1024));
    let mut line = 1_usize;
    let mut last_selected = start.saturating_sub(1);
    let mut saw_any = false;
    let mut last_was_newline = false;
    let mut truncated = false;
    let mut stopped_early = false;
    let mut first_unit = true;

    'outer: loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| HandlerError::new("io_error", format!("failed to read file: {e}")))?;
        if n == 0 {
            break;
        }

        let mut index = 0;
        if let Some(first) = carry.take() {
            if n == 0 {
                carry = Some(first);
                continue;
            }
            let pair = [first, buf[0]];
            index = 1;
            let unit = if little_endian {
                u16::from_le_bytes(pair)
            } else {
                u16::from_be_bytes(pair)
            };
            if first_unit && unit == 0xfeff {
                first_unit = false;
            } else {
                first_unit = false;
                saw_any = true;
                last_was_newline = unit == 0x000a;
                let selected = line >= start && end.map(|last| line <= last).unwrap_or(true);
                if unit == 0x000a {
                    if selected {
                        last_selected = line;
                        let next = line.saturating_add(1);
                        let next_selected =
                            next >= start && end.map(|last| next <= last).unwrap_or(true);
                        if next_selected {
                            if units.len() >= cap {
                                truncated = true;
                                stopped_early = true;
                                break 'outer;
                            }
                            units.push(0x000a);
                        }
                    }
                    if end.is_some_and(|last| line >= last) {
                        stopped_early = true;
                        break 'outer;
                    }
                    line = line.saturating_add(1);
                } else if selected {
                    last_selected = line;
                    if units.len() >= cap {
                        truncated = true;
                        stopped_early = true;
                        break 'outer;
                    }
                    units.push(unit);
                }
            }
        }

        while index + 1 < n {
            let pair = [buf[index], buf[index + 1]];
            index += 2;
            let unit = if little_endian {
                u16::from_le_bytes(pair)
            } else {
                u16::from_be_bytes(pair)
            };
            if first_unit && unit == 0xfeff {
                first_unit = false;
                continue;
            }
            first_unit = false;
            saw_any = true;
            last_was_newline = unit == 0x000a;
            let selected = line >= start && end.map(|last| line <= last).unwrap_or(true);

            if unit == 0x000a {
                if selected {
                    last_selected = line;
                    let next = line.saturating_add(1);
                    let next_selected =
                        next >= start && end.map(|last| next <= last).unwrap_or(true);
                    if next_selected {
                        if units.len() >= cap {
                            truncated = true;
                            stopped_early = true;
                            break 'outer;
                        }
                        units.push(0x000a);
                    }
                }
                if end.is_some_and(|last| line >= last) {
                    stopped_early = true;
                    break 'outer;
                }
                line = line.saturating_add(1);
            } else if selected {
                last_selected = line;
                if units.len() >= cap {
                    truncated = true;
                    stopped_early = true;
                    break 'outer;
                }
                units.push(unit);
            }
        }
        if index < n {
            carry = Some(buf[index]);
        }
    }

    let total_lines = if !saw_any {
        0
    } else if stopped_early {
        line
    } else if last_was_newline {
        line.saturating_sub(1)
    } else {
        line
    };
    let mut content = String::from_utf16_lossy(&units);
    let before = content.len();
    content = clip(content, cap);
    truncated |= content.len() < before;
    Ok((
        content,
        total_lines,
        !stopped_early,
        truncated,
        last_selected,
    ))
}

pub fn read(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let raw = require_str(payload, "path")?;
    let path = resolve(policy, raw)?;
    let meta = fs::metadata(&path).map_err(|error| access_error(raw, error))?;
    if meta.is_dir() {
        return Err(HandlerError::new(
            "is_directory",
            format!("{raw:?} is a directory. Use list instead."),
        ));
    }
    if !meta.is_file() {
        return Err(HandlerError::new(
            "invalid_payload",
            format!("{raw:?} is not a regular file"),
        ));
    }

    let mut cap = policy.file_ops_max_read_bytes;
    if let Some(requested) = payload.get("max_bytes").and_then(Value::as_u64) {
        if requested > 0 {
            cap = cap.min(usize::try_from(requested).unwrap_or(usize::MAX));
        }
    }
    let range = parse_range(payload)?;
    let mut probe = vec![0_u8; PROBE.min(usize::try_from(meta.len()).unwrap_or(PROBE))];
    let mut file = fs::File::open(&path).map_err(|error| {
        let code = if error.kind() == std::io::ErrorKind::PermissionDenied {
            "permission_denied"
        } else {
            "io_error"
        };
        HandlerError::new(code, format!("cannot read {raw:?}: {error}"))
    })?;
    let n = file
        .read(&mut probe)
        .map_err(|e| HandlerError::new("io_error", format!("cannot read {raw:?}: {e}")))?;
    probe.truncate(n);

    let utf16_le = probe.starts_with(&[0xff, 0xfe]);
    let utf16_be = probe.starts_with(&[0xfe, 0xff]);
    if !utf16_le && !utf16_be && probe.contains(&0) {
        let preview = probe
            .iter()
            .take(256)
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        return Ok(BTreeMap::from([
            ("ok".into(), Value::Bool(true)),
            ("path".into(), Value::String(path.display().to_string())),
            ("encoding".into(), Value::String("binary".into())),
            ("size_bytes".into(), Value::from(meta.len())),
            ("preview_hex".into(), Value::String(preview)),
            (
                "modified_at".into(),
                mtime(&meta).map(Value::String).unwrap_or(Value::Null),
            ),
            ("truncated".into(), Value::Bool(true)),
        ]));
    }

    let (start, end) = range.unwrap_or((1, None));
    let (content, total_lines, total_exact, truncated, last) = if utf16_le || utf16_be {
        scan_utf16(&path, start, end, cap, utf16_le)?
    } else {
        scan_utf8(&path, start, end, cap)?
    };

    let mut result = BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("path".into(), Value::String(path.display().to_string())),
        (
            "encoding".into(),
            Value::String(
                if utf16_le || utf16_be {
                    "utf-16"
                } else {
                    "utf-8"
                }
                .into(),
            ),
        ),
        ("content".into(), Value::String(content.clone())),
        ("total_lines".into(), Value::from(total_lines as u64)),
        ("total_lines_exact".into(), Value::Bool(total_exact)),
        (
            "lines_returned".into(),
            Value::from(line_count(&content) as u64),
        ),
        ("size_bytes".into(), Value::from(meta.len())),
        ("truncated".into(), Value::Bool(truncated)),
        (
            "modified_at".into(),
            mtime(&meta).map(Value::String).unwrap_or(Value::Null),
        ),
    ]);
    if range.is_some() {
        result.insert("view_range".into(), serde_json::json!([start, last]));
    }
    Ok(result)
}

pub fn list(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let raw = require_str(payload, "path")?;
    let root = resolve(policy, raw)?;
    let meta = fs::metadata(&root).map_err(|error| access_error(raw, error))?;
    if !meta.is_dir() {
        return Err(HandlerError::new(
            "is_file",
            format!("{raw:?} is not a directory. Use read instead."),
        ));
    }

    let depth = payload
        .get("depth")
        .and_then(Value::as_i64)
        .unwrap_or(1)
        .clamp(1, 5) as usize;
    let hidden = payload
        .get("show_hidden")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let pattern = match payload.get("glob") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) => Some(
            Pattern::new(text)
                .map_err(|e| HandlerError::new("invalid_payload", format!("invalid glob: {e}")))?,
        ),
        _ => {
            return Err(HandlerError::new(
                "invalid_payload",
                "glob must be a string",
            ));
        }
    };

    let mut entries = Vec::new();
    let mut truncated = false;
    for entry in WalkDir::new(&root)
        .min_depth(1)
        .max_depth(depth)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| {
            let name = entry.file_name().to_string_lossy();
            !SKIP_DIRS.contains(&name.as_ref()) && (hidden || !name.starts_with('.'))
        })
    {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name().to_string_lossy();
        if pattern.as_ref().is_some_and(|p| !p.matches(&name)) {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        let rel = entry
            .path()
            .strip_prefix(&root)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .into_owned();
        entries.push(serde_json::json!({
            "name": rel,
            "type": kind(&meta),
            "size": meta.len(),
            "mtime": mtime(&meta),
        }));
        if entries.len() >= policy.file_ops_max_list_entries {
            truncated = true;
            break;
        }
    }

    let total = entries.len();
    Ok(BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("path".into(), Value::String(root.display().to_string())),
        ("entries".into(), Value::Array(entries)),
        ("total".into(), Value::from(total as u64)),
        ("truncated".into(), Value::Bool(truncated)),
    ]))
}

fn skip_search_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
        .map(|ext| SKIP_EXTS.contains(&ext.as_str()))
        .unwrap_or(false)
}

pub fn search(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let raw = require_str(payload, "path")?;
    let needle = require_str(payload, "pattern")?;
    let root = resolve(policy, raw)?;
    let case_sensitive = payload
        .get("case_sensitive")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let is_regex = payload
        .get("regex")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let file_glob = match payload.get("file_glob") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) => Some(Pattern::new(text).map_err(|e| {
            HandlerError::new("invalid_payload", format!("invalid file_glob: {e}"))
        })?),
        _ => {
            return Err(HandlerError::new(
                "invalid_payload",
                "file_glob must be a string",
            ));
        }
    };
    let cap = payload
        .get("max_results")
        .and_then(Value::as_u64)
        .and_then(|v| usize::try_from(v).ok())
        .filter(|v| *v > 0)
        .unwrap_or(policy.file_ops_max_search_results)
        .min(policy.file_ops_max_search_results);

    let mut matcher_builder = RegexMatcherBuilder::new();
    matcher_builder.case_insensitive(!case_sensitive);
    let matcher = if is_regex {
        matcher_builder.build(needle)
    } else {
        matcher_builder.build_literals(&[needle])
    }
    .map_err(|e| {
        let message = if is_regex {
            format!("pattern is not a valid regex: {e}")
        } else {
            format!("pattern could not be compiled: {e}")
        };
        HandlerError::new("invalid_payload", message)
    })?;

    let mut matches = Vec::new();
    let mut files_searched = 0_u64;
    let mut truncated = false;
    let mut walker = WalkBuilder::new(&root);
    walker
        .hidden(false)
        .parents(false)
        .ignore(false)
        .git_global(false)
        .git_ignore(false)
        .git_exclude(false)
        .follow_links(false)
        .filter_entry(|entry| {
            let name = entry.file_name().to_string_lossy();
            !entry.file_type().is_some_and(|ty| ty.is_dir()) || !SKIP_DIRS.contains(&name.as_ref())
        });
    let mut searcher = SearcherBuilder::new()
        .line_number(true)
        .binary_detection(BinaryDetection::none())
        .build();

    for entry in walker.build() {
        let Ok(entry) = entry else { continue };
        if !entry.file_type().is_some_and(|ty| ty.is_file()) || skip_search_file(entry.path()) {
            continue;
        }
        if file_glob
            .as_ref()
            .is_some_and(|p| !p.matches(&entry.file_name().to_string_lossy()))
        {
            continue;
        }
        let Ok(mut file) = fs::File::open(entry.path()) else {
            continue;
        };
        let mut probe = [0_u8; PROBE];
        let Ok(n) = file.read(&mut probe) else {
            continue;
        };
        if probe[..n].contains(&0) || file.rewind().is_err() {
            continue;
        };
        files_searched += 1;

        let rel = if root.is_file() {
            root.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(raw)
                .to_owned()
        } else {
            entry
                .path()
                .strip_prefix(&root)
                .unwrap_or(entry.path())
                .to_string_lossy()
                .into_owned()
        };
        let search_result = searcher.search_file(
            &matcher,
            &file,
            Bytes(|line_number, line| {
                let Ok(line) = std::str::from_utf8(line) else {
                    return Ok(true);
                };
                let Ok(Some(found)) = matcher.find(line.as_bytes()) else {
                    return Ok(true);
                };
                let mut preview = line.trim().to_owned();
                if preview.chars().count() > PREVIEW_CHARS {
                    preview = preview.chars().take(PREVIEW_CHARS).collect::<String>() + "…";
                }
                matches.push(serde_json::json!({
                    "file": rel.as_str(),
                    "line": line_number,
                    "column": found.start() + 1,
                    "text": preview,
                }));
                Ok(matches.len() < cap)
            }),
        );
        if search_result.is_err() {
            continue;
        }
        if matches.len() >= cap {
            truncated = true;
            break;
        }
    }

    Ok(BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("path".into(), Value::String(root.display().to_string())),
        ("pattern".into(), Value::String(needle.into())),
        ("matches".into(), Value::Array(matches)),
        ("files_searched".into(), Value::from(files_searched)),
        ("truncated".into(), Value::Bool(truncated)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{FileAccess, FileOpsPath};
    use tempfile::tempdir;

    fn policy(root: &Path) -> Policy {
        Policy {
            file_ops_paths: vec![FileOpsPath {
                path: root.to_owned(),
                access: FileAccess::Read,
            }],
            ..Policy::default()
        }
    }

    #[test]
    fn permission_denied_is_not_reported_as_internal_io_error() {
        let error = access_error(
            "/restricted/tree",
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        );
        assert_eq!(error.code, "permission_denied");
        assert!(error.message.contains("/restricted/tree"));
    }

    #[test]
    fn read_range_and_search_contracts() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("a.txt");
        fs::write(&file, "one\ntwo needle\nthree\n").unwrap();
        let policy = policy(dir.path());
        let read_result = read(
            &policy,
            &Map::from_iter([
                ("path".into(), Value::String(file.display().to_string())),
                ("view_range".into(), serde_json::json!([2, 3])),
            ]),
        )
        .unwrap();
        assert_eq!(read_result["content"], "two needle\nthree");

        let search_result = search(
            &policy,
            &Map::from_iter([
                (
                    "path".into(),
                    Value::String(dir.path().display().to_string()),
                ),
                ("pattern".into(), Value::String("needle".into())),
            ]),
        )
        .unwrap();
        assert_eq!(search_result["matches"][0]["line"], 2);
    }

    fn search_payload(root: &Path, pattern: &str) -> Map<String, Value> {
        Map::from_iter([
            ("path".into(), Value::String(root.display().to_string())),
            ("pattern".into(), Value::String(pattern.into())),
        ])
    }

    #[test]
    fn search_is_case_insensitive_by_default_and_reports_byte_column() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "prefix NeEdLe suffix\n").unwrap();
        let result = search(&policy(dir.path()), &search_payload(dir.path(), "needle")).unwrap();
        assert_eq!(result["matches"][0]["line"], 1);
        assert_eq!(result["matches"][0]["column"], 8);
        assert_eq!(result["matches"][0]["text"], "prefix NeEdLe suffix");
    }

    #[test]
    fn search_case_sensitive_mode_rejects_case_mismatch() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "NeEdLe\n").unwrap();
        let mut payload = search_payload(dir.path(), "needle");
        payload.insert("case_sensitive".into(), Value::Bool(true));
        let result = search(&policy(dir.path()), &payload).unwrap();
        assert_eq!(result["matches"], serde_json::json!([]));
    }

    #[test]
    fn search_regex_mode_uses_ripgrep_matcher() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "abc 123 xyz\n").unwrap();
        let mut payload = search_payload(dir.path(), r"\d{3}");
        payload.insert("regex".into(), Value::Bool(true));
        let result = search(&policy(dir.path()), &payload).unwrap();
        assert_eq!(result["matches"][0]["column"], 5);
    }

    #[test]
    fn search_skips_binary_noise_dirs_and_nonmatching_globs() {
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join("target")).unwrap();
        fs::write(dir.path().join("target").join("hidden.txt"), "needle\n").unwrap();
        fs::write(dir.path().join("keep.rs"), "needle\n").unwrap();
        fs::write(dir.path().join("wrong.txt"), "needle\n").unwrap();
        fs::write(dir.path().join("binary.rs"), b"needle\0more\n").unwrap();

        let mut payload = search_payload(dir.path(), "needle");
        payload.insert("file_glob".into(), Value::String("*.rs".into()));
        let result = search(&policy(dir.path()), &payload).unwrap();
        let matches = result["matches"].as_array().unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0]["file"], "keep.rs");
        assert_eq!(result["files_searched"], 1);
    }

    #[test]
    fn search_global_result_cap_sets_truncated() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "needle\nneedle\n").unwrap();
        let mut payload = search_payload(dir.path(), "needle");
        payload.insert("max_results".into(), Value::from(1));
        let result = search(&policy(dir.path()), &payload).unwrap();
        assert_eq!(result["matches"].as_array().unwrap().len(), 1);
        assert_eq!(result["truncated"], true);
    }

    #[test]
    fn search_single_file_preserves_basename_contract() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("a.txt");
        fs::write(&file, "needle\n").unwrap();
        let result = search(&policy(dir.path()), &search_payload(&file, "needle")).unwrap();
        assert_eq!(result["matches"][0]["file"], "a.txt");
    }

    #[test]
    fn invalid_regex_is_a_payload_error() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "needle\n").unwrap();
        let mut payload = search_payload(dir.path(), "(");
        payload.insert("regex".into(), Value::Bool(true));
        let error = search(&policy(dir.path()), &payload).unwrap_err();
        assert_eq!(error.code, "invalid_payload");
        assert!(error.message.contains("valid regex"));
    }
}
