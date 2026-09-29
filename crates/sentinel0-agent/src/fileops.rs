use crate::{
    handler_error::{HandlerError, HandlerResult, require_str},
    policy::Policy,
};
use chrono::{DateTime, Utc};
use glob::Pattern;
use grep_matcher::Matcher;
use grep_regex::{RegexMatcher, RegexMatcherBuilder};
use grep_searcher::{BinaryDetection, Searcher, SearcherBuilder, sinks::Bytes};
use ignore::WalkBuilder;
use serde_json::{Map, Value};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Seek},
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

const PROBE: usize = 8192;
const PREVIEW_CHARS: usize = 200;
const MAX_SEARCH_ERRORS: usize = 32;
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

fn access_error(raw: &str, error: &std::io::Error) -> HandlerError {
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

fn record_search_error(
    errors: &mut Vec<Value>,
    count: &mut u64,
    file: Option<&Path>,
    message: impl Into<String>,
) {
    *count = count.saturating_add(1);
    if errors.len() >= MAX_SEARCH_ERRORS {
        return;
    }
    let mut error = Map::from_iter([("error".into(), Value::String(message.into()))]);
    if let Some(file) = file {
        error.insert("file".into(), Value::String(file.display().to_string()));
    }
    errors.push(Value::Object(error));
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
            let selected = line >= start && end.is_none_or(|last| line <= last);

            if byte == b'\n' {
                if selected {
                    last_selected = line;
                    let next_line = line.saturating_add(1);
                    let next_selected =
                        next_line >= start && end.is_none_or(|last| next_line <= last);
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

struct Utf16ScanState {
    units: Vec<u16>,
    start: usize,
    end: Option<usize>,
    cap: usize,
    line: usize,
    last_selected: usize,
    saw_any: bool,
    last_was_newline: bool,
    truncated: bool,
    stopped_early: bool,
    first_unit: bool,
}

impl Utf16ScanState {
    fn new(start: usize, end: Option<usize>, cap: usize) -> Self {
        Self {
            units: Vec::with_capacity(cap.min(64 * 1024)),
            start,
            end,
            cap,
            line: 1,
            last_selected: start.saturating_sub(1),
            saw_any: false,
            last_was_newline: false,
            truncated: false,
            stopped_early: false,
            first_unit: true,
        }
    }

    fn push_unit(&mut self, unit: u16) -> bool {
        if self.first_unit && unit == 0xfeff {
            self.first_unit = false;
            return false;
        }
        self.first_unit = false;
        self.saw_any = true;
        self.last_was_newline = unit == 0x000a;
        let selected = self.line >= self.start && self.end.is_none_or(|last| self.line <= last);

        if unit == 0x000a {
            if selected {
                self.last_selected = self.line;
                let next = self.line.saturating_add(1);
                let next_selected = next >= self.start && self.end.is_none_or(|last| next <= last);
                if next_selected {
                    if self.units.len() >= self.cap {
                        self.truncated = true;
                        self.stopped_early = true;
                        return true;
                    }
                    self.units.push(0x000a);
                }
            }
            if self.end.is_some_and(|last| self.line >= last) {
                self.stopped_early = true;
                return true;
            }
            self.line = self.line.saturating_add(1);
        } else if selected {
            self.last_selected = self.line;
            if self.units.len() >= self.cap {
                self.truncated = true;
                self.stopped_early = true;
                return true;
            }
            self.units.push(unit);
        }
        false
    }

    fn finish(mut self) -> (String, usize, bool, bool, usize) {
        let total_lines = if !self.saw_any {
            0
        } else if self.stopped_early {
            self.line
        } else if self.last_was_newline {
            self.line.saturating_sub(1)
        } else {
            self.line
        };
        let mut content = String::from_utf16_lossy(&self.units);
        let before = content.len();
        content = clip(content, self.cap);
        self.truncated |= content.len() < before;
        (
            content,
            total_lines,
            !self.stopped_early,
            self.truncated,
            self.last_selected,
        )
    }
}

fn utf16_unit(pair: [u8; 2], little_endian: bool) -> u16 {
    if little_endian {
        u16::from_le_bytes(pair)
    } else {
        u16::from_be_bytes(pair)
    }
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
    let mut state = Utf16ScanState::new(start, end, cap);

    'outer: loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| HandlerError::new("io_error", format!("failed to read file: {e}")))?;
        if n == 0 {
            break;
        }
        let mut index = 0;
        if let Some(first) = carry.take() {
            index = 1;
            if state.push_unit(utf16_unit([first, buf[0]], little_endian)) {
                break 'outer;
            }
        }
        while index + 1 < n {
            let pair = [buf[index], buf[index + 1]];
            index += 2;
            if state.push_unit(utf16_unit(pair, little_endian)) {
                break 'outer;
            }
        }
        if index < n {
            carry = Some(buf[index]);
        }
    }
    Ok(state.finish())
}

/// # Errors
/// Returns an error when the path is invalid, disallowed, unreadable, or the payload is malformed.
pub fn read(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let raw = require_str(payload, "path")?;
    let path = resolve(policy, raw)?;
    let meta = fs::metadata(&path).map_err(|error| access_error(raw, &error))?;
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
    if let Some(requested) = payload.get("max_bytes").and_then(Value::as_u64)
        && requested > 0
    {
        cap = cap.min(usize::try_from(requested).unwrap_or(usize::MAX));
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

    let utf16_little_endian = probe.starts_with(&[0xff, 0xfe]);
    let has_utf16_bom = utf16_little_endian || probe.starts_with(&[0xfe, 0xff]);
    if !has_utf16_bom && probe.contains(&0) {
        let preview = crate::hex_lower(&probe[..probe.len().min(256)]);
        return Ok(BTreeMap::from([
            ("ok".into(), Value::Bool(true)),
            ("path".into(), Value::String(path.display().to_string())),
            ("encoding".into(), Value::String("binary".into())),
            ("size_bytes".into(), Value::from(meta.len())),
            ("preview_hex".into(), Value::String(preview)),
            (
                "modified_at".into(),
                mtime(&meta).map_or(Value::Null, Value::String),
            ),
            ("truncated".into(), Value::Bool(true)),
        ]));
    }

    let (start, end) = range.unwrap_or((1, None));
    let (content, total_lines, total_exact, truncated, last) = if has_utf16_bom {
        scan_utf16(&path, start, end, cap, utf16_little_endian)?
    } else {
        scan_utf8(&path, start, end, cap)?
    };

    let mut result = BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("path".into(), Value::String(path.display().to_string())),
        (
            "encoding".into(),
            Value::String(if has_utf16_bom { "utf-16" } else { "utf-8" }.into()),
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
            mtime(&meta).map_or(Value::Null, Value::String),
        ),
    ]);
    if range.is_some() {
        result.insert("view_range".into(), serde_json::json!([start, last]));
    }
    Ok(result)
}

/// # Errors
/// Returns an error when the directory request is invalid, disallowed, or cannot be read.
pub fn list(policy: &Policy, payload: &Map<String, Value>) -> HandlerResult {
    let raw = require_str(payload, "path")?;
    let root = resolve(policy, raw)?;
    let meta = fs::metadata(&root).map_err(|error| access_error(raw, &error))?;
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
        .clamp(1, 5);
    let depth = usize::try_from(depth).unwrap_or(5);
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
            .unwrap_or_else(|_| entry.path())
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
        .map(str::to_ascii_lowercase)
        .is_some_and(|ext| SKIP_EXTS.contains(&ext.as_str()))
}

struct SearchState {
    matches: Vec<Value>,
    files_searched: u64,
    errors: Vec<Value>,
    error_count: u64,
    cap: usize,
}

fn build_search_matcher(
    pattern: &str,
    is_regex: bool,
    case_sensitive: bool,
) -> Result<RegexMatcher, HandlerError> {
    let mut builder = RegexMatcherBuilder::new();
    builder.case_insensitive(!case_sensitive);
    if is_regex {
        builder.build(pattern).map_err(|e| {
            HandlerError::new(
                "invalid_payload",
                format!("pattern is not a valid regex: {e}"),
            )
        })
    } else {
        builder.build_literals(&[pattern]).map_err(|e| {
            HandlerError::new(
                "invalid_payload",
                format!("pattern could not be compiled: {e}"),
            )
        })
    }
}

fn search_candidate(
    path: &Path,
    rel: &str,
    matcher: &RegexMatcher,
    searcher: &mut Searcher,
    state: &mut SearchState,
) -> bool {
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) => {
            record_search_error(
                &mut state.errors,
                &mut state.error_count,
                Some(path),
                format!("open failed: {error}"),
            );
            return false;
        }
    };
    let mut probe = [0_u8; PROBE];
    let n = match file.read(&mut probe) {
        Ok(n) => n,
        Err(error) => {
            record_search_error(
                &mut state.errors,
                &mut state.error_count,
                Some(path),
                format!("probe read failed: {error}"),
            );
            return false;
        }
    };
    if probe[..n].contains(&0) {
        return false;
    }
    if let Err(error) = file.rewind() {
        record_search_error(
            &mut state.errors,
            &mut state.error_count,
            Some(path),
            format!("rewind failed: {error}"),
        );
        return false;
    }
    state.files_searched += 1;
    let result = searcher.search_file(
        matcher,
        &file,
        Bytes(|line_number, line| {
            let line = match std::str::from_utf8(line) {
                Ok(line) => line,
                Err(error) => {
                    record_search_error(
                        &mut state.errors,
                        &mut state.error_count,
                        Some(path),
                        format!("line {line_number} is not UTF-8: {error}"),
                    );
                    return Ok(true);
                }
            };
            let found = match matcher.find(line.as_bytes()) {
                Ok(Some(found)) => found,
                Ok(None) => return Ok(true),
                Err(error) => {
                    record_search_error(
                        &mut state.errors,
                        &mut state.error_count,
                        Some(path),
                        format!("matcher failed on line {line_number}: {error}"),
                    );
                    return Ok(true);
                }
            };
            let mut preview = line.trim().to_owned();
            if preview.chars().count() > PREVIEW_CHARS {
                preview = preview.chars().take(PREVIEW_CHARS).collect::<String>() + "…";
            }
            let byte_column = found.start() + 1;
            let column = line
                .char_indices()
                .take_while(|(index, _)| *index < found.start())
                .count()
                + 1;
            state.matches.push(serde_json::json!({
                "file": rel,
                "line": line_number,
                "column": column,
                "byte_column": byte_column,
                "text": preview,
            }));
            Ok(state.matches.len() < state.cap)
        }),
    );
    if let Err(error) = result {
        record_search_error(
            &mut state.errors,
            &mut state.error_count,
            Some(path),
            format!("search failed: {error}"),
        );
    }
    state.matches.len() >= state.cap
}

/// # Errors
/// Returns an error when the search request is invalid, disallowed, or cannot be executed.
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
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value > 0)
        .unwrap_or(policy.file_ops_max_search_results)
        .min(policy.file_ops_max_search_results);
    let matcher = build_search_matcher(needle, is_regex, case_sensitive)?;
    let mut state = SearchState {
        matches: Vec::new(),
        files_searched: 0,
        errors: Vec::new(),
        error_count: 0,
        cap,
    };
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
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                record_search_error(
                    &mut state.errors,
                    &mut state.error_count,
                    None,
                    format!("walk failed: {error}"),
                );
                continue;
            }
        };
        if !entry.file_type().is_some_and(|ty| ty.is_file()) || skip_search_file(entry.path()) {
            continue;
        }
        if file_glob
            .as_ref()
            .is_some_and(|pattern| !pattern.matches(&entry.file_name().to_string_lossy()))
        {
            continue;
        }
        let rel = if root.is_file() {
            root.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(raw)
                .to_owned()
        } else {
            entry
                .path()
                .strip_prefix(&root)
                .unwrap_or_else(|_| entry.path())
                .to_string_lossy()
                .into_owned()
        };
        if search_candidate(entry.path(), &rel, &matcher, &mut searcher, &mut state) {
            break;
        }
    }

    Ok(BTreeMap::from([
        ("ok".into(), Value::Bool(true)),
        ("path".into(), Value::String(root.display().to_string())),
        ("pattern".into(), Value::String(needle.into())),
        ("matches".into(), Value::Array(state.matches)),
        ("files_searched".into(), Value::from(state.files_searched)),
        ("search_error_count".into(), Value::from(state.error_count)),
        ("search_errors".into(), Value::Array(state.errors)),
        (
            "truncated".into(),
            Value::Bool(state.matches.len() >= state.cap),
        ),
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
            &std::io::Error::from(std::io::ErrorKind::PermissionDenied),
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

    #[test]
    fn search_column_is_character_based_and_byte_column_is_explicit() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("utf8.txt"), "żółw needle\n").unwrap();
        let result = search(&policy(dir.path()), &search_payload(dir.path(), "needle")).unwrap();
        let first = &result["matches"].as_array().unwrap()[0];
        assert_eq!(first["column"], 6);
        assert_eq!(first["byte_column"], 9);
    }
}
