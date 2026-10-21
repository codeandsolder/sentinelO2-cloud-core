use crate::policy::Policy;

const READ_ONLY_FILTERS: &[&str] = &[
    "head",
    "tail",
    "sort",
    "uniq",
    "wc",
    "cut",
    "tr",
    "grep",
    "egrep",
    "fgrep",
    "rg",
    "cat",
    "rev",
    "tac",
    "nl",
    "fold",
    "paste",
    "join",
    "comm",
    "column",
    "base64",
    "md5sum",
    "sha256sum",
    "echo",
    "printf",
    "true",
    "false",
    "seq",
    "basename",
    "dirname",
    "realpath",
    "readlink",
    "date",
];
const POSITION_FREE: &[&str] = &["cd"];
const SAFE_BUILTINS: &[&str] = &[
    "set", "test", "[", "[[", "true", "false", ":", "read", "shift", "break", "continue", "exit",
    "return", "wait",
];
const LEADING_KEYWORDS: &[&str] = &[
    "do", "then", "else", "elif", "if", "while", "until", "!", "{", "time",
];
const CLOSING_KEYWORDS: &[&str] = &["done", "fi", "}"];
const HEADER_KEYWORDS: &[&str] = &["for", "select"];
const MAX_NESTING: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnparseableCommand(pub String);

fn first_word(segment: &str) -> &str {
    segment.split_whitespace().next().unwrap_or("")
}

#[must_use]
pub fn split_top_level(command: &str) -> Vec<String> {
    let chars: Vec<char> = command.chars().collect();
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut i = 0;
    let mut quote: Option<char> = None;
    while i < chars.len() {
        let ch = chars[i];
        if let Some(active) = quote {
            buf.push(ch);
            if ch == '\\' && active == '"' && i + 1 < chars.len() {
                i += 1;
                buf.push(chars[i]);
            } else if ch == active {
                quote = None;
            }
            i += 1;
            continue;
        }
        if matches!(ch, '\'' | '"') {
            quote = Some(ch);
            buf.push(ch);
            i += 1;
            continue;
        }
        if ch == '\\' && i + 1 < chars.len() {
            buf.push(ch);
            i += 1;
            buf.push(chars[i]);
            i += 1;
            continue;
        }
        if chars
            .get(i + 1)
            .is_some_and(|next| (ch == '&' && *next == '&') || (ch == '|' && *next == '|'))
        {
            if !buf.trim().is_empty() {
                out.push(buf.trim().to_owned());
            }
            buf.clear();
            i += 2;
            continue;
        }
        if ch == '&' {
            let next = chars.get(i + 1).copied().unwrap_or('\0');
            let prev = buf.chars().last().unwrap_or('\0');
            if next == '>' || matches!(prev, '<' | '>') {
                buf.push(ch);
                i += 1;
                continue;
            }
            if !buf.trim().is_empty() {
                out.push(buf.trim().to_owned());
            }
            buf.clear();
            i += 1;
            continue;
        }
        if matches!(ch, ';' | '|' | '\n') {
            if !buf.trim().is_empty() {
                out.push(buf.trim().to_owned());
            }
            buf.clear();
            i += 1;
            continue;
        }
        buf.push(ch);
        i += 1;
    }
    if !buf.trim().is_empty() {
        out.push(buf.trim().to_owned());
    }
    out
}

#[must_use]
pub fn has_substitution(command: &str) -> Option<&'static str> {
    let bytes = command.as_bytes();
    let mut i = 0;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let ch = bytes[i];
        if quote == Some(b'\'') {
            if ch == b'\'' {
                quote = None;
            }
            i += 1;
            continue;
        }
        if ch == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if quote == Some(b'"') {
            if ch == b'"' {
                quote = None;
            } else if bytes[i..].starts_with(b"$(") {
                return Some("$(");
            } else if ch == b'`' {
                return Some("`");
            }
            i += 1;
            continue;
        }
        if matches!(ch, b'\'' | b'"') {
            quote = Some(ch);
            i += 1;
            continue;
        }
        if bytes[i..].starts_with(b"$(") {
            return Some("$(");
        }
        if ch == b'`' {
            return Some("`");
        }
        if bytes[i..].starts_with(b"<(") {
            return Some("<(");
        }
        if bytes[i..].starts_with(b">(") {
            return Some(">(");
        }
        i += 1;
    }
    None
}

#[must_use]
pub fn control_character(command: &str) -> Option<char> {
    command
        .chars()
        .find(|ch| ((*ch as u32) < 32 && *ch != '\t') || *ch as u32 == 127)
}

#[must_use]
pub fn file_redirection(command: &str) -> Option<String> {
    let bytes = command.as_bytes();
    let mut i = 0;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let ch = bytes[i];
        if let Some(active) = quote {
            if ch == b'\\' && active == b'"' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if ch == active {
                quote = None;
            }
            i += 1;
            continue;
        }
        if ch == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if matches!(ch, b'\'' | b'"') {
            quote = Some(ch);
            i += 1;
            continue;
        }
        if !matches!(ch, b'<' | b'>') {
            i += 1;
            continue;
        }
        let start = i;
        if bytes[i..].starts_with(b"<<") {
            i += if bytes[i..].starts_with(b"<<<") { 3 } else { 2 };
            continue;
        }
        if bytes[i..].starts_with(b"<(") || bytes[i..].starts_with(b">(") {
            i += 2;
            continue;
        }
        let mut j = i + 1;
        while j < bytes.len() && matches!(bytes[j], b'>' | b'|') {
            j += 1;
        }
        if j < bytes.len() && bytes[j] == b'&' {
            let mut k = j + 1;
            while k < bytes.len() && (bytes[k].is_ascii_digit() || bytes[k] == b'-') {
                k += 1;
            }
            if k > j + 1 {
                i = k;
                continue;
            }
            j += 1;
        }
        while j < bytes.len() && matches!(bytes[j], b' ' | b'\t') {
            j += 1;
        }
        let mut k = j;
        while k < bytes.len()
            && !matches!(
                bytes[k],
                b' ' | b'\t' | b';' | b'|' | b'&' | b'<' | b'>' | b'(' | b')'
            )
        {
            k += 1;
        }
        if command[j..k].trim_matches(['\'', '"']) == "/dev/null" {
            i = k;
            continue;
        }
        return Some(command[start..k].trim().to_owned());
    }
    None
}

fn shell_words(segment: &str) -> Result<Vec<String>, ()> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut chars = segment.chars();
    let mut quote: Option<char> = None;
    while let Some(ch) = chars.next() {
        if let Some(active) = quote {
            if ch == active {
                quote = None;
            } else if ch == '\\' && active == '"' {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            } else {
                current.push(ch);
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '\\' => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            c if c.is_whitespace() => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if quote.is_some() {
        return Err(());
    }
    if !current.is_empty() {
        out.push(current);
    }
    Ok(out)
}

fn looks_like_path(token: &str) -> bool {
    token.starts_with('/') || token.starts_with('~') || token.contains('/')
}

fn option_takes_value(name: &str, option: &str) -> bool {
    match name {
        "head" | "tail" => matches!(option, "-n" | "-c"),
        "cut" => matches!(option, "-d" | "-f" | "-b" | "-c"),
        "sort" => matches!(option, "-k" | "-t" | "-S" | "-T"),
        "grep" => matches!(option, "-e" | "-f" | "-m" | "-A" | "-B" | "-C"),
        "egrep" | "fgrep" => matches!(option, "-e" | "-f"),
        "rg" => matches!(option, "-e" | "-f" | "-m"),
        "fold" => option == "-w",
        "paste" => option == "-d",
        "join" => matches!(option, "-t" | "-1" | "-2"),
        _ => false,
    }
}

fn filter_unsafe(segment: &str) -> bool {
    let Ok(tokens) = shell_words(segment) else {
        return true;
    };
    let Some(name) = tokens.first().map(String::as_str) else {
        return false;
    };
    if tokens.iter().skip(1).any(|token| {
        let head = token.split('=').next().unwrap_or(token);
        name == "sort" && matches!(head, "-o" | "--output" | "--compress-program" | "-S")
    }) {
        return true;
    }
    let mut operands = Vec::new();
    let mut expecting_value = false;
    for token in tokens.iter().skip(1) {
        if expecting_value {
            expecting_value = false;
            continue;
        }
        if token == "--" {
            continue;
        }
        if token.starts_with('-') && token != "-" {
            let head = token.split('=').next().unwrap_or(token);
            if !token.contains('=') && option_takes_value(name, head) {
                expecting_value = true;
            }
            continue;
        }
        operands.push(token.as_str());
    }
    if matches!(name, "grep" | "egrep" | "fgrep" | "rg") && !operands.is_empty() {
        operands.remove(0);
    }
    operands.into_iter().any(looks_like_path)
}

fn command_part(segment: &str) -> Result<Option<String>, UnparseableCommand> {
    let mut rest = segment.trim();
    loop {
        rest = rest.trim_start_matches('(').trim();
        let word = first_word(rest);
        if LEADING_KEYWORDS.contains(&word) {
            rest = rest[word.len()..].trim();
        } else {
            break;
        }
    }
    let word = first_word(rest);
    if word.is_empty() || CLOSING_KEYWORDS.contains(&word) || HEADER_KEYWORDS.contains(&word) {
        return Ok(None);
    }
    if matches!(word, "case" | "esac") {
        return Err(UnparseableCommand("a case statement".into()));
    }
    while rest.ends_with(')') && rest.matches(')').count() > rest.matches('(').count() {
        rest = rest[..rest.len() - 1].trim_end();
    }
    Ok((!rest.is_empty()).then(|| rest.to_owned()))
}

fn only_assignments(segment: &str) -> bool {
    let tokens: Vec<&str> = segment.split_whitespace().collect();
    !tokens.is_empty()
        && tokens.into_iter().all(|token| {
            token.split_once('=').is_some_and(|(name, _)| {
                let mut chars = name.chars();
                chars
                    .next()
                    .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
                    && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
            })
        })
}

fn matching_paren(command: &str, mut index: usize) -> Result<usize, UnparseableCommand> {
    let bytes = command.as_bytes();
    let mut depth = 1usize;
    let mut quote: Option<u8> = None;
    while index < bytes.len() {
        let ch = bytes[index];
        if let Some(active) = quote {
            if ch == b'\\' && active == b'"' && index + 1 < bytes.len() {
                index += 2;
                continue;
            }
            if ch == active {
                quote = None;
            }
            index += 1;
            continue;
        }
        if ch == b'\\' && index + 1 < bytes.len() {
            index += 2;
            continue;
        }
        if matches!(ch, b'\'' | b'"') {
            quote = Some(ch);
        } else if ch == b'(' {
            depth += 1;
        } else if ch == b')' {
            depth -= 1;
            if depth == 0 {
                return Ok(index);
            }
        }
        index += 1;
    }
    Err(UnparseableCommand(
        "unbalanced parentheses in a substitution".into(),
    ))
}

fn mask_substitutions(
    command: &str,
    literal_quotes: bool,
) -> Result<(String, Vec<String>), UnparseableCommand> {
    let bytes = command.as_bytes();
    let mut masked = Vec::with_capacity(bytes.len());
    let mut bodies = Vec::new();
    let mut i = 0usize;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let ch = bytes[i];
        if !literal_quotes {
            if quote == Some(b'\'') {
                masked.push(ch);
                if ch == b'\'' {
                    quote = None;
                }
                i += 1;
                continue;
            }
            if ch == b'\\' && i + 1 < bytes.len() {
                masked.extend_from_slice(&bytes[i..i + 2]);
                i += 2;
                continue;
            }
            if quote == Some(b'"') && ch == b'"' {
                quote = None;
                masked.push(ch);
                i += 1;
                continue;
            }
            if quote.is_none() && matches!(ch, b'\'' | b'"') {
                quote = Some(ch);
                masked.push(ch);
                i += 1;
                continue;
            }
        } else if ch == b'\\' && i + 1 < bytes.len() {
            masked.extend_from_slice(&bytes[i..i + 2]);
            i += 2;
            continue;
        }

        if bytes[i..].starts_with(b"$((") {
            let close = matching_paren(command, i + 2)?;
            if close <= i + 3 {
                return Err(UnparseableCommand("empty arithmetic expansion".into()));
            }
            let (_, nested) = mask_substitutions(&command[i + 3..close - 1], literal_quotes)?;
            bodies.extend(nested);
            masked.push(b'0');
            i = close + 1;
            continue;
        }

        let process = !literal_quotes
            && quote.is_none()
            && (bytes[i..].starts_with(b"<(") || bytes[i..].starts_with(b">("));
        if bytes[i..].starts_with(b"$(") || process {
            let close = matching_paren(command, i + 2)?;
            bodies.push(command[i + 2..close].to_owned());
            masked.extend_from_slice(b"__SX_SUBST__");
            i = close + 1;
            continue;
        }

        if ch == b'`' {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] != b'`' {
                j += if bytes[j] == b'\\' && j + 1 < bytes.len() {
                    2
                } else {
                    1
                };
            }
            if j >= bytes.len() {
                return Err(UnparseableCommand("unbalanced backtick".into()));
            }
            bodies.push(command[i + 1..j].replace("\\`", "`"));
            masked.extend_from_slice(b"__SX_SUBST__");
            i = j + 1;
            continue;
        }

        masked.push(ch);
        i += 1;
    }
    let masked = String::from_utf8(masked)
        .map_err(|_| UnparseableCommand("command stopped being valid UTF-8".into()))?;
    Ok((masked, bodies))
}

#[derive(Debug)]
struct HeredocSpec {
    delimiter: String,
    strip_tabs: bool,
    live: bool,
}

fn heredoc_stop(ch: u8) -> bool {
    ch.is_ascii_whitespace() || b";&|<>()'\"".contains(&ch)
}

fn parse_heredoc_operator(
    command: &str,
    start: usize,
) -> Result<(usize, HeredocSpec), UnparseableCommand> {
    let bytes = command.as_bytes();
    let mut i = start + 2;
    let strip_tabs = bytes.get(i) == Some(&b'-');
    if strip_tabs {
        i += 1;
    }
    while matches!(bytes.get(i), Some(b' ' | b'\t')) {
        i += 1;
    }
    let Some(&first) = bytes.get(i) else {
        return Err(UnparseableCommand(
            "a here-document whose delimiter can't be read".into(),
        ));
    };

    let (delimiter, live, end) = if matches!(first, b'\'' | b'"') {
        let quote = first;
        let body_start = i + 1;
        let mut j = body_start;
        while j < bytes.len() && bytes[j] != quote && bytes[j] != b'\n' {
            j += 1;
        }
        if j >= bytes.len() || bytes[j] != quote {
            return Err(UnparseableCommand(
                "a here-document whose delimiter can't be read".into(),
            ));
        }
        (command[body_start..j].to_owned(), false, j + 1)
    } else {
        let escaped = first == b'\\';
        if escaped {
            i += 1;
        }
        let body_start = i;
        while i < bytes.len() && !heredoc_stop(bytes[i]) {
            i += 1;
        }
        if i == body_start {
            return Err(UnparseableCommand(
                "a here-document whose delimiter can't be read".into(),
            ));
        }
        (command[body_start..i].to_owned(), !escaped, i)
    };

    Ok((
        end,
        HeredocSpec {
            delimiter,
            strip_tabs,
            live,
        },
    ))
}

fn strip_heredoc_bodies(command: &str) -> Result<(String, Vec<String>), UnparseableCommand> {
    let bytes = command.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut live_bodies = Vec::new();
    let mut pending = Vec::<HeredocSpec>::new();
    let mut i = 0usize;
    let mut quote: Option<u8> = None;

    while i < bytes.len() {
        let ch = bytes[i];
        if let Some(active) = quote {
            out.push(ch);
            if ch == b'\\' && active == b'"' && i + 1 < bytes.len() {
                out.push(bytes[i + 1]);
                i += 2;
                continue;
            }
            if ch == active {
                quote = None;
            }
            i += 1;
            continue;
        }
        if ch == b'\\' && i + 1 < bytes.len() {
            out.extend_from_slice(&bytes[i..i + 2]);
            i += 2;
            continue;
        }
        if matches!(ch, b'\'' | b'"') {
            quote = Some(ch);
            out.push(ch);
            i += 1;
            continue;
        }
        if bytes[i..].starts_with(b"<<") && !bytes[i..].starts_with(b"<<<") {
            let (end, spec) = parse_heredoc_operator(command, i)?;
            out.extend_from_slice(&bytes[i..end]);
            pending.push(spec);
            i = end;
            continue;
        }
        if ch == b'\n' && !pending.is_empty() {
            out.push(ch);
            i += 1;
            for spec in std::mem::take(&mut pending) {
                let mut body = Vec::<String>::new();
                loop {
                    if i >= bytes.len() {
                        return Err(UnparseableCommand(format!(
                            "here-document not terminated (missing {:?})",
                            spec.delimiter
                        )));
                    }
                    let relative_end = bytes[i..].iter().position(|byte| *byte == b'\n');
                    let line_end = relative_end.map_or(bytes.len(), |offset| i + offset);
                    let line = &command[i..line_end];
                    i = if line_end < bytes.len() {
                        line_end + 1
                    } else {
                        bytes.len()
                    };
                    let candidate = if spec.strip_tabs {
                        line.trim_start_matches('\t')
                    } else {
                        line
                    }
                    .trim_end_matches('\r');
                    if candidate == spec.delimiter {
                        break;
                    }
                    body.push(line.to_owned());
                }
                if spec.live {
                    live_bodies.push(body.join("\n"));
                }
            }
            continue;
        }
        out.push(ch);
        i += 1;
    }

    if !pending.is_empty() {
        return Err(UnparseableCommand("a here-document with no body".into()));
    }
    let stripped = String::from_utf8(out)
        .map_err(|_| UnparseableCommand("command stopped being valid UTF-8".into()))?;
    Ok((stripped, live_bodies))
}

/// Returns the first command segment not authorised by policy.
///
/// # Errors
/// Returns [`UnparseableCommand`] when shell structure cannot be checked safely.
pub fn unauthorised_chain(
    policy: &Policy,
    command: &str,
) -> Result<Option<String>, UnparseableCommand> {
    unauthorised_chain_inner(policy, command, 0)
}

fn unauthorised_chain_inner(
    policy: &Policy,
    command: &str,
    depth: usize,
) -> Result<Option<String>, UnparseableCommand> {
    if depth > MAX_NESTING {
        return Err(UnparseableCommand("substitutions nested too deeply".into()));
    }
    let (stripped, live_bodies) = strip_heredoc_bodies(command)?;
    let (masked, mut bodies) = mask_substitutions(&stripped, false)?;
    for body in live_bodies {
        let (_, nested) = mask_substitutions(&body, true)?;
        bodies.extend(nested);
    }
    for (index, raw) in split_top_level(&masked).into_iter().enumerate() {
        let Some(segment) = command_part(&raw)? else {
            continue;
        };
        if only_assignments(&segment) || policy.is_command_allowed(&segment) {
            continue;
        }
        let word = first_word(&segment);
        if POSITION_FREE.contains(&word) || SAFE_BUILTINS.contains(&word) {
            continue;
        }
        let filter_position = index > 0 || depth > 0;
        if filter_position && READ_ONLY_FILTERS.contains(&word) {
            if filter_unsafe(&segment) {
                return Ok(Some(segment));
            }
            continue;
        }
        return Ok(Some(segment));
    }
    for body in bodies {
        if let Some(offending) = unauthorised_chain_inner(policy, &body, depth + 1)? {
            return Ok(Some(offending));
        }
    }
    Ok(None)
}

#[must_use]
pub fn unauthorised_segment(policy: &Policy, command: &str) -> Option<String> {
    for (index, segment) in split_top_level(command).into_iter().enumerate() {
        if policy.is_command_allowed(&segment) {
            continue;
        }
        let word = first_word(&segment);
        if POSITION_FREE.contains(&word) {
            continue;
        }
        if index > 0 && READ_ONLY_FILTERS.contains(&word) {
            if filter_unsafe(&segment) {
                return Some(segment);
            }
            continue;
        }
        return Some(segment);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(commands: &[&str]) -> Policy {
        Policy {
            allowed_commands: commands.iter().map(|value| (*value).to_owned()).collect(),
            ..Policy::default()
        }
    }

    #[test]
    fn quoted_separators_are_data_not_structure() {
        assert_eq!(
            split_top_level("printf ';|&&' && echo done"),
            vec!["printf ';|&&'", "echo done"]
        );
    }

    #[test]
    fn newlines_and_background_operators_split_commands() {
        assert_eq!(
            split_top_level("uptime & id\npwd&&ls"),
            vec!["uptime", "id", "pwd", "ls"]
        );
        assert_eq!(split_top_level("printf x 2>&1"), vec!["printf x 2>&1"]);
    }

    #[test]
    fn substitution_detection_covers_process_substitution() {
        assert_eq!(has_substitution("echo '$(id)'"), None);
        assert_eq!(has_substitution("echo \"$(id)\""), Some("$("));
        assert_eq!(has_substitution("echo `id`"), Some("`"));
        assert_eq!(has_substitution("cat <(id)"), Some("<("));
    }

    #[test]
    fn strict_redirections_refuse_files_but_not_descriptors_or_dev_null() {
        assert!(file_redirection("printf x > /tmp/x").is_some());
        assert!(file_redirection("cat < /etc/passwd").is_some());
        assert!(file_redirection("printf x 2>&1").is_none());
        assert!(file_redirection("printf x >/dev/null").is_none());
        assert!(file_redirection("cat <<EOF").is_none());
    }

    #[test]
    fn filters_cannot_open_paths_or_use_write_options() {
        let policy = policy(&["make"]);
        assert_eq!(unauthorised_segment(&policy, "make | cat"), None);
        assert_eq!(
            unauthorised_segment(&policy, "make | cat /etc/shadow"),
            Some("cat /etc/shadow".into())
        );
        assert_eq!(
            unauthorised_segment(&policy, "make | sort -o /tmp/x"),
            Some("sort -o /tmp/x".into())
        );
    }

    #[test]
    fn chain_check_handles_grammar_and_substitutions() {
        let policy = policy(&["make", "ls", "printf"]);
        assert_eq!(
            unauthorised_chain(&policy, "cd /tmp && make | head"),
            Ok(None)
        );
        assert_eq!(
            unauthorised_chain(&policy, "make; curl bad"),
            Ok(Some("curl bad".into()))
        );
        assert_eq!(
            unauthorised_chain(&policy, "printf '%s' \"$(id)\""),
            Ok(Some("id".into()))
        );
        assert_eq!(
            unauthorised_chain(&policy, "for x in 1 2; do printf '%s' \"$x\"; done"),
            Ok(None)
        );
        assert!(unauthorised_chain(&policy, "case x in x) ls;; esac").is_err());
    }

    #[test]
    fn chain_check_understands_heredocs_and_arithmetic() {
        let policy = policy(&["cat", "printf"]);
        assert_eq!(
            unauthorised_chain(&policy, "cat <<EOF\nplain data\nEOF"),
            Ok(None)
        );
        assert_eq!(
            unauthorised_chain(&policy, "cat <<'EOF'\n$(id)\nEOF"),
            Ok(None)
        );
        assert_eq!(
            unauthorised_chain(&policy, "cat <<EOF\n'$(id)'\nEOF"),
            Ok(Some("id".into()))
        );
        assert_eq!(
            unauthorised_chain(&policy, "printf '%s' \"$((1 | 2))\""),
            Ok(None)
        );
        assert_eq!(
            unauthorised_chain(&policy, "printf '%s' \"$((1 + $(id)))\""),
            Ok(Some("id".into()))
        );
        assert!(unauthorised_chain(&policy, "cat <<EOF\nmissing terminator").is_err());
    }
}
