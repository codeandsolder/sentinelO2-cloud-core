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
    let mut chars = segment.chars().peekable();
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
    let mut rest = segment.trim().to_owned();
    loop {
        rest = rest.trim_start_matches('(').trim().to_owned();
        let word = first_word(&rest).to_owned();
        if LEADING_KEYWORDS.contains(&word.as_str()) {
            rest = rest[word.len()..].trim().to_owned();
        } else {
            break;
        }
    }
    let word = first_word(&rest);
    if word.is_empty() || CLOSING_KEYWORDS.contains(&word) || HEADER_KEYWORDS.contains(&word) {
        return Ok(None);
    }
    if matches!(word, "case" | "esac") {
        return Err(UnparseableCommand("a case statement".into()));
    }
    while rest.ends_with(')') && rest.matches(')').count() > rest.matches('(').count() {
        rest.pop();
        rest = rest.trim_end().to_owned();
    }
    Ok((!rest.is_empty()).then_some(rest))
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

fn substitution_bodies(command: &str) -> Result<(String, Vec<String>), UnparseableCommand> {
    let bytes = command.as_bytes();
    let mut masked = String::new();
    let mut bodies = Vec::new();
    let mut i = 0;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let ch = bytes[i];
        if quote == Some(b'\'') {
            masked.push(ch as char);
            if ch == b'\'' {
                quote = None;
            }
            i += 1;
            continue;
        }
        if ch == b'\\' && i + 1 < bytes.len() {
            masked.push_str(&command[i..i + 2]);
            i += 2;
            continue;
        }
        if quote == Some(b'"') && ch == b'"' {
            quote = None;
            masked.push('"');
            i += 1;
            continue;
        }
        if quote.is_none() && matches!(ch, b'\'' | b'"') {
            quote = Some(ch);
            masked.push(ch as char);
            i += 1;
            continue;
        }
        let process =
            quote.is_none() && (bytes[i..].starts_with(b"<(") || bytes[i..].starts_with(b">("));
        let dollar = bytes[i..].starts_with(b"$(") && !bytes[i..].starts_with(b"$((");
        if dollar || process {
            let body_start = i + 2;
            let mut j = body_start;
            let mut depth = 1usize;
            let mut inner_quote: Option<u8> = None;
            while j < bytes.len() {
                let current = bytes[j];
                if let Some(active) = inner_quote {
                    if current == b'\\' && active == b'"' && j + 1 < bytes.len() {
                        j += 2;
                        continue;
                    }
                    if current == active {
                        inner_quote = None;
                    }
                } else if matches!(current, b'\'' | b'"') {
                    inner_quote = Some(current);
                } else if current == b'(' {
                    depth += 1;
                } else if current == b')' {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                j += 1;
            }
            if j >= bytes.len() {
                return Err(UnparseableCommand(
                    "unbalanced parentheses in a substitution".into(),
                ));
            }
            bodies.push(command[body_start..j].to_owned());
            masked.push_str("__SX_SUBST__");
            i = j + 1;
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
            masked.push_str("__SX_SUBST__");
            i = j + 1;
            continue;
        }
        masked.push(ch as char);
        i += 1;
    }
    Ok((masked, bodies))
}

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
    if command.contains("<<") && !command.contains("<<<") {
        return Err(UnparseableCommand("a here-document".into()));
    }
    let (masked, bodies) = substitution_bodies(command)?;
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
        if (index > 0 || depth > 0) && READ_ONLY_FILTERS.contains(&word) {
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
            unauthorised_chain(&policy, "cd /tmp && make | head").unwrap(),
            None
        );
        assert_eq!(
            unauthorised_chain(&policy, "make; curl bad").unwrap(),
            Some("curl bad".into())
        );
        assert_eq!(
            unauthorised_chain(&policy, "printf '%s' \"$(id)\"").unwrap(),
            Some("id".into())
        );
        assert_eq!(
            unauthorised_chain(&policy, "for x in 1 2; do printf '%s' \"$x\"; done").unwrap(),
            None
        );
        assert!(unauthorised_chain(&policy, "case x in x) ls;; esac").is_err());
    }
}
