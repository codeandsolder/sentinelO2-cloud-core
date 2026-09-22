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
    "awk",
    "sed",
    "jq",
    "rg",
    "cat",
    "tee",
    "column",
    "rev",
    "tac",
    "nl",
    "fold",
    "paste",
    "join",
    "comm",
    "xxd",
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
            if ch == '\\' && i + 1 < chars.len() {
                i += 1;
                buf.push(chars[i]);
            } else if ch == active {
                quote = None;
            }
            i += 1;
            continue;
        }

        if ch == '\'' || ch == '"' {
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

        let double = if i + 1 < chars.len() {
            Some((ch, chars[i + 1]))
        } else {
            None
        };
        if matches!(double, Some(('&', '&') | ('|', '|'))) {
            let trimmed = buf.trim();
            if !trimmed.is_empty() {
                out.push(trimmed.to_owned());
            }
            buf.clear();
            i += 2;
            continue;
        }
        if ch == ';' || ch == '|' {
            let trimmed = buf.trim();
            if !trimmed.is_empty() {
                out.push(trimmed.to_owned());
            }
            buf.clear();
            i += 1;
            continue;
        }

        buf.push(ch);
        i += 1;
    }

    let trimmed = buf.trim();
    if !trimmed.is_empty() {
        out.push(trimmed.to_owned());
    }
    out
}

pub fn has_substitution(command: &str) -> Option<&'static str> {
    let chars: Vec<char> = command.chars().collect();
    let mut i = 0;
    let mut quote: Option<char> = None;
    while i < chars.len() {
        let ch = chars[i];
        if quote == Some('\'') {
            if ch == '\'' {
                quote = None;
            }
            i += 1;
            continue;
        }
        if ch == '\\' && i + 1 < chars.len() {
            i += 2;
            continue;
        }
        if quote == Some('"') {
            if ch == '"' {
                quote = None;
                i += 1;
                continue;
            }
            if ch == '$' && chars.get(i + 1) == Some(&'(') {
                return Some("$(");
            }
            if ch == '`' {
                return Some("`");
            }
            i += 1;
            continue;
        }
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
            i += 1;
            continue;
        }
        if ch == '$' && chars.get(i + 1) == Some(&'(') {
            return Some("$(");
        }
        if ch == '`' {
            return Some("`");
        }
        i += 1;
    }
    None
}

fn first_word(segment: &str) -> &str {
    segment.split_whitespace().next().unwrap_or("")
}

pub fn unauthorised_segment(policy: &Policy, command: &str) -> Option<String> {
    for (index, segment) in split_top_level(command).into_iter().enumerate() {
        if policy.is_command_allowed(&segment) {
            continue;
        }
        let word = first_word(&segment);
        if word == "cd" {
            continue;
        }
        if index > 0 && READ_ONLY_FILTERS.contains(&word) {
            continue;
        }
        return Some(segment);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_separators_are_data_not_structure() {
        assert_eq!(
            split_top_level("printf ';|&&' && echo done"),
            vec!["printf ';|&&'", "echo done"]
        );
    }

    #[test]
    fn substitution_ignores_single_quotes_but_not_double_quotes() {
        assert_eq!(has_substitution("echo '$(id)'"), None);
        assert_eq!(has_substitution("echo \"$(id)\""), Some("$("));
        assert_eq!(has_substitution("echo `id`"), Some("`"));
    }

    #[test]
    fn strict_segments_match_official_concessions() {
        let policy = Policy {
            allowed_commands: vec!["make".into()],
            ..Policy::default()
        };
        assert_eq!(
            unauthorised_segment(&policy, "cd /tmp && make | head"),
            None
        );
        assert_eq!(
            unauthorised_segment(&policy, "make; curl bad"),
            Some("curl bad".into())
        );
    }
}
