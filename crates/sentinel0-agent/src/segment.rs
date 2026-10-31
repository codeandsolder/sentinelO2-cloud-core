use crate::policy::Policy;
use brush_parser::{
    ParserOptions,
    ast::{
        AndOr, AndOrList, Command, CommandPrefixOrSuffixItem, CompoundCommand, CompoundList,
        ExtendedTestExpr, IoFileRedirectTarget, IoRedirect, Pipeline, ProcessSubstitutionKind,
        Program, RedirectList, SimpleCommand, Word,
    },
    parse_tokens, tokenize_str, unquote_str,
    word::{self, Parameter, ParameterExpr, WordPiece, WordPieceWithSource},
};

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
const SAFE_BUILTINS: &[&str] = &[
    "test", "[", "[[", "true", "false", ":", "break", "continue", "exit", "return", "wait",
];
// These mutate the parent shell or execute/resolve another command. A textual
// command-name allowlist cannot stay meaningful once they can alter the state
// used to interpret the rest of the same `bash -lc` program.
const STATEFUL_OR_META_BUILTINS: &[&str] = &[
    ".",
    "alias",
    "bg",
    "builtin",
    "cd",
    "command",
    "declare",
    "dirs",
    "disown",
    "enable",
    "eval",
    "exec",
    "export",
    "fc",
    "fg",
    "getopts",
    "hash",
    "history",
    "let",
    "local",
    "mapfile",
    "popd",
    "pushd",
    "read",
    "readarray",
    "readonly",
    "set",
    "shift",
    "shopt",
    "source",
    "suspend",
    "trap",
    "typeset",
    "ulimit",
    "umask",
    "unalias",
    "unset",
];
const MAX_NESTING: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnparseableCommand(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AssignmentKind {
    None,
    Only,
    WithCommand,
}

impl AssignmentKind {
    const fn any(self) -> bool {
        !matches!(self, Self::None)
    }

    const fn only(self) -> bool {
        matches!(self, Self::Only)
    }
}

#[derive(Debug)]
struct CommandInfo {
    rendered: String,
    program: String,
    arguments: Vec<String>,
    filter_position: bool,
    assignment_kind: AssignmentKind,
    has_unsafe_redirection: bool,
}

#[derive(Debug, Default)]
struct Analysis {
    commands: Vec<CommandInfo>,
    substitution: Option<&'static str>,
    file_redirection: Option<String>,
    seen_top_level_command: bool,
}

fn parse_program(source: &str) -> Result<Program, UnparseableCommand> {
    let tokens = tokenize_str(source)
        .map_err(|error| UnparseableCommand(format!("shell tokenization failed: {error}")))?;
    parse_tokens(&tokens, &ParserOptions::default())
        .map_err(|error| UnparseableCommand(format!("shell parsing failed: {error}")))
}

fn check_nesting(depth: usize) -> Result<(), UnparseableCommand> {
    if depth > MAX_NESTING {
        return Err(UnparseableCommand("substitutions nested too deeply".into()));
    }
    Ok(())
}

fn scan_nested_source(
    source: &str,
    analysis: &mut Analysis,
    depth: usize,
) -> Result<(), UnparseableCommand> {
    check_nesting(depth)?;
    let program = parse_program(source)?;
    walk_program(&program, analysis, depth)
}

fn scan_parameter(
    parameter: &Parameter,
    analysis: &mut Analysis,
    depth: usize,
) -> Result<(), UnparseableCommand> {
    if let Parameter::NamedWithIndex { index, .. } = parameter {
        scan_word_text(index, analysis, depth)?;
    }
    Ok(())
}

fn scan_optional_text(
    value: Option<&str>,
    analysis: &mut Analysis,
    depth: usize,
) -> Result<(), UnparseableCommand> {
    if let Some(value) = value {
        scan_word_text(value, analysis, depth)?;
    }
    Ok(())
}

fn scan_parameter_expr(
    expression: &ParameterExpr,
    analysis: &mut Analysis,
    depth: usize,
) -> Result<(), UnparseableCommand> {
    match expression {
        ParameterExpr::Parameter { parameter, .. }
        | ParameterExpr::ParameterLength { parameter, .. }
        | ParameterExpr::Transform { parameter, .. } => scan_parameter(parameter, analysis, depth),
        ParameterExpr::UseDefaultValues {
            parameter,
            default_value,
            ..
        } => {
            scan_parameter(parameter, analysis, depth)?;
            scan_optional_text(default_value.as_deref(), analysis, depth)
        }
        ParameterExpr::AssignDefaultValues { .. } => Err(UnparseableCommand(
            "assignment-style parameter expansion is not supported by exec policy".into(),
        )),
        ParameterExpr::IndicateErrorIfNullOrUnset {
            parameter,
            error_message,
            ..
        } => {
            scan_parameter(parameter, analysis, depth)?;
            scan_optional_text(error_message.as_deref(), analysis, depth)
        }
        ParameterExpr::UseAlternativeValue {
            parameter,
            alternative_value,
            ..
        } => {
            scan_parameter(parameter, analysis, depth)?;
            scan_optional_text(alternative_value.as_deref(), analysis, depth)
        }
        ParameterExpr::RemoveSmallestSuffixPattern {
            parameter, pattern, ..
        }
        | ParameterExpr::RemoveLargestSuffixPattern {
            parameter, pattern, ..
        }
        | ParameterExpr::RemoveSmallestPrefixPattern {
            parameter, pattern, ..
        }
        | ParameterExpr::RemoveLargestPrefixPattern {
            parameter, pattern, ..
        }
        | ParameterExpr::UppercaseFirstChar {
            parameter, pattern, ..
        }
        | ParameterExpr::UppercasePattern {
            parameter, pattern, ..
        }
        | ParameterExpr::LowercaseFirstChar {
            parameter, pattern, ..
        }
        | ParameterExpr::LowercasePattern {
            parameter, pattern, ..
        } => {
            scan_parameter(parameter, analysis, depth)?;
            scan_optional_text(pattern.as_deref(), analysis, depth)
        }
        ParameterExpr::Substring {
            parameter,
            offset,
            length,
            ..
        } => {
            scan_parameter(parameter, analysis, depth)?;
            scan_word_text(&offset.value, analysis, depth)?;
            if let Some(length) = length {
                scan_word_text(&length.value, analysis, depth)?;
            }
            Ok(())
        }
        ParameterExpr::ReplaceSubstring {
            parameter,
            pattern,
            replacement,
            ..
        } => {
            scan_parameter(parameter, analysis, depth)?;
            scan_word_text(pattern, analysis, depth)?;
            scan_optional_text(replacement.as_deref(), analysis, depth)
        }
        ParameterExpr::VariableNames { .. } | ParameterExpr::MemberKeys { .. } => Ok(()),
    }
}

fn scan_word_pieces(
    pieces: &[WordPieceWithSource],
    analysis: &mut Analysis,
    depth: usize,
) -> Result<(), UnparseableCommand> {
    for piece in pieces {
        match &piece.piece {
            WordPiece::CommandSubstitution(source) => {
                analysis.substitution.get_or_insert("$(");
                scan_nested_source(source, analysis, depth + 1)?;
            }
            WordPiece::BackquotedCommandSubstitution(source) => {
                analysis.substitution.get_or_insert("`");
                scan_nested_source(source, analysis, depth + 1)?;
            }
            WordPiece::DoubleQuotedSequence(nested)
            | WordPiece::GettextDoubleQuotedSequence(nested) => {
                scan_word_pieces(nested, analysis, depth)?;
            }
            WordPiece::ParameterExpansion(expression) => {
                scan_parameter_expr(expression, analysis, depth)?;
            }
            WordPiece::ArithmeticExpression(_) => {
                return Err(UnparseableCommand(
                    "arithmetic expansion can mutate shell state and is not supported by exec policy"
                        .into(),
                ));
            }
            WordPiece::Text(_)
            | WordPiece::SingleQuotedText(_)
            | WordPiece::AnsiCQuotedText(_)
            | WordPiece::TildeExpansion(_)
            | WordPiece::EscapeSequence(_) => {}
        }
    }
    Ok(())
}

fn scan_word_text(
    text: &str,
    analysis: &mut Analysis,
    depth: usize,
) -> Result<(), UnparseableCommand> {
    let pieces = word::parse(text, &ParserOptions::default())
        .map_err(|error| UnparseableCommand(format!("shell word parsing failed: {error}")))?;
    scan_word_pieces(&pieces, analysis, depth)
}

fn scan_word(
    value: &Word,
    analysis: &mut Analysis,
    depth: usize,
) -> Result<(), UnparseableCommand> {
    scan_word_text(&value.value, analysis, depth)
}

fn scan_extended_test(
    expression: &ExtendedTestExpr,
    analysis: &mut Analysis,
    depth: usize,
) -> Result<(), UnparseableCommand> {
    match expression {
        ExtendedTestExpr::And(left, right) | ExtendedTestExpr::Or(left, right) => {
            scan_extended_test(left, analysis, depth)?;
            scan_extended_test(right, analysis, depth)
        }
        ExtendedTestExpr::Not(inner) | ExtendedTestExpr::Parenthesized(inner) => {
            scan_extended_test(inner, analysis, depth)
        }
        ExtendedTestExpr::UnaryTest(_, word) => scan_word(word, analysis, depth),
        ExtendedTestExpr::BinaryTest(_, left, right) => {
            scan_word(left, analysis, depth)?;
            scan_word(right, analysis, depth)
        }
    }
}

const fn process_substitution_marker(kind: &ProcessSubstitutionKind) -> &'static str {
    match kind {
        ProcessSubstitutionKind::Read => "<(",
        ProcessSubstitutionKind::Write => ">(",
    }
}

fn scan_redirect(
    redirect: &IoRedirect,
    analysis: &mut Analysis,
    depth: usize,
) -> Result<bool, UnparseableCommand> {
    match redirect {
        IoRedirect::File(_, _, target) => match target {
            IoFileRedirectTarget::Filename(word) => {
                scan_word(word, analysis, depth)?;
                let target = unquote_str(&word.value);
                if target != "/dev/null" {
                    analysis
                        .file_redirection
                        .get_or_insert_with(|| redirect.to_string());
                    return Ok(true);
                }
                Ok(false)
            }
            IoFileRedirectTarget::Fd(_) => Ok(false),
            IoFileRedirectTarget::Duplicate(word) => {
                scan_word(word, analysis, depth)?;
                let target = unquote_str(&word.value);
                if target == "-" || target.chars().all(|ch| ch.is_ascii_digit()) {
                    Ok(false)
                } else {
                    analysis
                        .file_redirection
                        .get_or_insert_with(|| redirect.to_string());
                    Ok(true)
                }
            }
            IoFileRedirectTarget::ProcessSubstitution(kind, command) => {
                analysis
                    .substitution
                    .get_or_insert_with(|| process_substitution_marker(kind));
                walk_compound_list(&command.list, analysis, depth + 1)?;
                Ok(false)
            }
        },
        IoRedirect::HereDocument(_, here_document) => {
            if here_document.requires_expansion {
                let pieces =
                    word::parse_heredoc(&here_document.doc.value, &ParserOptions::default())
                        .map_err(|error| {
                            UnparseableCommand(format!("here-document parsing failed: {error}"))
                        })?;
                scan_word_pieces(&pieces, analysis, depth)?;
            }
            Ok(false)
        }
        IoRedirect::HereString(_, word) => {
            scan_word(word, analysis, depth)?;
            Ok(false)
        }
        IoRedirect::OutputAndError(word, _) => {
            scan_word(word, analysis, depth)?;
            let target = unquote_str(&word.value);
            if target != "/dev/null" {
                analysis
                    .file_redirection
                    .get_or_insert_with(|| redirect.to_string());
                return Ok(true);
            }
            Ok(false)
        }
    }
}

fn scan_redirects(
    redirects: Option<&RedirectList>,
    analysis: &mut Analysis,
    depth: usize,
) -> Result<bool, UnparseableCommand> {
    let Some(redirects) = redirects else {
        return Ok(false);
    };
    let mut unsafe_redirection = false;
    for redirect in &redirects.0 {
        unsafe_redirection |= scan_redirect(redirect, analysis, depth)?;
    }
    Ok(unsafe_redirection)
}

fn scan_item(
    item: &CommandPrefixOrSuffixItem,
    analysis: &mut Analysis,
    depth: usize,
) -> Result<bool, UnparseableCommand> {
    match item {
        CommandPrefixOrSuffixItem::IoRedirect(redirect) => scan_redirect(redirect, analysis, depth),
        CommandPrefixOrSuffixItem::Word(word)
        | CommandPrefixOrSuffixItem::AssignmentWord(_, word) => {
            scan_word(word, analysis, depth)?;
            Ok(false)
        }
        CommandPrefixOrSuffixItem::ProcessSubstitution(kind, command) => {
            analysis
                .substitution
                .get_or_insert_with(|| process_substitution_marker(kind));
            walk_compound_list(&command.list, analysis, depth + 1)?;
            Ok(false)
        }
    }
}

fn command_arguments(simple: &SimpleCommand) -> Vec<String> {
    simple
        .suffix
        .as_ref()
        .into_iter()
        .flat_map(|suffix| suffix.0.iter())
        .filter_map(|item| match item {
            CommandPrefixOrSuffixItem::Word(word) => Some(unquote_str(&word.value)),
            _ => None,
        })
        .collect()
}

fn assignment_kind(simple: &SimpleCommand) -> AssignmentKind {
    let items = simple
        .prefix
        .as_ref()
        .into_iter()
        .flat_map(|prefix| prefix.0.iter())
        .chain(
            simple
                .suffix
                .as_ref()
                .into_iter()
                .flat_map(|suffix| suffix.0.iter()),
        )
        .collect::<Vec<_>>();
    if !items
        .iter()
        .any(|item| matches!(item, CommandPrefixOrSuffixItem::AssignmentWord(_, _)))
    {
        AssignmentKind::None
    } else if simple.word_or_name.is_none()
        && items
            .iter()
            .all(|item| matches!(item, CommandPrefixOrSuffixItem::AssignmentWord(_, _)))
    {
        AssignmentKind::Only
    } else {
        AssignmentKind::WithCommand
    }
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

fn file_option(name: &str, option: &str) -> bool {
    match name {
        "grep" | "egrep" | "fgrep" => matches!(option, "-f" | "--file"),
        "rg" => matches!(
            option,
            "-f" | "--file" | "--pre" | "--pre-glob" | "--hostname-bin"
        ),
        "wc" | "sort" => option == "--files0-from",
        "date" => matches!(option, "-f" | "--file"),
        _ => false,
    }
}

fn filter_unsafe(name: &str, arguments: &[String], has_unsafe_redirection: bool) -> bool {
    if has_unsafe_redirection {
        return true;
    }
    if arguments.iter().any(|token| {
        let head = token.split('=').next().unwrap_or(token);
        file_option(name, head)
            || (name == "sort" && matches!(head, "-o" | "--output" | "--compress-program" | "-S"))
    }) {
        return true;
    }
    if matches!(
        name,
        "tr" | "echo" | "printf" | "true" | "false" | "seq" | "date"
    ) {
        return false;
    }
    let mut operands = Vec::new();
    let mut expecting_value = false;
    for token in arguments {
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
    !operands.is_empty()
}

fn push_before_nested(analysis: &mut Analysis, nested_start: usize, command: CommandInfo) {
    let nested = analysis.commands.split_off(nested_start);
    analysis.commands.push(command);
    analysis.commands.extend(nested);
}

fn walk_simple(
    simple: &SimpleCommand,
    analysis: &mut Analysis,
    depth: usize,
) -> Result<(), UnparseableCommand> {
    let filter_position = depth > 0 || analysis.seen_top_level_command;
    if depth == 0 {
        analysis.seen_top_level_command = true;
    }
    let nested_start = analysis.commands.len();
    let mut unsafe_redirection = false;
    if let Some(prefix) = &simple.prefix {
        for item in &prefix.0 {
            unsafe_redirection |= scan_item(item, analysis, depth)?;
        }
    }
    if let Some(word) = &simple.word_or_name {
        scan_word(word, analysis, depth)?;
    }
    if let Some(suffix) = &simple.suffix {
        for item in &suffix.0 {
            unsafe_redirection |= scan_item(item, analysis, depth)?;
        }
    }

    let assignment_kind = assignment_kind(simple);
    let Some(program) = simple.word_or_name.as_ref() else {
        push_before_nested(
            analysis,
            nested_start,
            CommandInfo {
                rendered: simple.to_string(),
                program: String::new(),
                arguments: Vec::new(),
                filter_position,
                assignment_kind,
                has_unsafe_redirection: unsafe_redirection,
            },
        );
        return Ok(());
    };
    push_before_nested(
        analysis,
        nested_start,
        CommandInfo {
            rendered: simple.to_string(),
            program: unquote_str(&program.value),
            arguments: command_arguments(simple),
            filter_position,
            assignment_kind,
            has_unsafe_redirection: unsafe_redirection,
        },
    );
    Ok(())
}

fn walk_command(
    command: &Command,
    analysis: &mut Analysis,
    depth: usize,
) -> Result<(), UnparseableCommand> {
    match command {
        Command::Simple(simple) => walk_simple(simple, analysis, depth),
        Command::Compound(compound, redirects) => {
            scan_redirects(redirects.as_ref(), analysis, depth)?;
            walk_compound(compound, analysis, depth)
        }
        Command::Function(_) => Err(UnparseableCommand(
            "function definitions are not supported by exec policy".into(),
        )),
        Command::ExtendedTest(test, redirects) => {
            let filter_position = depth > 0 || analysis.seen_top_level_command;
            if depth == 0 {
                analysis.seen_top_level_command = true;
            }
            let nested_start = analysis.commands.len();
            scan_extended_test(&test.expr, analysis, depth)?;
            let unsafe_redirection = scan_redirects(redirects.as_ref(), analysis, depth)?;
            push_before_nested(
                analysis,
                nested_start,
                CommandInfo {
                    rendered: format!("[[ {test} ]]"),
                    program: "[[".into(),
                    arguments: Vec::new(),
                    filter_position,
                    assignment_kind: AssignmentKind::None,
                    has_unsafe_redirection: unsafe_redirection,
                },
            );
            Ok(())
        }
    }
}

fn walk_pipeline(
    pipeline: &Pipeline,
    analysis: &mut Analysis,
    depth: usize,
) -> Result<(), UnparseableCommand> {
    for command in &pipeline.seq {
        walk_command(command, analysis, depth)?;
    }
    Ok(())
}

fn walk_and_or(
    list: &AndOrList,
    analysis: &mut Analysis,
    depth: usize,
) -> Result<(), UnparseableCommand> {
    walk_pipeline(&list.first, analysis, depth)?;
    for additional in &list.additional {
        match additional {
            AndOr::And(pipeline) | AndOr::Or(pipeline) => {
                walk_pipeline(pipeline, analysis, depth)?;
            }
        }
    }
    Ok(())
}

fn walk_compound_list(
    list: &CompoundList,
    analysis: &mut Analysis,
    depth: usize,
) -> Result<(), UnparseableCommand> {
    check_nesting(depth)?;
    for item in &list.0 {
        walk_and_or(&item.0, analysis, depth)?;
    }
    Ok(())
}

fn walk_compound(
    command: &CompoundCommand,
    analysis: &mut Analysis,
    depth: usize,
) -> Result<(), UnparseableCommand> {
    match command {
        CompoundCommand::Arithmetic(_) => Err(UnparseableCommand(
            "arithmetic commands are not supported by exec policy".into(),
        )),
        CompoundCommand::ArithmeticForClause(_) => Err(UnparseableCommand(
            "arithmetic for clauses are not supported by exec policy".into(),
        )),
        CompoundCommand::BraceGroup(command) => walk_compound_list(&command.list, analysis, depth),
        CompoundCommand::Subshell(command) => walk_compound_list(&command.list, analysis, depth),
        CompoundCommand::ForClause(_) => Err(UnparseableCommand(
            "for/select clauses mutate shell state and are not supported by exec policy".into(),
        )),
        CompoundCommand::CaseClause(_) => Err(UnparseableCommand(
            "case clauses are not supported by exec policy".into(),
        )),
        CompoundCommand::IfClause(command) => {
            walk_compound_list(&command.condition, analysis, depth)?;
            walk_compound_list(&command.then, analysis, depth)?;
            if let Some(elses) = &command.elses {
                for branch in elses {
                    if let Some(condition) = &branch.condition {
                        walk_compound_list(condition, analysis, depth)?;
                    }
                    walk_compound_list(&branch.body, analysis, depth)?;
                }
            }
            Ok(())
        }
        CompoundCommand::WhileClause(command) | CompoundCommand::UntilClause(command) => {
            walk_compound_list(&command.0, analysis, depth)?;
            walk_compound_list(&command.1.list, analysis, depth)
        }
        CompoundCommand::Coprocess(_) => Err(UnparseableCommand(
            "coprocesses are not supported by exec policy".into(),
        )),
    }
}

fn walk_program(
    program: &Program,
    analysis: &mut Analysis,
    depth: usize,
) -> Result<(), UnparseableCommand> {
    for command in &program.complete_commands {
        walk_compound_list(command, analysis, depth)?;
    }
    Ok(())
}

fn analyze(command: &str) -> Result<Analysis, UnparseableCommand> {
    let mut analysis = Analysis::default();
    scan_nested_source(command, &mut analysis, 0)?;
    Ok(analysis)
}

#[must_use]
pub fn split_top_level(command: &str) -> Vec<String> {
    analyze(command).map_or_else(
        |_| vec![command.trim().to_owned()],
        |analysis| {
            analysis
                .commands
                .into_iter()
                .filter(|command| !command.assignment_kind.only())
                .map(|command| command.rendered)
                .collect()
        },
    )
}

#[must_use]
pub fn has_substitution(command: &str) -> Option<&'static str> {
    analyze(command)
        .ok()
        .and_then(|analysis| analysis.substitution)
}

#[must_use]
pub fn control_character(command: &str) -> Option<char> {
    command
        .chars()
        .find(|ch| ((*ch as u32) < 32 && *ch != '\t') || *ch as u32 == 127)
}

#[must_use]
pub fn file_redirection(command: &str) -> Option<String> {
    analyze(command)
        .ok()
        .and_then(|analysis| analysis.file_redirection)
}

fn first_unauthorised(policy: &Policy, analysis: Analysis, chain: bool) -> Option<String> {
    for command in analysis.commands {
        // Assignments can affect command resolution directly (PATH), alter what an
        // otherwise allowlisted executable loads (LD_PRELOAD, PYTHONPATH, ...), or
        // persist for later segments. A variable blacklist would always be partial.
        if command.assignment_kind.any() {
            return Some(command.rendered);
        }
        let name = command.program.as_str();
        if STATEFUL_OR_META_BUILTINS.contains(&name) {
            return Some(command.rendered);
        }
        // Bash printf is normally harmless, but `printf -v NAME ...` writes a
        // shell variable and can therefore mutate PATH or another runtime hook.
        if name == "printf"
            && command
                .arguments
                .first()
                .is_some_and(|arg| arg.starts_with("-v"))
        {
            return Some(command.rendered);
        }
        if policy.is_command_allowed(&command.rendered) {
            continue;
        }
        if chain && SAFE_BUILTINS.contains(&name) {
            if command.has_unsafe_redirection {
                return Some(command.rendered);
            }
            continue;
        }
        if command.filter_position && READ_ONLY_FILTERS.contains(&name) {
            if filter_unsafe(name, &command.arguments, command.has_unsafe_redirection) {
                return Some(command.rendered);
            }
            continue;
        }
        return Some(command.rendered);
    }
    None
}

/// Returns the first command segment not authorised by policy.
///
/// # Errors
/// Returns [`UnparseableCommand`] when shell structure cannot be checked safely.
pub fn unauthorised_chain(
    policy: &Policy,
    command: &str,
) -> Result<Option<String>, UnparseableCommand> {
    analyze(command).map(|analysis| first_unauthorised(policy, analysis, true))
}

/// Returns the first command segment not authorised by strict policy.
///
/// # Errors
/// Returns [`UnparseableCommand`] when shell structure cannot be checked safely.
pub fn unauthorised_segment(
    policy: &Policy,
    command: &str,
) -> Result<Option<String>, UnparseableCommand> {
    analyze(command).map(|analysis| first_unauthorised(policy, analysis, false))
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
        assert_eq!(split_top_level("printf x 2>&1"), vec!["printf x 2>& 1"]);
    }

    #[test]
    fn substitution_detection_covers_process_substitution() {
        assert_eq!(has_substitution("echo '$(id)'"), None);
        assert_eq!(has_substitution("echo \"$(id)\""), Some("$("));
        assert_eq!(has_substitution("echo `id`"), Some("`"));
        assert_eq!(has_substitution("cat <(id)"), Some("<("));
        assert_eq!(has_substitution("echo ${x:-$(id)}"), Some("$("));
    }

    #[test]
    fn strict_redirections_refuse_files_but_not_descriptors_or_dev_null() {
        assert!(file_redirection("printf x > /tmp/x").is_some());
        assert!(file_redirection("cat < /etc/passwd").is_some());
        assert!(file_redirection("printf x 2>&1").is_none());
        assert!(file_redirection("printf x >/dev/null").is_none());
        assert!(file_redirection("cat <<EOF\nx\nEOF").is_none());
    }

    #[test]
    fn nested_substitution_does_not_make_first_top_level_filter_free() {
        let policy = policy(&["printf"]);
        assert_eq!(
            unauthorised_chain(&policy, "cat \"$(printf x)\""),
            Ok(Some("cat \"$(printf x)\"".into()))
        );
    }

    #[test]
    fn parent_command_is_reported_before_nested_substitution() {
        let empty = policy(&[]);
        assert_eq!(
            unauthorised_chain(&empty, "curl \"$(id)\""),
            Ok(Some("curl \"$(id)\"".into()))
        );
        let outer_allowed = policy(&["curl"]);
        assert_eq!(
            unauthorised_chain(&outer_allowed, "curl \"$(id)\""),
            Ok(Some("id".into()))
        );
    }

    #[test]
    fn process_substitution_respects_nesting_limit() {
        let policy = policy(&["cat"]);
        let mut command = "cat".to_owned();
        for _ in 0..=MAX_NESTING {
            command = format!("cat <({command})");
        }
        assert!(unauthorised_chain(&policy, &command).is_err());
    }

    #[test]
    fn filters_cannot_open_paths_or_use_write_options() {
        let policy = policy(&["make"]);
        assert_eq!(unauthorised_segment(&policy, "make | cat"), Ok(None));
        assert_eq!(
            unauthorised_segment(&policy, "make | cat /etc/shadow"),
            Ok(Some("cat /etc/shadow".into()))
        );
        assert_eq!(
            unauthorised_segment(&policy, "make | sort -o /tmp/x"),
            Ok(Some("sort -o /tmp/x".into()))
        );
    }

    #[test]
    fn redirect_only_and_malformed_commands_fail_closed() {
        let empty = policy(&[]);
        assert_eq!(
            unauthorised_chain(&empty, "> /tmp/owned"),
            Ok(Some("> /tmp/owned".into()))
        );
        assert_eq!(
            unauthorised_chain(&empty, "FOO=bar"),
            Ok(Some("FOO=bar".into()))
        );
        assert!(unauthorised_chain(&empty, "echo '").is_err());
        assert!(unauthorised_segment(&empty, "echo '").is_err());
    }

    #[test]
    fn extended_test_is_safe_builtin_only_for_allowlist_chains() {
        let empty = policy(&[]);
        assert_eq!(unauthorised_chain(&empty, "[[ x == x ]]"), Ok(None));
        assert!(matches!(
            unauthorised_segment(&empty, "[[ x == x ]]"),
            Ok(Some(_))
        ));
    }

    #[test]
    fn chain_check_handles_grammar_and_substitutions() {
        let policy = policy(&["make", "ls", "printf"]);
        assert_eq!(
            unauthorised_chain(&policy, "cd /tmp && make | head"),
            Ok(Some("cd /tmp".into()))
        );
        assert_eq!(
            unauthorised_chain(&policy, "make; curl bad"),
            Ok(Some("curl bad".into()))
        );
        assert_eq!(
            unauthorised_chain(&policy, "printf '%s' \"$(id)\""),
            Ok(Some("id".into()))
        );
        assert!(unauthorised_chain(&policy, "for x in 1 2; do printf '%s' \"$x\"; done").is_err());
        assert!(unauthorised_chain(&policy, "case x in x) ls;; *) curl bad;; esac").is_err());
    }

    #[test]
    fn shell_state_cannot_redirect_an_allowlisted_command() {
        let policy = policy(&["ls"]);
        assert_eq!(
            unauthorised_chain(&policy, "PATH=/tmp/attacker:$PATH; ls"),
            Ok(Some("PATH=/tmp/attacker:$PATH".into()))
        );
        assert_eq!(
            unauthorised_chain(&policy, "LD_PRELOAD=/tmp/evil.so ls"),
            Ok(Some("LD_PRELOAD=/tmp/evil.so ls".into()))
        );
        assert!(unauthorised_chain(&policy, "for PATH in /tmp/attacker; do ls; done").is_err());
    }

    #[test]
    fn parent_shell_mutators_are_refused_even_when_named_in_the_allowlist() {
        let policy = policy(&["ls", "cd", "read", "export", "command", "eval"]);
        for command in [
            "cd /tmp; ls",
            "read PATH; ls",
            "export PATH=/tmp/attacker; ls",
            "command ls",
            "eval ls",
        ] {
            assert!(
                matches!(unauthorised_chain(&policy, command), Ok(Some(_))),
                "unexpectedly allowed {command:?}"
            );
        }
    }

    #[test]
    fn printf_cannot_write_shell_state_but_normal_printf_still_works() {
        let policy = policy(&["ls", "printf"]);
        assert_eq!(
            unauthorised_chain(&policy, "printf -v PATH /tmp/attacker; ls"),
            Ok(Some("printf -v PATH /tmp/attacker".into()))
        );
        assert_eq!(unauthorised_chain(&policy, "printf '%s' ok"), Ok(None));
        assert!(unauthorised_chain(&policy, ": ${PATH:=/tmp/attacker}; ls").is_err());
        assert!(unauthorised_chain(&policy, r#": "$((PATH=123))"; ls"#).is_err());
    }

    #[test]
    fn historically_unsupported_bash_constructs_still_fail_closed() {
        let policy = policy(&["echo", "true"]);
        for command in [
            "f() { echo ok; }",
            "((1 + 2))",
            "for ((i=0; i<2; i++)); do echo ok; done",
            "case x in x) echo ok;; esac",
            "coproc echo ok",
        ] {
            assert!(
                unauthorised_chain(&policy, command).is_err(),
                "unexpectedly accepted {command:?}"
            );
        }
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
        assert!(
            unauthorised_chain(&policy, "printf '%s' \"$((1 | 2))\"").is_err(),
            "checked exec rejects arithmetic expansion because it can mutate shell state"
        );
        assert!(
            unauthorised_chain(&policy, "printf '%s' \"$((1 + $(id)))\"").is_err(),
            "arithmetic expansion is rejected before nested shell evaluation"
        );
        assert!(unauthorised_chain(&policy, "cat <<EOF\nmissing terminator").is_err());
    }

    #[test]
    fn concessions_cannot_read_relative_files_or_hide_file_inputs_in_options() {
        let policy = policy(&["make"]);
        assert_eq!(
            unauthorised_chain(&policy, "make | cat secret.txt"),
            Ok(Some("cat secret.txt".into()))
        );
        assert_eq!(
            unauthorised_chain(&policy, "make | grep -f patterns needle"),
            Ok(Some("grep -f patterns needle".into()))
        );
        assert_eq!(
            unauthorised_chain(&policy, "make | rg --file=patterns needle"),
            Ok(Some("rg --file=patterns needle".into()))
        );
        assert_eq!(unauthorised_chain(&policy, "make | cat"), Ok(None));
        assert_eq!(unauthorised_chain(&policy, "make | printf done"), Ok(None));
    }

    #[test]
    fn concession_segments_cannot_redirect_to_files() {
        let policy = policy(&["make"]);
        assert_eq!(
            unauthorised_chain(&policy, "make && cd . > result.txt"),
            Ok(Some("cd . > result.txt".into()))
        );
        assert_eq!(
            unauthorised_chain(&policy, "make | printf done > result.txt"),
            Ok(Some("printf done > result.txt".into()))
        );
    }
}
