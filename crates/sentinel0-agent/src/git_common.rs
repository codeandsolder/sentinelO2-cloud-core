//! Shared hermetic Git command construction for repository operations and snapshots.

use crate::policy::Policy;
use serde_json::{Map, Value};
use std::path::Path;

pub(super) fn git_argv<'a>(
    policy: &Policy,
    root: &Path,
    arguments: impl IntoIterator<Item = &'a str>,
) -> Vec<String> {
    let mut command = vec![
        policy.tooling.command("git").display().to_string(),
        "-C".into(),
        root.display().to_string(),
        "-c".into(),
        "core.fsmonitor=false".into(),
    ];
    command.extend(arguments.into_iter().map(str::to_owned));
    command
}

pub(super) fn git_env() -> Map<String, Value> {
    Map::from_iter([
        ("GIT_TERMINAL_PROMPT".into(), Value::String("0".into())),
        ("GIT_OPTIONAL_LOCKS".into(), Value::String("0".into())),
        ("GIT_PAGER".into(), Value::String("cat".into())),
        ("GIT_CONFIG_NOSYSTEM".into(), Value::String("1".into())),
        ("LC_ALL".into(), Value::String("C".into())),
    ])
}
