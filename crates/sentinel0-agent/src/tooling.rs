use serde_json::{Map, Value, json};
use std::{
    collections::BTreeMap,
    env,
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
};

use crate::handler_error::HandlerError;

#[derive(Debug, Clone)]
pub struct Tooling {
    pub search_path: Vec<PathBuf>,
    pub executables: BTreeMap<String, PathBuf>,
    pub uv_python: String,
    pub forbid_direct_python: bool,
}

impl Default for Tooling {
    fn default() -> Self {
        let search_path = env::var_os("PATH")
            .map(|value| env::split_paths(&value).collect())
            .filter(|paths: &Vec<PathBuf>| !paths.is_empty())
            .unwrap_or_else(|| {
                ["/usr/local/bin", "/usr/bin", "/bin"]
                    .into_iter()
                    .map(PathBuf::from)
                    .collect()
            });
        Self {
            search_path,
            executables: BTreeMap::new(),
            uv_python: "3".into(),
            forbid_direct_python: true,
        }
    }
}

impl Tooling {
    #[must_use]
    pub fn command(&self, name: &str) -> PathBuf {
        self.executables
            .get(name)
            .cloned()
            .or_else(|| self.resolve(name))
            .unwrap_or_else(|| PathBuf::from(name))
    }

    /// # Errors
    /// Returns an error when the configured tool search path cannot be represented safely.
    pub fn path_env(&self) -> Result<OsString, HandlerError> {
        env::join_paths(&self.search_path).map_err(|error| {
            HandlerError::new(
                "tooling_invalid",
                format!("tooling.path cannot be represented as PATH: {error}"),
            )
        })
    }

    /// # Errors
    /// Returns an error when the command environment cannot be configured safely.
    pub fn configure_tokio(
        &self,
        command: &mut tokio::process::Command,
    ) -> Result<(), HandlerError> {
        command.env("PATH", self.path_env()?);
        Ok(())
    }

    /// # Errors
    /// Returns an error when the command environment cannot be configured safely.
    pub fn configure_std(&self, command: &mut std::process::Command) -> Result<(), HandlerError> {
        command.env("PATH", self.path_env()?);
        Ok(())
    }

    #[must_use]
    pub fn resolve(&self, name: &str) -> Option<PathBuf> {
        if let Some(configured) = self.executables.get(name) {
            return is_executable(configured).then(|| configured.clone());
        }
        self.search_path
            .iter()
            .map(|dir| dir.join(name))
            .find(|path| is_executable(path))
    }

    #[must_use]
    pub fn report(&self) -> Value {
        let names = [
            "bash",
            "git",
            "nginx",
            "pwsh",
            "sudo",
            "systemctl",
            "systemd-analyze",
            "uv",
        ];
        let resolved = names
            .into_iter()
            .map(|name| {
                (
                    name.to_owned(),
                    self.resolve(name).map_or(Value::Null, |path| {
                        Value::String(path.display().to_string())
                    }),
                )
            })
            .collect::<Map<_, _>>();
        json!({
            "path": self.search_path.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
            "executables": resolved,
            "uv_python": self.uv_python,
            "forbid_direct_python": self.forbid_direct_python,
        })
    }

    #[must_use]
    pub fn direct_python_violation(&self, command: &str) -> Option<&'static str> {
        if !self.forbid_direct_python {
            return None;
        }
        for segment in crate::segment::split_top_level(command) {
            let Some(argv) = shlex::split(&segment) else {
                continue;
            };
            let Some(program) = effective_program(&argv) else {
                continue;
            };
            let name = Path::new(program)
                .file_name()
                .and_then(OsStr::to_str)
                .unwrap_or(program);
            if matches!(name, "pip" | "pip3") {
                return Some("pip");
            }
            if matches!(name, "python" | "python3") {
                return Some("python");
            }
        }
        None
    }
}

fn effective_program(argv: &[String]) -> Option<&str> {
    let mut index = 0;
    while argv
        .get(index)
        .is_some_and(|part| part.contains('=') && !part.starts_with('-'))
    {
        index += 1;
    }
    if argv.get(index).map(String::as_str) == Some("sudo") {
        index += 1;
        while let Some(part) = argv.get(index) {
            if part == "--" {
                index += 1;
                break;
            }
            if matches!(
                part.as_str(),
                "-u" | "--user"
                    | "-g"
                    | "--group"
                    | "-h"
                    | "--host"
                    | "-p"
                    | "--prompt"
                    | "-C"
                    | "--close-from"
                    | "-T"
                    | "--command-timeout"
            ) {
                index = index.saturating_add(2);
                continue;
            }
            if part.starts_with("--user=")
                || part.starts_with("--group=")
                || part.starts_with("--host=")
                || part.starts_with("--prompt=")
                || part.starts_with("--close-from=")
                || part.starts_with("--command-timeout=")
            {
                index += 1;
                continue;
            }
            if !part.starts_with('-') {
                break;
            }
            index += 1;
        }
    }
    argv.get(index).map(String::as_str)
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestResult;

    #[test]
    fn direct_python_policy_catches_plain_and_sudo_invocations() -> TestResult {
        let tooling = Tooling::default();
        assert_eq!(
            tooling.direct_python_violation("python3 x.py"),
            Some("python")
        );
        assert_eq!(
            tooling.direct_python_violation("sudo -n pip install x"),
            Some("pip")
        );
        assert_eq!(
            tooling.direct_python_violation("sudo -n -u nobody python3 x.py"),
            Some("python")
        );
        assert_eq!(tooling.direct_python_violation("uv run python x.py"), None);
        assert_eq!(tooling.direct_python_violation("echo python3"), None);

        Ok(())
    }
}
