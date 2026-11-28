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
                #[cfg(unix)]
                let dirs = ["/usr/local/bin", "/usr/bin", "/bin"];
                #[cfg(windows)]
                let dirs = [r"C:\Windows\System32", r"C:\Windows"];
                dirs.into_iter().map(PathBuf::from).collect()
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
    #[must_use = "the returned path locates the selected tool executable"]
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

    #[must_use = "the result identifies the resolved helper executable when available"]
    pub fn resolve(&self, name: &str) -> Option<PathBuf> {
        if let Some(configured) = self.executables.get(name) {
            return is_executable(configured).then(|| configured.clone());
        }
        self.search_path.iter().find_map(|dir| {
            let candidate = dir.join(name);
            if is_executable(&candidate) {
                return Some(candidate);
            }
            #[cfg(windows)]
            if candidate.extension().is_none() {
                for extension in ["exe", "cmd", "bat", "com"] {
                    let candidate = candidate.with_extension(extension);
                    if is_executable(&candidate) {
                        return Some(candidate);
                    }
                }
            }
            None
        })
    }

    #[must_use = "the returned value describes the available tooling"]
    pub fn report(&self) -> Value {
        let names = [
            "cmd",
            "powershell",
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

    pub(crate) fn shell_python_violation(
        &self,
        command: &str,
        analysis: Option<&crate::segment::Analysis>,
    ) -> Option<&'static str> {
        if !self.forbid_direct_python {
            return None;
        }
        if let Some(analysis) = analysis {
            return analysis
                .invocations()
                .find_map(|(program, arguments)| self.python_violation(program, arguments));
        }
        // Unrestricted mode may accept constructs outside the checked shell grammar.
        // Preserve the best-effort literal invocation check for that case.
        let argv = shlex::split(command)?;
        let start = argv
            .iter()
            .position(|part| !part.contains('=') || part.starts_with('-'))?;
        self.argv_python_violation(&argv[start..])
    }

    pub(crate) fn argv_python_violation(&self, argv: &[String]) -> Option<&'static str> {
        let (program, arguments) = argv.split_first()?;
        self.python_violation(program, arguments)
    }

    fn python_violation(&self, program: &str, arguments: &[String]) -> Option<&'static str> {
        if !self.forbid_direct_python {
            return None;
        }
        let program = effective_program(program, arguments)?;
        let name = Path::new(program)
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or(program);
        match name {
            "pip" | "pip3" => Some("pip"),
            "python" | "python3" => Some("python"),
            _ => None,
        }
    }
}

fn effective_program<'a>(program: &'a str, argv: &'a [String]) -> Option<&'a str> {
    let mut index = 0;
    if program == "sudo" {
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
        argv.get(index).map(String::as_str)
    } else {
        Some(program)
    }
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

    #[test]
    fn direct_python_policy_catches_plain_and_sudo_invocations() {
        let tooling = Tooling::default();
        let violation = |command: &str| {
            let analysis = crate::segment::analyze(command);
            tooling.shell_python_violation(command, analysis.as_ref().ok())
        };
        assert_eq!(violation("python3 x.py"), Some("python"));
        assert_eq!(violation("sudo -n pip install x"), Some("pip"));
        assert_eq!(violation("sudo -n -u nobody python3 x.py"), Some("python"));
        assert_eq!(violation("uv run python x.py"), None);
        assert_eq!(violation("echo python3"), None);
        assert_eq!(violation("FOO=bar python3 x.py"), Some("python"));
        assert_eq!(violation("> /tmp/out python3 x.py"), Some("python"));
        assert_eq!(
            tooling.argv_python_violation(&["echo".into(), "$(python3 x.py)".into()]),
            None
        );
        assert_eq!(violation("echo \"$(python3 x.py)\""), Some("python"));
        assert_eq!(violation("if true; then pip install x; fi"), Some("pip"));
    }
}
