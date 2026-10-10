use crate::tooling::Tooling;
use sentinel0_proto::ConfigSummary;
use serde::{Deserialize, Serialize};
use soft_canonicalize::soft_canonicalize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};
use tracing::warn;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileAccess {
    Read,
    ReadWrite,
}

#[derive(Debug, Clone)]
pub struct FileOpsPath {
    pub path: PathBuf,
    pub access: FileAccess,
}

#[derive(Debug, Clone, Serialize)]
pub struct LocationSpec {
    pub path: String,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct ServiceSpec {
    pub unit: String,
    pub actions: Vec<String>,
    pub requires_sudo: bool,
    pub description: String,
    pub domain: String,
    pub backend: String,
    pub user: String,
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub exec_strict: bool,
    pub exec_enforce_allowlist: bool,
    pub disabled_ops: BTreeSet<String>,
    pub allowed_commands: Vec<String>,
    pub services: BTreeMap<String, ServiceSpec>,
    pub playbooks: BTreeMap<String, yaml_serde::Value>,
    pub hostname_label: Option<String>,
    pub preferred_profile: Option<String>,
    pub exec_timeout_default: u64,
    pub exec_timeout_max: u64,
    pub exec_capture_max_bytes: usize,
    pub upload_base: PathBuf,
    pub trusted_fetch_hosts: Vec<String>,
    pub file_url_timeout_seconds: u64,
    pub file_ops_paths: Vec<FileOpsPath>,
    pub file_ops_max_read_bytes: usize,
    pub file_ops_max_list_entries: usize,
    pub file_ops_max_search_results: usize,
    pub local_apis: BTreeMap<String, yaml_serde::Value>,
    pub locations: BTreeMap<String, LocationSpec>,
    pub tooling: Tooling,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            exec_strict: false,
            exec_enforce_allowlist: false,
            disabled_ops: BTreeSet::new(),
            allowed_commands: Vec::new(),
            services: BTreeMap::new(),
            playbooks: BTreeMap::new(),
            hostname_label: None,
            preferred_profile: None,
            exec_timeout_default: 60,
            exec_timeout_max: 600,
            exec_capture_max_bytes: 4 * 1024 * 1024,
            upload_base: PathBuf::from("/var/lib/sentinelx/uploads"),
            trusted_fetch_hosts: Vec::new(),
            file_url_timeout_seconds: 15,
            file_ops_paths: Vec::new(),
            file_ops_max_read_bytes: 65_536,
            file_ops_max_list_entries: 1_000,
            file_ops_max_search_results: 200,
            local_apis: BTreeMap::new(),
            locations: BTreeMap::new(),
            tooling: Tooling::default(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("could not read policy {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("could not parse policy {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: yaml_serde::Error,
    },
    #[error("invalid config value for {field}: {message}")]
    InvalidValue {
        field: &'static str,
        message: String,
    },
}

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct RawPolicy {
    agent: RawAgent,
    exec: RawExec,
    allowed_commands: Vec<String>,
    services: BTreeMap<String, RawService>,
    locations: BTreeMap<String, RawLocation>,
    playbooks: BTreeMap<String, yaml_serde::Value>,
    // Upstream recognizes these top-level compatibility keys, but hub routing
    // comes from CLI/identity and Rust logging is configured by CLI/env.
    // Parse them so valid upstream configs do not produce false unknown-key warnings.
    #[serde(rename = "hub_url")]
    _hub_url: Option<String>,
    #[serde(rename = "log")]
    _log: RawLog,
    upload_base: Option<PathBuf>,
    security: RawSecurity,
    file_ops: RawFileOps,
    local_apis: BTreeMap<String, yaml_serde::Value>,
    tooling: RawTooling,
    disabled_ops: Vec<String>,
    exec_strict: bool,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct RawLog {
    #[serde(rename = "path")]
    _path: Option<PathBuf>,
    #[serde(rename = "level")]
    _level: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawLocation {
    Path(String),
    Detailed(RawLocationDetailed),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLocationDetailed {
    path: String,
    #[serde(default)]
    description: String,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawTooling {
    path: Option<Vec<PathBuf>>,
    executables: BTreeMap<String, PathBuf>,
    uv_python: String,
    forbid_direct_python: bool,
}

impl Default for RawTooling {
    fn default() -> Self {
        Self {
            path: None,
            executables: BTreeMap::new(),
            uv_python: "3".into(),
            forbid_direct_python: true,
        }
    }
}

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct RawAgent {
    hostname_label: Option<String>,
    preferred_profile: Option<String>,
    #[serde(rename = "response_timestamp_interval_seconds")]
    _response_timestamp_interval_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawExec {
    timeout_default: u64,
    timeout_max: u64,
    capture_max_bytes: usize,
    enforce_allowlist: bool,
}

impl Default for RawExec {
    fn default() -> Self {
        Self {
            timeout_default: 60,
            timeout_max: 600,
            capture_max_bytes: 4 * 1024 * 1024,
            enforce_allowlist: false,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawSecurity {
    trusted_fetch_hosts: Vec<String>,
    file_url_timeout_seconds: u64,
}

impl Default for RawSecurity {
    fn default() -> Self {
        Self {
            trusted_fetch_hosts: Vec::new(),
            file_url_timeout_seconds: 15,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawFileOps {
    paths: Option<Vec<RawFilePath>>,
    allowed_read_paths: Option<Vec<String>>,
    max_read_bytes: usize,
    max_list_entries: usize,
    max_search_results: usize,
}

impl Default for RawFileOps {
    fn default() -> Self {
        Self {
            paths: None,
            allowed_read_paths: None,
            max_read_bytes: 65_536,
            max_list_entries: 1_000,
            max_search_results: 200,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawFilePath {
    Path(String),
    Detailed(RawFilePathDetailed),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFilePathDetailed {
    path: String,
    #[serde(default)]
    access: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawService {
    unit: Option<String>,
    actions: Vec<String>,
    requires_sudo: bool,
    description: String,
    domain: String,
    backend: String,
    user: String,
}

impl Default for RawService {
    fn default() -> Self {
        Self {
            unit: None,
            actions: Vec::new(),
            requires_sudo: true,
            description: String::new(),
            domain: "system".into(),
            backend: "service".into(),
            user: String::new(),
        }
    }
}

fn validate_raw_policy(raw: &RawPolicy) -> Result<(), PolicyError> {
    const PLAYBOOK_KEYS: &[&str] = &[
        "description",
        "commands",
        "when",
        "steps",
        "requires",
        "notes",
    ];
    if raw.exec.timeout_default == 0 {
        return Err(PolicyError::InvalidValue {
            field: "exec.timeout_default",
            message: "must be greater than zero".into(),
        });
    }
    if raw.exec.timeout_max < raw.exec.timeout_default {
        return Err(PolicyError::InvalidValue {
            field: "exec.timeout_max",
            message: format!(
                "must be >= exec.timeout_default ({})",
                raw.exec.timeout_default
            ),
        });
    }
    if raw.exec.capture_max_bytes < 64 * 1024 {
        return Err(PolicyError::InvalidValue {
            field: "exec.capture_max_bytes",
            message: "must be at least 65536 bytes".into(),
        });
    }
    if raw.security.file_url_timeout_seconds == 0 {
        return Err(PolicyError::InvalidValue {
            field: "security.file_url_timeout_seconds",
            message: "must be greater than zero".into(),
        });
    }
    for (field, value) in [
        ("file_ops.max_read_bytes", raw.file_ops.max_read_bytes),
        ("file_ops.max_list_entries", raw.file_ops.max_list_entries),
        (
            "file_ops.max_search_results",
            raw.file_ops.max_search_results,
        ),
    ] {
        if value == 0 {
            return Err(PolicyError::InvalidValue {
                field,
                message: "must be greater than zero".into(),
            });
        }
    }
    for op in &raw.disabled_ops {
        let op = op.trim();
        if !op.is_empty()
            && !sentinel0_proto::Op::ALL
                .iter()
                .any(|known| known.as_str() == op)
        {
            return Err(PolicyError::InvalidValue {
                field: "disabled_ops",
                message: format!("unknown operation {op:?}"),
            });
        }
    }
    crate::local_api::validate_config(&raw.local_apis).map_err(|message| {
        PolicyError::InvalidValue {
            field: "local_apis",
            message,
        }
    })?;
    for (name, value) in &raw.playbooks {
        if !matches!(value, yaml_serde::Value::Mapping(_)) {
            return Err(PolicyError::InvalidValue {
                field: "playbooks",
                message: format!("playbook {name:?} must be an object"),
            });
        }
        let json = serde_json::to_value(value).map_err(|error| PolicyError::InvalidValue {
            field: "playbooks",
            message: format!("playbook {name:?} is not JSON-representable: {error}"),
        })?;
        let object = json.as_object().ok_or_else(|| PolicyError::InvalidValue {
            field: "playbooks",
            message: format!("playbook {name:?} must be an object"),
        })?;
        if let Some(key) = object
            .keys()
            .find(|key| !PLAYBOOK_KEYS.contains(&key.as_str()))
        {
            return Err(PolicyError::InvalidValue {
                field: "playbooks",
                message: format!("playbook {name:?} contains unknown key {key:?}"),
            });
        }
    }
    Ok(())
}

fn parse_locations(
    raw_locations: BTreeMap<String, RawLocation>,
) -> Result<BTreeMap<String, LocationSpec>, PolicyError> {
    let mut locations = BTreeMap::new();
    for (name, location) in raw_locations {
        let (path, description) = match location {
            RawLocation::Path(path) => (path, String::new()),
            RawLocation::Detailed(RawLocationDetailed { path, description }) => (path, description),
        };
        if path.trim().is_empty() {
            return Err(PolicyError::InvalidValue {
                field: "locations",
                message: format!("location {name:?} has an empty path"),
            });
        }
        locations.insert(name, LocationSpec { path, description });
    }
    Ok(locations)
}

fn valid_service_user(user: &str) -> bool {
    let bytes = user.as_bytes();
    if bytes.is_empty() || bytes.len() > 32 {
        return false;
    }
    let first = bytes[0];
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'.' | b'-'))
}

fn parse_services(raw_services: BTreeMap<String, RawService>) -> BTreeMap<String, ServiceSpec> {
    raw_services
        .into_iter()
        .filter_map(|(name, service)| {
            let user = service.user.trim().to_owned();
            if !user.is_empty() && !valid_service_user(&user) {
                warn!(service = %name, user = %user, "service has invalid systemd user; skipping it");
                return None;
            }
            let unit = service.unit.unwrap_or_else(|| name.clone());
            Some((
                name,
                ServiceSpec {
                    unit,
                    actions: service.actions,
                    requires_sudo: service.requires_sudo,
                    description: service.description,
                    domain: service.domain,
                    backend: service.backend,
                    user,
                },
            ))
        })
        .collect()
}

fn parse_file_ops_paths(
    paths: Option<Vec<RawFilePath>>,
    allowed_read_paths: Option<Vec<String>>,
) -> Result<Vec<FileOpsPath>, PolicyError> {
    if let Some(paths) = paths {
        if allowed_read_paths
            .as_ref()
            .is_some_and(|paths| !paths.is_empty())
        {
            warn!("file_ops has both paths and allowed_read_paths; using paths");
        }
        paths
            .into_iter()
            .map(|entry| {
                let (path, access) = match entry {
                    RawFilePath::Path(path) => (path, FileAccess::Read),
                    RawFilePath::Detailed(RawFilePathDetailed { path, access }) => {
                        let access = match access.as_deref().map(str::trim) {
                            None | Some("" | "r") => FileAccess::Read,
                            Some("rw") => FileAccess::ReadWrite,
                            Some(other) => {
                                return Err(PolicyError::InvalidValue {
                                    field: "file_ops.paths[].access",
                                    message: format!("must be \"r\" or \"rw\", got {other:?}"),
                                });
                            }
                        };
                        (path, access)
                    }
                };
                if path.trim().is_empty() {
                    return Err(PolicyError::InvalidValue {
                        field: "file_ops.paths[].path",
                        message: "must not be empty".into(),
                    });
                }
                Ok(FileOpsPath {
                    path: PathBuf::from(path),
                    access,
                })
            })
            .collect()
    } else {
        allowed_read_paths
            .unwrap_or_default()
            .into_iter()
            .map(|path| {
                if path.trim().is_empty() {
                    return Err(PolicyError::InvalidValue {
                        field: "file_ops.allowed_read_paths[]",
                        message: "must not be empty".into(),
                    });
                }
                Ok(FileOpsPath {
                    path: PathBuf::from(path),
                    access: FileAccess::Read,
                })
            })
            .collect()
    }
}

fn parse_preferred_profile(value: Option<&String>) -> Result<Option<String>, PolicyError> {
    match value.map(String::as_str) {
        Some("compact") => Ok(Some("compact".into())),
        Some("full") => Ok(Some("full".into())),
        None => Ok(None),
        Some(other) => Err(PolicyError::InvalidValue {
            field: "agent.preferred_profile",
            message: format!("must be \"compact\" or \"full\", got {other:?}"),
        }),
    }
}

fn parse_tooling(raw: RawTooling) -> Tooling {
    Tooling {
        search_path: raw.path.unwrap_or_else(|| Tooling::default().search_path),
        executables: raw.executables,
        uv_python: if raw.uv_python.trim().is_empty() {
            "3".into()
        } else {
            raw.uv_python
        },
        forbid_direct_python: raw.forbid_direct_python,
    }
}

impl Policy {
    /// # Errors
    /// Returns an error when the policy file cannot be read, parsed, or validated.
    pub fn from_file(path: &Path) -> Result<Self, PolicyError> {
        if !path.exists() {
            warn!(path = %path.display(), "policy file missing; loading built-in defaults");
            return Ok(Self::default());
        }

        let text = fs::read_to_string(path).map_err(|source| PolicyError::Read {
            path: path.into(),
            source,
        })?;
        let raw: RawPolicy = yaml_serde::from_str(&text).map_err(|source| PolicyError::Parse {
            path: path.into(),
            source,
        })?;
        Self::from_raw(raw)
    }

    fn from_raw(raw: RawPolicy) -> Result<Self, PolicyError> {
        validate_raw_policy(&raw)?;

        let RawPolicy {
            agent,
            exec,
            allowed_commands,
            services: raw_services,
            locations: raw_locations,
            playbooks,
            _hub_url: _,
            _log: _,
            upload_base,
            security,
            file_ops,
            local_apis,
            tooling,
            disabled_ops,
            exec_strict,
        } = raw;
        let RawAgent {
            hostname_label,
            preferred_profile,
            _response_timestamp_interval_seconds: _,
        } = agent;
        let RawSecurity {
            trusted_fetch_hosts,
            file_url_timeout_seconds,
        } = security;
        let RawFileOps {
            paths,
            allowed_read_paths,
            max_read_bytes,
            max_list_entries,
            max_search_results,
        } = file_ops;

        let locations = parse_locations(raw_locations)?;
        let services = parse_services(raw_services);
        let file_ops_paths = parse_file_ops_paths(paths, allowed_read_paths)?;
        let preferred_profile = parse_preferred_profile(preferred_profile.as_ref())?;
        let upload_base =
            upload_base.unwrap_or_else(|| PathBuf::from("/var/lib/sentinelx/uploads"));
        let upload_base = soft_canonicalize(&upload_base).unwrap_or(upload_base);
        let tooling = parse_tooling(tooling);

        let policy = Self {
            exec_strict,
            exec_enforce_allowlist: exec.enforce_allowlist || exec_strict,
            disabled_ops: disabled_ops
                .into_iter()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
                .collect(),
            allowed_commands,
            services,
            playbooks,
            hostname_label,
            preferred_profile,
            exec_timeout_default: exec.timeout_default,
            exec_timeout_max: exec.timeout_max,
            exec_capture_max_bytes: exec.capture_max_bytes,
            upload_base,
            trusted_fetch_hosts,
            file_url_timeout_seconds,
            file_ops_paths,
            file_ops_max_read_bytes: max_read_bytes,
            file_ops_max_list_entries: max_list_entries,
            file_ops_max_search_results: max_search_results,
            local_apis,
            locations,
            tooling,
        };

        if policy.exec_enforce_allowlist && policy.allowed_commands.is_empty() {
            warn!(
                "exec allowlist enforcement is enabled with no allowed_commands; exec is deny-all"
            );
        }
        Ok(policy)
    }

    #[must_use]
    pub fn is_command_allowed(&self, command: &str) -> bool {
        let command = command.trim();
        !command.is_empty()
            && self
                .allowed_commands
                .iter()
                .any(|allowed| command.starts_with(allowed))
    }

    #[must_use]
    pub fn service_action_allowed(&self, service: &str, action: &str) -> bool {
        self.services
            .get(service)
            .is_some_and(|spec| spec.actions.iter().any(|allowed| allowed == action))
    }

    #[must_use]
    pub fn resolve_path(&self, path: &str, need_write: bool) -> Option<PathBuf> {
        if path.is_empty() || self.file_ops_paths.is_empty() {
            return None;
        }
        let candidate = soft_canonicalize(path).ok()?;

        self.file_ops_paths.iter().find_map(|entry| {
            if need_write && entry.access != FileAccess::ReadWrite {
                return None;
            }
            let allowed = soft_canonicalize(&entry.path).ok()?;
            if candidate == allowed || candidate.starts_with(&allowed) {
                Some(candidate.clone())
            } else {
                None
            }
        })
    }

    /// Resolve and authorize a path without following the final directory
    /// entry. This is for operations that manipulate the entry itself
    /// (move/copy/delete), so a symlink under an allowed directory remains the
    /// symlink rather than turning into its possibly-outside target.
    #[must_use]
    pub fn resolve_path_no_follow_leaf(&self, path: &str, need_write: bool) -> Option<PathBuf> {
        if path.is_empty() || self.file_ops_paths.is_empty() {
            return None;
        }
        let raw = Path::new(path);
        let leaf = raw.file_name()?;
        if leaf == "." || leaf == ".." {
            return None;
        }
        let parent = raw.parent().unwrap_or_else(|| Path::new("."));
        let parent = soft_canonicalize(parent).ok()?;
        let candidate = parent.join(leaf);

        self.file_ops_paths.iter().find_map(|entry| {
            if need_write && entry.access != FileAccess::ReadWrite {
                return None;
            }
            let allowed = soft_canonicalize(&entry.path).ok()?;
            if candidate == allowed || candidate.starts_with(&allowed) {
                Some(candidate.clone())
            } else {
                None
            }
        })
    }

    #[must_use]
    pub fn config_summary(&self) -> ConfigSummary {
        ConfigSummary {
            allowed_command_count: Some(self.allowed_commands.len() as u64),
            file_ops_path_count: Some(self.file_ops_paths.len() as u64),
            file_ops_rw_count: Some(
                self.file_ops_paths
                    .iter()
                    .filter(|entry| entry.access == FileAccess::ReadWrite)
                    .count() as u64,
            ),
            service_count: Some(self.services.len() as u64),
            playbook_count: Some(self.playbooks.len() as u64),
            trusted_fetch_host_count: Some(self.trusted_fetch_hosts.len() as u64),
            exec_timeout_default: Some(self.exec_timeout_default),
            exec_timeout_max: Some(self.exec_timeout_max),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TestResult, TestValue as _};
    use tempfile::tempdir;

    fn parse(text: &str) -> TestResult<Policy> {
        let raw: RawPolicy = yaml_serde::from_str(text).test_value()?;
        Policy::from_raw(raw).test_value()
    }

    #[test]
    fn actual_core_fields_parse_with_official_defaults() -> TestResult {
        let policy = parse(
            r#"
allowed_commands: [git, "sudo systemctl"]
exec:
  timeout_default: 30
  timeout_max: 3600
services:
  nginx:
    actions: [status, restart]
file_ops:
  paths:
    - path: /etc
      access: r
    - path: /srv/scratch
      access: rw
security:
  trusted_fetch_hosts: [drop.pensa.ar]
agent:
  preferred_profile: compact
  response_timestamp_interval_seconds: 75
hub_url: https://ignored.example
log:
  level: INFO
upload_base: /var/lib/sentinelx/uploads
"#,
        )?;
        assert_eq!(policy.exec_timeout_default, 30);
        assert_eq!(policy.exec_timeout_max, 3600);
        assert!(!policy.exec_enforce_allowlist);
        assert!(policy.is_command_allowed("git status"));
        assert!(!policy.is_command_allowed("curl example.com"));
        assert!(policy.service_action_allowed("nginx", "restart"));
        assert_eq!(policy.preferred_profile.as_deref(), Some("compact"));
        assert_eq!(policy.file_ops_paths.len(), 2);

        Ok(())
    }

    #[test]
    fn systemd_user_services_are_parsed_and_invalid_users_are_skipped() -> TestResult {
        let policy = parse(
            r#"
services:
  good:
    actions: [status, restart]
    user: alice_2.test-user
  bad:
    actions: [status]
    user: "bad user;root"
"#,
        )?;
        assert_eq!(policy.services["good"].user, "alice_2.test-user");
        assert!(!policy.services.contains_key("bad"));
        Ok(())
    }

    #[test]
    fn allowlist_enforcement_is_opt_in_but_legacy_strict_still_enforces() -> TestResult {
        let policy = parse(
            r"
allowed_commands: [git]
",
        )?;
        assert!(!policy.exec_enforce_allowlist);

        let policy = parse(
            r"
allowed_commands: [git]
exec:
  enforce_allowlist: true
",
        )?;
        assert!(policy.exec_enforce_allowlist);

        let policy = parse(
            r"
allowed_commands: [git]
exec_strict: true
",
        )?;
        assert!(policy.exec_enforce_allowlist);

        Ok(())
    }

    #[test]
    fn unknown_top_level_keys_fail_at_parse_boundary() {
        for text in [
            "allow: [git]\n",
            "allowedCommands: [git]\n",
            "commands: [git]\n",
            "service: {}\n",
            "location: {}\n",
            "playbook: {}\n",
            "hub: https://example.invalid\n",
            "future_magic: true\n",
        ] {
            assert!(
                yaml_serde::from_str::<RawPolicy>(text).is_err(),
                "unknown top-level key unexpectedly parsed: {text:?}"
            );
        }
    }

    #[test]
    fn invalid_file_access_fails_loudly() -> TestResult {
        let raw: RawPolicy = yaml_serde::from_str(
            "file_ops:
  paths:
    - path: /tmp
      access: wr
",
        )
        .test_value()?;
        assert!(matches!(
            Policy::from_raw(raw),
            Err(PolicyError::InvalidValue {
                field: "file_ops.paths[].access",
                ..
            })
        ));

        Ok(())
    }

    #[test]
    fn malformed_local_api_fails_config_load() -> TestResult {
        let raw: RawPolicy = yaml_serde::from_str(
            "local_apis:
  x:
    transport: stdio
    protocol: jsonrpc
    path: /tmp/x
    actions:
      ping: { method: ping }
",
        )
        .test_value()?;
        assert!(matches!(
            Policy::from_raw(raw),
            Err(PolicyError::InvalidValue {
                field: "local_apis",
                ..
            })
        ));

        Ok(())
    }

    #[test]
    fn impossible_exec_limits_fail_loudly() -> TestResult {
        let raw: RawPolicy = yaml_serde::from_str(
            "exec:
  timeout_default: 60
  timeout_max: 10
",
        )
        .test_value()?;
        assert!(matches!(
            Policy::from_raw(raw),
            Err(PolicyError::InvalidValue {
                field: "exec.timeout_max",
                ..
            })
        ));

        Ok(())
    }

    #[test]
    fn compatibility_blocks_are_strictly_typed() {
        for text in [
            "log:
  path: /tmp/x.log
  levle: INFO
",
            "locations:
  x:
    path: /tmp
    descrption: nope
",
            "playbooks:
  broken: [one, two]
",
            "playbooks:
  broken:
    description: x
    stepps: []
",
        ] {
            let parsed = yaml_serde::from_str::<RawPolicy>(text);
            if let Ok(raw) = parsed {
                assert!(
                    Policy::from_raw(raw).is_err(),
                    "invalid compatibility block unexpectedly loaded: {text:?}"
                );
            }
        }
    }

    #[test]
    fn nested_config_typos_fail_at_parse_boundary() {
        for text in [
            "exec:\n  timeout_defualt: 30\n",
            "security:\n  file_url_timeout_second: 15\n",
            "file_ops:\n  max_read_byte: 123\n",
            "services:\n  nginx:\n    action: [status]\n",
            "agent:\n  prefered_profile: compact\n",
            "tooling:\n  uv_pythn: 3\n",
            "file_ops:\n  paths:\n    - path: /tmp\n      acces: rw\n",
        ] {
            assert!(
                yaml_serde::from_str::<RawPolicy>(text).is_err(),
                "nested typo unexpectedly parsed: {text:?}"
            );
        }
    }

    #[test]
    fn legacy_read_paths_stay_read_only() -> TestResult {
        let policy = parse(
            r"
file_ops:
  allowed_read_paths:
    - /tmp
",
        )?;
        assert_eq!(policy.file_ops_paths[0].access, FileAccess::Read);

        Ok(())
    }

    #[test]
    fn path_prefix_check_has_component_boundary() -> TestResult {
        let dir = tempdir().test_value()?;
        let allowed = dir.path().join("allowed");
        let sibling = dir.path().join("allowed-not");
        fs::create_dir_all(&allowed).test_value()?;
        fs::create_dir_all(&sibling).test_value()?;

        let policy = Policy {
            file_ops_paths: vec![FileOpsPath {
                path: allowed.clone(),
                access: FileAccess::ReadWrite,
            }],
            ..Policy::default()
        };

        assert!(
            policy
                .resolve_path(allowed.join("x").to_str().test_value()?, true)
                .is_some()
        );
        assert!(
            policy
                .resolve_path(sibling.to_str().test_value()?, false)
                .is_none()
        );

        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_is_resolved_before_allowlist_check() -> TestResult {
        use std::os::unix::fs::symlink;

        let dir = tempdir().test_value()?;
        let allowed = dir.path().join("allowed");
        let outside = dir.path().join("outside");
        fs::create_dir_all(&allowed).test_value()?;
        fs::create_dir_all(&outside).test_value()?;
        symlink(&outside, allowed.join("escape")).test_value()?;

        let policy = Policy {
            file_ops_paths: vec![FileOpsPath {
                path: allowed.clone(),
                access: FileAccess::ReadWrite,
            }],
            ..Policy::default()
        };

        assert!(
            policy
                .resolve_path(allowed.join("escape/new.txt").to_str().test_value()?, true)
                .is_none()
        );
        Ok(())
    }
}
