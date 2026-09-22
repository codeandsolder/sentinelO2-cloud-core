use sentinel0_proto::ConfigSummary;
use serde::Deserialize;
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

#[derive(Debug, Clone)]
pub struct ServiceSpec {
    pub unit: String,
    pub actions: Vec<String>,
    pub requires_sudo: bool,
    pub description: String,
    pub domain: String,
    pub backend: String,
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub exec_strict: bool,
    pub disabled_ops: BTreeSet<String>,
    pub allowed_commands: Vec<String>,
    pub services: BTreeMap<String, ServiceSpec>,
    pub playbooks: BTreeMap<String, yaml_serde::Value>,
    pub hostname_label: Option<String>,
    pub preferred_profile: Option<String>,
    pub exec_timeout_default: u64,
    pub exec_timeout_max: u64,
    pub upload_base: PathBuf,
    pub trusted_fetch_hosts: Vec<String>,
    pub file_url_timeout_seconds: u64,
    pub file_ops_paths: Vec<FileOpsPath>,
    pub file_ops_max_read_bytes: usize,
    pub file_ops_max_list_entries: usize,
    pub file_ops_max_search_results: usize,
    pub local_apis: BTreeMap<String, yaml_serde::Value>,
    pub locations: BTreeMap<String, yaml_serde::Value>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            exec_strict: false,
            disabled_ops: BTreeSet::new(),
            allowed_commands: Vec::new(),
            services: BTreeMap::new(),
            playbooks: BTreeMap::new(),
            hostname_label: None,
            preferred_profile: None,
            exec_timeout_default: 60,
            exec_timeout_max: 600,
            upload_base: PathBuf::from("/var/lib/sentinelx/uploads"),
            trusted_fetch_hosts: Vec::new(),
            file_url_timeout_seconds: 15,
            file_ops_paths: Vec::new(),
            file_ops_max_read_bytes: 65_536,
            file_ops_max_list_entries: 1_000,
            file_ops_max_search_results: 200,
            local_apis: BTreeMap::new(),
            locations: BTreeMap::new(),
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
    #[error("config.yaml contains key {key:?}; did you mean {suggestion:?}?")]
    KnownTypo {
        key: String,
        suggestion: &'static str,
    },
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct RawPolicy {
    agent: RawAgent,
    exec: RawExec,
    allowed_commands: Vec<String>,
    services: BTreeMap<String, RawService>,
    locations: BTreeMap<String, yaml_serde::Value>,
    playbooks: BTreeMap<String, yaml_serde::Value>,
    upload_base: Option<PathBuf>,
    security: RawSecurity,
    file_ops: RawFileOps,
    local_apis: BTreeMap<String, yaml_serde::Value>,
    disabled_ops: Vec<String>,
    exec_strict: bool,
    #[serde(flatten)]
    unknown: BTreeMap<String, yaml_serde::Value>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct RawAgent {
    hostname_label: Option<String>,
    preferred_profile: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct RawExec {
    timeout_default: u64,
    timeout_max: u64,
}

impl Default for RawExec {
    fn default() -> Self {
        Self {
            timeout_default: 60,
            timeout_max: 600,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
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
#[serde(default)]
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
    Detailed {
        path: String,
        #[serde(default)]
        access: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct RawService {
    unit: Option<String>,
    actions: Vec<String>,
    requires_sudo: bool,
    description: String,
    domain: String,
    backend: String,
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
        }
    }
}

impl Policy {
    pub fn from_file(path: &Path) -> Result<Self, PolicyError> {
        if !path.exists() {
            warn!(path = %path.display(), "policy file missing; loading deny-all defaults");
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
        const TYPO_HINTS: &[(&str, &str)] = &[
            ("allow", "allowed_commands"),
            ("allowedCommands", "allowed_commands"),
            ("commands", "allowed_commands"),
            ("service", "services"),
            ("location", "locations"),
            ("playbook", "playbooks"),
            ("hub", "hub_url"),
        ];

        for (key, suggestion) in TYPO_HINTS {
            if raw.unknown.contains_key(*key) {
                return Err(PolicyError::KnownTypo {
                    key: (*key).into(),
                    suggestion,
                });
            }
        }
        if !raw.unknown.is_empty() {
            warn!(
                unknown_keys = ?raw.unknown.keys().collect::<Vec<_>>(),
                "policy contains unknown top-level keys"
            );
        }

        let services = raw
            .services
            .into_iter()
            .map(|(name, service)| {
                let unit = service.unit.unwrap_or_else(|| name.clone());
                (
                    name,
                    ServiceSpec {
                        unit,
                        actions: service.actions,
                        requires_sudo: service.requires_sudo,
                        description: service.description,
                        domain: service.domain,
                        backend: service.backend,
                    },
                )
            })
            .collect();

        let file_ops_paths = if let Some(paths) = raw.file_ops.paths {
            if raw
                .file_ops
                .allowed_read_paths
                .as_ref()
                .is_some_and(|p| !p.is_empty())
            {
                warn!("file_ops has both paths and allowed_read_paths; using paths");
            }
            paths
                .into_iter()
                .filter_map(|entry| match entry {
                    RawFilePath::Path(path) if !path.trim().is_empty() => Some(FileOpsPath {
                        path: PathBuf::from(path),
                        access: FileAccess::Read,
                    }),
                    RawFilePath::Detailed { path, access } if !path.trim().is_empty() => {
                        let access = if access.as_deref() == Some("rw") {
                            FileAccess::ReadWrite
                        } else {
                            FileAccess::Read
                        };
                        Some(FileOpsPath {
                            path: PathBuf::from(path),
                            access,
                        })
                    }
                    _ => {
                        warn!("invalid empty file_ops path entry skipped");
                        None
                    }
                })
                .collect()
        } else {
            raw.file_ops
                .allowed_read_paths
                .unwrap_or_default()
                .into_iter()
                .filter(|path| !path.trim().is_empty())
                .map(|path| FileOpsPath {
                    path: PathBuf::from(path),
                    access: FileAccess::Read,
                })
                .collect()
        };

        let preferred_profile = match raw.agent.preferred_profile.as_deref() {
            Some("compact") => Some("compact".into()),
            Some("full") => Some("full".into()),
            None => None,
            Some(other) => {
                warn!(value = %other, "invalid agent.preferred_profile ignored");
                None
            }
        };

        let upload_base = raw
            .upload_base
            .unwrap_or_else(|| PathBuf::from("/var/lib/sentinelx/uploads"));
        let upload_base = soft_canonicalize(&upload_base).unwrap_or(upload_base);

        let policy = Self {
            exec_strict: raw.exec_strict,
            disabled_ops: raw
                .disabled_ops
                .into_iter()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
                .collect(),
            allowed_commands: raw.allowed_commands,
            services,
            playbooks: raw.playbooks,
            hostname_label: raw.agent.hostname_label,
            preferred_profile,
            exec_timeout_default: raw.exec.timeout_default,
            exec_timeout_max: raw.exec.timeout_max,
            upload_base,
            trusted_fetch_hosts: raw.security.trusted_fetch_hosts,
            file_url_timeout_seconds: raw.security.file_url_timeout_seconds,
            file_ops_paths,
            file_ops_max_read_bytes: raw.file_ops.max_read_bytes,
            file_ops_max_list_entries: raw.file_ops.max_list_entries,
            file_ops_max_search_results: raw.file_ops.max_search_results,
            local_apis: raw.local_apis,
            locations: raw.locations,
        };

        if policy.allowed_commands.is_empty() {
            warn!("policy loaded with no allowed_commands; exec is deny-all");
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
    use tempfile::tempdir;

    fn parse(text: &str) -> Policy {
        let raw: RawPolicy = yaml_serde::from_str(text).unwrap();
        Policy::from_raw(raw).unwrap()
    }

    #[test]
    fn actual_core_fields_parse_with_official_defaults() {
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
upload_base: /var/lib/sentinelx/uploads
"#,
        );
        assert_eq!(policy.exec_timeout_default, 30);
        assert_eq!(policy.exec_timeout_max, 3600);
        assert!(policy.is_command_allowed("git status"));
        assert!(!policy.is_command_allowed("curl example.com"));
        assert!(policy.service_action_allowed("nginx", "restart"));
        assert_eq!(policy.preferred_profile.as_deref(), Some("compact"));
        assert_eq!(policy.file_ops_paths.len(), 2);
    }

    #[test]
    fn known_typo_fails_loudly() {
        let raw: RawPolicy = yaml_serde::from_str("allow: [git]").unwrap();
        assert!(matches!(
            Policy::from_raw(raw),
            Err(PolicyError::KnownTypo { .. })
        ));
    }

    #[test]
    fn legacy_read_paths_stay_read_only() {
        let policy = parse(
            r#"
file_ops:
  allowed_read_paths:
    - /tmp
"#,
        );
        assert_eq!(policy.file_ops_paths[0].access, FileAccess::Read);
    }

    #[test]
    fn path_prefix_check_has_component_boundary() {
        let dir = tempdir().unwrap();
        let allowed = dir.path().join("allowed");
        let sibling = dir.path().join("allowed-not");
        fs::create_dir_all(&allowed).unwrap();
        fs::create_dir_all(&sibling).unwrap();

        let policy = Policy {
            file_ops_paths: vec![FileOpsPath {
                path: allowed.clone(),
                access: FileAccess::ReadWrite,
            }],
            ..Policy::default()
        };

        assert!(
            policy
                .resolve_path(allowed.join("x").to_str().unwrap(), true)
                .is_some()
        );
        assert!(
            policy
                .resolve_path(sibling.to_str().unwrap(), false)
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_is_resolved_before_allowlist_check() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        let allowed = dir.path().join("allowed");
        let outside = dir.path().join("outside");
        fs::create_dir_all(&allowed).unwrap();
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, allowed.join("escape")).unwrap();

        let policy = Policy {
            file_ops_paths: vec![FileOpsPath {
                path: allowed.clone(),
                access: FileAccess::ReadWrite,
            }],
            ..Policy::default()
        };

        assert!(
            policy
                .resolve_path(allowed.join("escape/new.txt").to_str().unwrap(), true)
                .is_none()
        );
    }
}
