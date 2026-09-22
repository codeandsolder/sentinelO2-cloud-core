use crate::{
    Dispatcher, edit, fileops,
    handler_error::{HandlerError, HandlerResult, require_str},
    host,
    policy::Policy,
    segment, shell,
};
use chrono::Utc;
use sentinel0_proto::{Message, Op};
use serde_json::{Map, Value, json};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

pub const IMPLEMENTED_OPS: &[Op] = &[
    Op::Ping,
    Op::Capabilities,
    Op::Help,
    Op::State,
    Op::Exec,
    Op::ScriptRun,
    Op::Service,
    Op::Restart,
    Op::Edit,
    Op::EditUploadInit,
    Op::EditUploadFile,
    Op::EditUploadComplete,
    Op::Git,
    Op::Read,
    Op::List,
    Op::Search,
    Op::Move,
    Op::Copy,
    Op::Delete,
    Op::Chmod,
    Op::Chown,
    Op::UploadInit,
    Op::UploadChunk,
    Op::UploadComplete,
    Op::UploadFile,
    Op::FileExportInit,
    Op::FileExportChunk,
    Op::FileExportComplete,
    Op::ProjectSnapshot,
    Op::ReadAudit,
    Op::LocalApi,
];

#[derive(Clone)]
pub struct CoreDispatcher {
    policy: Arc<Policy>,
    config_path: PathBuf,
    agent_version: String,
}

impl CoreDispatcher {
    pub fn new(policy: Policy, config_path: PathBuf, agent_version: impl Into<String>) -> Self {
        Self {
            policy: Arc::new(policy),
            config_path,
            agent_version: agent_version.into(),
        }
    }

    #[must_use]
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    #[must_use]
    pub fn capabilities(&self) -> Vec<String> {
        IMPLEMENTED_OPS
            .iter()
            .filter(|op| self.op_enabled(**op))
            .map(|op| op.as_str().to_owned())
            .chain(std::iter::once("opaque_ref".into()))
            .collect()
    }

    fn op_enabled(&self, op: Op) -> bool {
        if op == Op::LocalApi && !crate::local_api::has_usable_endpoints(&self.policy) {
            return false;
        }
        matches!(op, Op::Ping | Op::Capabilities | Op::State | Op::Help)
            || !self.policy.disabled_ops.contains(op.as_str())
    }

    fn response(id: &str, result: HandlerResult) -> Message {
        match result {
            Ok(result) => Message::Response {
                id: id.into(),
                ok: true,
                result: Some(result),
                error: None,
            },
            Err(error) => Message::Response {
                id: id.into(),
                ok: false,
                result: None,
                error: Some(error.response_error()),
            },
        }
    }

    fn ping(&self) -> HandlerResult {
        Ok(BTreeMap::from([
            ("pong".into(), Value::Bool(true)),
            (
                "agent_version".into(),
                Value::String(self.agent_version.clone()),
            ),
        ]))
    }

    fn state(&self) -> HandlerResult {
        Ok(BTreeMap::from([
            ("hostname".into(), Value::String(host::hostname())),
            (
                "kernel".into(),
                host::kernel().map(Value::String).unwrap_or(Value::Null),
            ),
            ("arch".into(), Value::String(std::env::consts::ARCH.into())),
            (
                "platform".into(),
                Value::String(format!(
                    "{} {} {}",
                    host::distro().unwrap_or_else(|| "linux".into()),
                    host::kernel().unwrap_or_default(),
                    std::env::consts::ARCH
                )),
            ),
            ("now_utc".into(), Value::String(Utc::now().to_rfc3339())),
            (
                "uptime_seconds".into(),
                host::uptime_seconds()
                    .map(Value::from)
                    .unwrap_or(Value::Null),
            ),
            (
                "loadavg".into(),
                host::loadavg()
                    .map(|values| Value::Array(values.into_iter().map(Value::from).collect()))
                    .unwrap_or(Value::Null),
            ),
        ]))
    }

    fn no_new_privileges() -> bool {
        #[cfg(target_os = "linux")]
        {
            if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                return status.lines().any(|line| {
                    line.strip_prefix("NoNewPrivs:")
                        .and_then(|rest| rest.split_whitespace().next())
                        == Some("1")
                });
            }
        }
        false
    }

    fn unusable_commands_for(allowed_commands: &[String], no_new_privileges: bool) -> Value {
        if !no_new_privileges {
            return json!({});
        }

        let blocked = allowed_commands
            .iter()
            .filter(|command| {
                let mut parts = command.split_whitespace();
                let Some(first) = parts.next() else {
                    return false;
                };
                command.as_str() == "sudo"
                    || command.starts_with("sudo ")
                    || first.contains("/sudo")
            })
            .cloned()
            .collect::<Vec<_>>();

        if blocked.is_empty() {
            json!({})
        } else {
            json!({
                "commands": blocked,
                "reason": "no_new_privileges",
                "detail": concat!(
                    "This agent runs with NoNewPrivileges set, so sudo can never ",
                    "elevate regardless of sudoers. These entries are in the allowlist ",
                    "but will always fail. Either run the privileged step through a ",
                    "service action, or have the operator install the agent without ",
                    "that hardening -- not recommended -- or wrap the work in a ",
                    "setuid-free helper the agent can call directly."
                ),
            })
        }
    }

    fn capabilities_result(&self, payload: &Map<String, Value>) -> HandlerResult {
        let detail = crate::progressive_help::capabilities_detail(payload)?;
        let mut ops = self
            .capabilities()
            .into_iter()
            .filter(|name| name != "opaque_ref")
            .collect::<Vec<_>>();
        ops.sort();

        let services = self
            .policy
            .services
            .iter()
            .map(|(name, spec)| {
                (
                    name.clone(),
                    json!({
                        "unit": spec.unit,
                        "backend": spec.backend,
                        "actions": spec.actions,
                        "requires_sudo": spec.requires_sudo,
                        "description": spec.description,
                    }),
                )
            })
            .collect::<Map<String, Value>>();

        let paths = self
            .policy
            .file_ops_paths
            .iter()
            .map(|entry| {
                json!({
                    "path": entry.path.display().to_string(),
                    "access": match entry.access {
                        crate::policy::FileAccess::Read => "r",
                        crate::policy::FileAccess::ReadWrite => "rw",
                    },
                })
            })
            .collect::<Vec<_>>();
        let readable = self
            .policy
            .file_ops_paths
            .iter()
            .map(|entry| Value::String(entry.path.display().to_string()))
            .collect::<Vec<_>>();
        let writable = self
            .policy
            .file_ops_paths
            .iter()
            .filter(|entry| entry.access == crate::policy::FileAccess::ReadWrite)
            .map(|entry| Value::String(entry.path.display().to_string()))
            .collect::<Vec<_>>();

        if detail == "summary" {
            let location_count = self.policy.locations.len()
                + usize::from(!self.policy.locations.contains_key("config"));
            return Ok(BTreeMap::from([
                ("agent".into(), Value::String("sentinelx-cloud-core".into())),
                ("version".into(), Value::String(self.agent_version.clone())),
                (
                    "host".into(),
                    json!({
                        "hostname": host::hostname(),
                        "label": self.policy.hostname_label,
                        "kernel": host::kernel(),
                        "arch": std::env::consts::ARCH,
                    }),
                ),
                (
                    "ops_supported".into(),
                    Value::Array(ops.into_iter().map(Value::String).collect()),
                ),
                (
                    "limits".into(),
                    json!({
                        "exec_timeout_default": self.policy.exec_timeout_default,
                        "exec_timeout_max": self.policy.exec_timeout_max,
                    }),
                ),
                (
                    "upload_base".into(),
                    Value::String(self.policy.upload_base.display().to_string()),
                ),
                (
                    "file_ops_limits".into(),
                    json!({
                        "max_read_bytes": self.policy.file_ops_max_read_bytes,
                        "max_list_entries": self.policy.file_ops_max_list_entries,
                        "max_search_results": self.policy.file_ops_max_search_results,
                    }),
                ),
                (
                    "policy_summary".into(),
                    json!({
                        "allowed_commands": self.policy.allowed_commands.len(),
                        "services": self.policy.services.len(),
                        "locations": location_count,
                        "playbooks": self.policy.playbooks.len(),
                        "file_ops_paths": self.policy.file_ops_paths.len(),
                        "writable_paths": self
                            .policy
                            .file_ops_paths
                            .iter()
                            .filter(|entry| entry.access == crate::policy::FileAccess::ReadWrite)
                            .count(),
                        "trusted_fetch_hosts": self.policy.trusted_fetch_hosts.len(),
                    }),
                ),
                (
                    "query_contract".into(),
                    json!({
                        "help": ["topic", "path", "playbook", "offset", "limit"],
                        "capabilities_detail": ["summary", "full"],
                        "max_page_limit": 100,
                        "legacy_empty_payload": "full",
                    }),
                ),
                (
                    "next".into(),
                    json!({
                        "help_index": {
                            "backend_operation": "help",
                            "payload": {"topic": "index"},
                        },
                        "playbook": {
                            "backend_operation": "help",
                            "payload": {"playbook": "<name>"},
                        },
                        "full_capabilities": {
                            "backend_operation": "capabilities",
                            "payload": {"detail": "full"},
                        },
                    }),
                ),
            ]));
        }

        let playbooks = self
            .policy
            .playbooks
            .iter()
            .filter_map(|(name, value)| {
                serde_json::to_value(value)
                    .ok()
                    .map(|value| (name.clone(), value))
            })
            .collect::<Map<String, Value>>();

        let mut locations = self
            .policy
            .locations
            .iter()
            .filter_map(|(name, value)| {
                serde_json::to_value(value)
                    .ok()
                    .map(|value| (name.clone(), value))
            })
            .collect::<Map<String, Value>>();
        locations.entry("config").or_insert_with(|| {
            json!({
                "path": self.config_path.display().to_string(),
                "description": "The agent's active config.yaml.",
            })
        });

        Ok(BTreeMap::from([
            ("agent".into(), Value::String("sentinelx-cloud-core".into())),
            ("version".into(), Value::String(self.agent_version.clone())),
            (
                "host".into(),
                json!({
                    "hostname": host::hostname(),
                    "label": self.policy.hostname_label,
                    "kernel": host::kernel(),
                    "arch": std::env::consts::ARCH,
                }),
            ),
            (
                "ops_supported".into(),
                Value::Array(ops.into_iter().map(Value::String).collect()),
            ),
            (
                "allowed_commands".into(),
                Value::Array(
                    self.policy
                        .allowed_commands
                        .iter()
                        .cloned()
                        .map(Value::String)
                        .collect(),
                ),
            ),
            (
                "disabled_ops".into(),
                Value::Array(
                    self.policy
                        .disabled_ops
                        .iter()
                        .cloned()
                        .map(Value::String)
                        .collect(),
                ),
            ),
            ("exec_strict".into(), Value::Bool(self.policy.exec_strict)),
            (
                "unusable_commands".into(),
                Self::unusable_commands_for(
                    &self.policy.allowed_commands,
                    Self::no_new_privileges(),
                ),
            ),
            ("services".into(), Value::Object(services)),
            ("locations".into(), Value::Object(locations)),
            ("playbooks".into(), Value::Object(playbooks)),
            (
                "limits".into(),
                json!({
                    "exec_timeout_default": self.policy.exec_timeout_default,
                    "exec_timeout_max": self.policy.exec_timeout_max,
                }),
            ),
            (
                "fetch_policy".into(),
                json!({
                    "trusted_fetch_hosts": self.policy.trusted_fetch_hosts,
                    "file_url_timeout_seconds": self.policy.file_url_timeout_seconds,
                    "scheme_allowed": ["https"],
                    "follow_redirects": false,
                }),
            ),
            (
                "file_ops".into(),
                json!({
                    "paths": paths,
                    "allowed_read_paths": readable,
                    "writable_paths": writable,
                    "max_read_bytes": self.policy.file_ops_max_read_bytes,
                    "max_list_entries": self.policy.file_ops_max_list_entries,
                    "max_search_results": self.policy.file_ops_max_search_results,
                }),
            ),
            (
                "upload_base".into(),
                Value::String(self.policy.upload_base.display().to_string()),
            ),
            (
                "config_path".into(),
                Value::String(self.config_path.display().to_string()),
            ),
        ]))
    }

    fn help_ops_live(&self, ops: &[Op]) -> bool {
        ops.iter()
            .all(|op| !self.policy.disabled_ops.contains(op.as_str()))
    }

    fn help_navigation(&self) -> Map<String, Value> {
        let has_read_paths = !self.policy.file_ops_paths.is_empty();
        let has_writable = self
            .policy
            .file_ops_paths
            .iter()
            .any(|entry| entry.access == crate::policy::FileAccess::ReadWrite);
        let has_commands = !self.policy.allowed_commands.is_empty();
        let has_services = !self.policy.services.is_empty();

        let mut navigation = Map::from_iter([
            (
                "capabilities".into(),
                Value::String(
                    "full policy: allowed paths (r/rw), commands, services, playbooks, limits"
                        .into(),
                ),
            ),
            (
                "state".into(),
                Value::String("live host status (hostname, kernel, uptime, load)".into()),
            ),
        ]);

        if self.help_ops_live(&[Op::Read, Op::List, Op::Search]) && has_read_paths {
            navigation.insert(
                "read / list / search".into(),
                Value::String("inspect files under allowed paths".into()),
            );
        }
        if self.help_ops_live(&[Op::Edit]) {
            navigation.insert(
                "edit".into(),
                Value::String(
                    "structured file edits; sudo=true for rw-gated or privileged writes".into(),
                ),
            );
        }
        if self.help_ops_live(&[Op::Move, Op::Copy, Op::Delete, Op::Chmod, Op::Chown])
            && has_writable
        {
            navigation.insert(
                "move / copy / delete / chmod / chown".into(),
                Value::String("mutate files under rw paths (never sudo)".into()),
            );
        }
        if self.help_ops_live(&[Op::Exec]) && has_commands {
            navigation.insert(
                "exec".into(),
                Value::String("run ONE allowlisted command (no pipes or redirects)".into()),
            );
        }
        if self.help_ops_live(&[Op::ScriptRun]) {
            navigation.insert(
                "script_run".into(),
                Value::String("run a multi-step bash/python script for complex tasks".into()),
            );
        }
        if self.help_ops_live(&[Op::Service, Op::Restart]) && has_services {
            navigation.insert(
                "service / restart".into(),
                Value::String("manage allowlisted services".into()),
            );
        }
        if self.help_ops_live(&[Op::UploadFile, Op::UploadInit]) {
            navigation.insert(
                "upload_file / upload_init+chunk+complete".into(),
                Value::String("get files onto the host".into()),
            );
        }
        if self.help_ops_live(&[Op::ReadAudit]) {
            navigation.insert(
                "read_audit".into(),
                Value::String("review this host's own recent operation log".into()),
            );
        }
        if !self.policy.playbooks.is_empty() {
            navigation.insert(
                "playbooks".into(),
                Value::String("guided multi-step recipes (see 'playbooks' in capabilities)".into()),
            );
        }
        navigation
    }

    fn help_extending_access(&self) -> Map<String, Value> {
        let has_writable = self
            .policy
            .file_ops_paths
            .iter()
            .any(|entry| entry.access == crate::policy::FileAccess::ReadWrite);
        let remote_edit_possible = self.help_ops_live(&[Op::Edit]) && has_writable;

        Map::from_iter([
            (
                "note".into(),
                Value::String(if remote_edit_possible {
                    "These changes need the operator's approval; apply them via SentinelX where a config path is available, or on the host.".into()
                } else {
                    "This host cannot edit its own config remotely: edit is disabled or no writable path is configured. The steps below must be applied by the operator ON the host (edit config.yaml directly and reload the agent), not through SentinelX.".into()
                }),
            ),
            (
                "read_or_write_directory".into(),
                Value::String(
                    "Add an entry under file_ops.paths with access 'r' or 'rw' covering a parent directory, then reload the agent; or use the configured add_allowed_read_path playbook when available.".into(),
                ),
            ),
            (
                "command".into(),
                Value::String(
                    "Add the command under allowed_commands, then reload; or use the configured add_allowed_command playbook when available.".into(),
                ),
            ),
            (
                "service".into(),
                Value::String(
                    "Add the service and allowed actions under services, then reload; or use the configured add_service playbook when available.".into(),
                ),
            ),
            (
                "how_to_edit_config".into(),
                Value::String(
                    "Config changes require operator approval: back up config.yaml, make the narrow change, validate it, then reload the agent.".into(),
                ),
            ),
        ])
    }

    fn help(&self, payload: &Map<String, Value>) -> HandlerResult {
        let paths = &self.policy.file_ops_paths;
        let writable = paths
            .iter()
            .filter(|entry| entry.access == crate::policy::FileAccess::ReadWrite)
            .count();
        let playbook_names = self.policy.playbooks.keys().cloned().collect::<Vec<_>>();

        let full = Map::from_iter([
            ("agent".into(), Value::String("sentinelx-cloud-core".into())),
            ("version".into(), Value::String(self.agent_version.clone())),
            (
                "host_label".into(),
                self.policy
                    .hostname_label
                    .clone()
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            ),
            (
                "summary".into(),
                Value::String(
                    "SentinelX provides policy-gated, auditable remote host operations over an authenticated outbound connection. The host policy and OS permissions are independent gates.".into(),
                ),
            ),
            (
                "security_model".into(),
                json!({
                    "two_layers": "Every file/command/service action must pass both SentinelX policy and the agent OS account's permissions.",
                    "allowlist_errors": "path_not_allowed, command_not_allowed and service_not_allowed mean the host policy refused the requested scope.",
                    "permission_errors": "permission_denied means policy allowed the request but the operating-system account could not access the resource.",
                    "sudo": "read/list/search never escalate; edit may use sudo when requested; move/copy/delete/chmod/chown never sudo.",
                    "audit_transparency": "Operations are recorded in the host-local audit without storing file contents or command arguments.",
                }),
            ),
            (
                "operating_notes".into(),
                json!([
                    "Diagnose before mutating: prefer read/list/search and state first.",
                    "For structured edits, use dry_run plus diff before applying risky changes.",
                    "When an action is blocked, use the returned policy or permission error rather than guessing.",
                    "Keep rollback paths for destructive or service-affecting changes.",
                    "Use capabilities for exact policy detail and help for progressive orientation.",
                ]),
            ),
            (
                "navigation".into(),
                Value::Object(self.help_navigation()),
            ),
            (
                "extending_access".into(),
                Value::Object(self.help_extending_access()),
            ),
            (
                "managing_hosts".into(),
                json!({
                    "add_a_host": "Install and enroll the SentinelX agent on the additional host; it joins the same account.",
                    "update_this_agent": "Use the repository/installer maintenance path for the installed implementation, then restart the agent.",
                    "targeting": "With multiple hosts, pass host_id on each operation or set a default host in the Hub integration.",
                }),
            ),
            (
                "playbooks".into(),
                json!({
                    "what": "Named multi-step recipes declared by this host policy.",
                    "names": playbook_names,
                    "count": self.policy.playbooks.len(),
                }),
            ),
            (
                "policy".into(),
                json!({
                    "allowed_commands": self.policy.allowed_commands.len(),
                    "file_ops_paths": paths.len(),
                    "writable_paths": writable,
                    "services": self.policy.services.len(),
                    "locations": self.policy.locations.len() + usize::from(!self.policy.locations.contains_key("config")),
                    "playbooks": self.policy.playbooks.len(),
                    "trusted_fetch_hosts": self.policy.trusted_fetch_hosts.len(),
                }),
            ),
            (
                "examples".into(),
                json!([
                    "Diagnose why a service is failing and show the evidence before changing it.",
                    "Check disk usage and identify what is consuming space.",
                    "Review a bounded slice of a log for suspicious events.",
                    "Restart an allowlisted service and confirm it returned healthy.",
                    "Explain which policy entry is needed for a blocked operation.",
                ]),
            ),
            (
                "getting_started".into(),
                Value::String(
                    "Start with capabilities for the effective policy and state for current host status. If something is blocked, use the returned error to determine whether policy or OS permissions need attention.".into(),
                ),
            ),
            (
                "resources".into(),
                json!({
                    "dashboard": "https://mcp.sentinelx.app/dashboard",
                    "upstream": "https://github.com/pensados/sentinelx-cloud-core",
                    "compatibility_fork": "https://github.com/codeandsolder/sentinelO2-cloud-core",
                    "issues": "https://github.com/codeandsolder/sentinelO2-cloud-core/issues",
                }),
            ),
            (
                "about".into(),
                json!({
                    "project": "SentinelO2 is a Rust compatibility reimplementation of the SentinelX host agent.",
                    "scope": "Match the hosted SentinelX protocol and Linux feature set while fixing implementation bugs rather than reproducing them.",
                }),
            ),
        ]);

        crate::progressive_help::select_help_response(payload, full, &self.policy.playbooks)
    }

    async fn exec(&self, payload: &Map<String, Value>) -> HandlerResult {
        let command = require_str(payload, "command")?;
        let timeout_secs = payload
            .get("timeout")
            .and_then(Value::as_f64)
            .unwrap_or(self.policy.exec_timeout_default as f64)
            .max(0.001);
        let ceiling = if payload
            .get("background")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            self.policy
                .exec_timeout_max
                .max(crate::jobs::BACKGROUND_TIMEOUT_MAX_SECS)
        } else {
            self.policy.exec_timeout_max
        };
        let timeout_secs = timeout_secs.min(ceiling as f64);

        if self.policy.exec_strict {
            if let Some(substitution) = segment::has_substitution(command) {
                return Err(HandlerError::with_details(
                    "command_not_allowed",
                    format!(
                        "exec_strict is on and this command uses {substitution} command substitution"
                    ),
                    Map::from_iter([
                        ("command".into(), Value::String(command.into())),
                        ("substitution".into(), Value::String(substitution.into())),
                    ]),
                ));
            }
            if let Some(offending) = segment::unauthorised_segment(&self.policy, command) {
                return Err(HandlerError::with_details(
                    "command_not_allowed",
                    format!(
                        "exec_strict is on and segment {offending:?} is not covered by allowed_commands"
                    ),
                    Map::from_iter([
                        ("command".into(), Value::String(command.into())),
                        ("offending_segment".into(), Value::String(offending)),
                    ]),
                ));
            }
        }
        if !self.policy.is_command_allowed(command) {
            return Err(HandlerError::with_details(
                "command_not_allowed",
                format!(
                    "command not in allowlist: {}",
                    command.split_whitespace().next().unwrap_or("")
                ),
                Map::from_iter([
                    ("command".into(), Value::String(command.into())),
                    (
                        "allowed_commands".into(),
                        Value::Array(
                            self.policy
                                .allowed_commands
                                .iter()
                                .cloned()
                                .map(Value::String)
                                .collect(),
                        ),
                    ),
                ]),
            ));
        }

        Ok(shell::run_shell(command, Duration::from_secs_f64(timeout_secs), None, None).await)
    }

    async fn service(&self, payload: &Map<String, Value>, force_restart: bool) -> HandlerResult {
        let service = require_str(payload, "service")?;
        let action = if force_restart {
            "restart"
        } else {
            require_str(payload, "action")?
        };
        let Some(spec) = self.policy.services.get(service) else {
            return Err(HandlerError::with_details(
                "service_not_allowed",
                format!("service {service:?} is not registered in policy"),
                Map::from_iter([(
                    "available".into(),
                    Value::Array(
                        self.policy
                            .services
                            .keys()
                            .cloned()
                            .map(Value::String)
                            .collect(),
                    ),
                )]),
            ));
        };
        if !spec.actions.iter().any(|allowed| allowed == action) {
            return Err(HandlerError::with_details(
                "service_action_not_allowed",
                format!("action {action:?} is not allowed for service {service:?}"),
                Map::from_iter([(
                    "allowed_actions".into(),
                    Value::Array(spec.actions.iter().cloned().map(Value::String).collect()),
                )]),
            ));
        }
        if spec.backend != "service" {
            return Err(HandlerError::new(
                "unsupported_backend",
                format!(
                    "service backend {:?} is not supported on this Linux build",
                    spec.backend
                ),
            ));
        }

        let read_only = matches!(action, "status" | "is-active" | "is-enabled");
        let command = if spec.requires_sudo && !read_only {
            format!("sudo systemctl {action} {}", spec.unit)
        } else {
            format!("systemctl {action} {}", spec.unit)
        };
        Ok(shell::run_shell(&command, Duration::from_secs(30), None, None).await)
    }

    async fn read_audit(&self, payload: &Map<String, Value>) -> HandlerResult {
        let limit = payload
            .get("limit")
            .and_then(Value::as_i64)
            .unwrap_or(200)
            .clamp(1, crate::local_audit::MAX_LINES as i64) as usize;
        let entries = tokio::task::spawn_blocking(move || crate::local_audit::read_recent(limit))
            .await
            .map_err(|error| {
                HandlerError::new("internal_error", format!("audit reader failed: {error}"))
            })?;
        Ok(BTreeMap::from([
            ("count".into(), Value::from(entries.len() as u64)),
            ("entries".into(), Value::Array(entries)),
            (
                "source".into(),
                Value::String(crate::local_audit::audit_path().display().to_string()),
            ),
            (
                "max_retained".into(),
                Value::from(crate::local_audit::MAX_LINES as u64),
            ),
        ]))
    }

    async fn blocking_file_op(&self, op: Op, payload: Map<String, Value>) -> HandlerResult {
        let policy = Arc::clone(&self.policy);
        tokio::task::spawn_blocking(move || match op {
            Op::Read => fileops::read(&policy, &payload),
            Op::List => fileops::list(&policy, &payload),
            Op::Search => fileops::search(&policy, &payload),
            Op::Edit => edit::edit(&policy, &payload),
            Op::EditUploadInit => crate::edit_upload::init(&policy),
            Op::EditUploadFile => crate::edit_upload::file(&policy, &payload),
            Op::EditUploadComplete => crate::edit_upload::complete(&policy, &payload),
            Op::UploadInit => crate::upload::upload_init(&policy, &payload),
            Op::UploadChunk => crate::upload::upload_chunk(&policy, &payload),
            Op::UploadComplete => crate::upload::upload_complete(&policy, &payload),
            Op::FileExportInit => crate::file_export::init(&policy, &payload),
            Op::FileExportComplete => crate::file_export::complete(&payload),
            Op::Move | Op::Copy | Op::Delete | Op::Chmod | Op::Chown => {
                crate::fsmutate::handle(&policy, op, &payload)
            }
            _ => Err(HandlerError::new(
                "unsupported_op",
                "not a blocking file op",
            )),
        })
        .await
        .map_err(|error| {
            HandlerError::new("internal_error", format!("worker task failed: {error}"))
        })?
    }
}

impl Dispatcher for CoreDispatcher {
    async fn dispatch(&self, id: &str, op: Op, payload: Map<String, Value>) -> Message {
        if !IMPLEMENTED_OPS.contains(&op) || !self.op_enabled(op) {
            return Self::response(
                id,
                Err(HandlerError::new(
                    "unsupported_op",
                    format!("agent does not support op: {op}"),
                )),
            );
        }

        let started = Instant::now();
        let audit_payload = payload.clone();
        let result = match op {
            Op::Ping => self.ping(),
            Op::Capabilities => self.capabilities_result(&payload),
            Op::Help => self.help(&payload),
            Op::State => self.state(),
            Op::Exec => self.exec(&payload).await,
            Op::ScriptRun => crate::script::handle(&self.policy, &payload).await,
            Op::UploadFile => crate::upload::upload_file(&self.policy, &payload).await,
            Op::FileExportChunk => crate::file_export::chunk(&payload).await,
            Op::Service => self.service(&payload, false).await,
            Op::Restart => self.service(&payload, true).await,
            Op::Read
            | Op::List
            | Op::Search
            | Op::Edit
            | Op::EditUploadInit
            | Op::EditUploadFile
            | Op::EditUploadComplete
            | Op::UploadInit
            | Op::UploadChunk
            | Op::UploadComplete
            | Op::FileExportInit
            | Op::FileExportComplete
            | Op::Move
            | Op::Copy
            | Op::Delete
            | Op::Chmod
            | Op::Chown => self.blocking_file_op(op, payload).await,
            Op::Git => crate::git_ops::handle(&self.policy, &payload).await,
            Op::ProjectSnapshot => crate::project_snapshot::handle(&self.policy, &payload).await,
            Op::ReadAudit => self.read_audit(&payload).await,
            Op::LocalApi => crate::local_api::handle(&self.policy, &payload).await,
        };

        let message = Self::response(id, result);
        let (dispatch_ok, error, result_ok, result_returncode) = match &message {
            Message::Response {
                ok, result, error, ..
            } => (
                *ok,
                error
                    .as_ref()
                    .map(|error| format!("{}: {}", error.code, error.message)),
                result
                    .as_ref()
                    .and_then(|result| result.get("ok"))
                    .and_then(Value::as_bool),
                result
                    .as_ref()
                    .and_then(|result| result.get("returncode"))
                    .and_then(Value::as_i64),
            ),
            _ => (
                false,
                Some("internal_error: non-response dispatch result".into()),
                None,
                None,
            ),
        };
        let duration_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        let op_name = op.as_str().to_owned();
        let audit_task = tokio::task::spawn_blocking(move || {
            crate::local_audit::record(
                &op_name,
                &audit_payload,
                dispatch_ok,
                error.as_deref(),
                duration_ms,
                result_ok,
                result_returncode,
            );
        });
        if let Err(error) = audit_task.await {
            tracing::warn!(?error, "local audit task failed");
        }
        message
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{FileAccess, FileOpsPath, ServiceSpec};
    use tempfile::tempdir;

    #[tokio::test]
    async fn capabilities_are_derived_from_real_dispatch_surface() {
        let dispatcher = CoreDispatcher::new(Policy::default(), "/tmp/config".into(), "test");
        let Message::Response {
            result: Some(result),
            ..
        } = dispatcher.dispatch("x", Op::Capabilities, Map::new()).await
        else {
            panic!("expected capabilities response");
        };
        let advertised = result["ops_supported"].as_array().unwrap();
        assert_eq!(advertised.len(), IMPLEMENTED_OPS.len() - 1);
        assert!(!advertised.iter().any(|value| value == "local_api"));

        let mut policy = Policy::default();
        policy.local_apis.insert(
            "fixture".into(),
            yaml_serde::from_str(
                "transport: unix\nprotocol: http\npath: /tmp/fixture.sock\nactions:\n  ping:\n    request: GET /ping\n",
            )
            .unwrap(),
        );
        let dispatcher = CoreDispatcher::new(policy, "/tmp/config".into(), "test");
        let capabilities = dispatcher.capabilities();
        assert_eq!(
            capabilities
                .iter()
                .filter(|name| name.as_str() != "opaque_ref")
                .count(),
            IMPLEMENTED_OPS.len()
        );
        assert!(capabilities.iter().any(|name| name == "local_api"));
    }

    #[test]
    fn unusable_commands_reports_only_sudo_under_no_new_privileges() {
        let commands = vec![
            "sudo systemctl".to_owned(),
            "/usr/bin/sudo -n true".to_owned(),
            "echo".to_owned(),
        ];
        let value = CoreDispatcher::unusable_commands_for(&commands, true);
        assert_eq!(value["reason"], "no_new_privileges");
        assert_eq!(
            value["commands"],
            json!(["sudo systemctl", "/usr/bin/sudo -n true"])
        );

        assert_eq!(
            CoreDispatcher::unusable_commands_for(&commands, false),
            json!({})
        );
    }

    #[test]
    fn unusable_commands_ignores_empty_and_whitespace_wildcards() {
        let commands = vec!["".to_owned(), "   ".to_owned(), "echo".to_owned()];
        assert_eq!(
            CoreDispatcher::unusable_commands_for(&commands, true),
            json!({})
        );
    }

    #[test]
    fn help_operations_only_recommends_live_reachable_surfaces() {
        let mut policy = Policy::default();
        policy.disabled_ops.extend(
            [
                "edit",
                "script_run",
                "upload_file",
                "upload_init",
                "read_audit",
            ]
            .into_iter()
            .map(str::to_owned),
        );
        let dispatcher = CoreDispatcher::new(policy, "/tmp/config".into(), "test");
        let response = dispatcher
            .help(&Map::from_iter([(
                "topic".into(),
                Value::String("operations".into()),
            )]))
            .unwrap();
        let navigation = response["navigation"].as_object().unwrap();

        assert_eq!(navigation.len(), 2);
        assert!(navigation.contains_key("capabilities"));
        assert!(navigation.contains_key("state"));
        assert!(!navigation.contains_key("exec"));
        assert!(!navigation.contains_key("read / list / search"));
        assert!(!navigation.contains_key("service / restart"));
        assert!(!navigation.contains_key("playbooks"));
    }

    #[test]
    fn help_access_tells_deny_all_host_to_change_config_on_host() {
        let mut policy = Policy::default();
        policy.disabled_ops.insert("edit".into());
        let dispatcher = CoreDispatcher::new(policy, "/tmp/config".into(), "test");
        let response = dispatcher
            .help(&Map::from_iter([(
                "topic".into(),
                Value::String("access".into()),
            )]))
            .unwrap();
        let note = response["extending_access"]["note"].as_str().unwrap();

        assert!(note.contains("cannot edit its own config remotely"));
        assert!(note.contains("ON the host"));
    }

    #[test]
    fn help_navigation_requires_real_prerequisites() {
        let dir = tempdir().unwrap();
        let mut policy = Policy {
            allowed_commands: vec!["git".into()],
            file_ops_paths: vec![FileOpsPath {
                path: dir.path().to_owned(),
                access: FileAccess::ReadWrite,
            }],
            ..Policy::default()
        };
        policy.services.insert(
            "fixture".into(),
            ServiceSpec {
                unit: "fixture.service".into(),
                actions: vec!["status".into()],
                requires_sudo: false,
                description: String::new(),
                domain: "system".into(),
                backend: "service".into(),
            },
        );
        let dispatcher = CoreDispatcher::new(policy, "/tmp/config".into(), "test");
        let navigation = dispatcher.help_navigation();

        for key in [
            "read / list / search",
            "edit",
            "move / copy / delete / chmod / chown",
            "exec",
            "service / restart",
        ] {
            assert!(
                navigation.contains_key(key),
                "missing live help entry: {key}"
            );
        }
    }

    #[tokio::test]
    async fn exec_and_file_ops_cover_self_hosting_minimum() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("hello.txt");
        std::fs::write(&file, "hello").unwrap();
        let policy = Policy {
            allowed_commands: vec!["printf".into()],
            file_ops_paths: vec![FileOpsPath {
                path: dir.path().to_owned(),
                access: FileAccess::ReadWrite,
            }],
            ..Policy::default()
        };
        let dispatcher = CoreDispatcher::new(policy, "/tmp/config".into(), "test");

        let Message::Response { ok: true, .. } = dispatcher
            .dispatch(
                "exec",
                Op::Exec,
                Map::from_iter([("command".into(), Value::String("printf ok".into()))]),
            )
            .await
        else {
            panic!("exec failed");
        };
        let Message::Response {
            ok: true,
            result: Some(result),
            ..
        } = dispatcher
            .dispatch(
                "read",
                Op::Read,
                Map::from_iter([("path".into(), Value::String(file.display().to_string()))]),
            )
            .await
        else {
            panic!("read failed");
        };
        assert_eq!(result["content"], "hello");
    }

    #[tokio::test]
    async fn read_only_service_action_does_not_add_sudo() {
        let mut policy = Policy::default();
        policy.services.insert(
            "fixture".into(),
            ServiceSpec {
                unit: "definitely-not-real.service".into(),
                actions: vec!["is-active".into()],
                requires_sudo: true,
                description: String::new(),
                domain: "system".into(),
                backend: "service".into(),
            },
        );
        let dispatcher = CoreDispatcher::new(policy, "/tmp/config".into(), "test");
        let result = dispatcher
            .service(
                &Map::from_iter([
                    ("service".into(), Value::String("fixture".into())),
                    ("action".into(), Value::String("is-active".into())),
                ]),
                false,
            )
            .await
            .unwrap();
        assert!(result.contains_key("returncode"));
    }
}
