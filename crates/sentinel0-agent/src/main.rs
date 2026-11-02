#![forbid(unsafe_code)]

use clap::Parser;
use sentinel0_agent::{
    Agent, AgentConfig, ReconnectPolicy,
    core::CoreDispatcher,
    host,
    identity::load_identity,
    instance_lock::{self, EXIT_ALREADY_RUNNING, InstanceLockError},
    policy::Policy,
    rotation::{RotationConfig, load_effective_identity},
};
use sentinel0_proto::PreferredProfile;
use std::{error::Error, path::PathBuf, time::Duration};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

const AGENT_VERSION: &str = "0.23.1-rust.2";

#[derive(Debug, Parser)]
#[command(name = "sentinelx-core")]
struct Args {
    #[arg(long)]
    hub: Option<String>,
    #[arg(long, default_value = "/etc/sentinelx/identity.json")]
    identity: PathBuf,
    #[arg(long, default_value = "/etc/sentinelx/config.yaml")]
    config: PathBuf,
    #[arg(long, default_value = "info")]
    log_level: String,
    #[arg(long)]
    check_config: bool,
    #[arg(long)]
    verify_enrollment: bool,
    #[arg(long, hide = true)]
    local_api_relay: Option<PathBuf>,
    #[arg(long, hide = true, default_value_t = 30.0)]
    relay_timeout: f64,
    #[arg(long, hide = true)]
    ssh_execution_target: Option<String>,
    #[arg(long, hide = true, num_args = 2, value_names = ["SOURCE", "TARGET"])]
    internal_commit_new: Option<Vec<PathBuf>>,
}

const EXIT_INTERNAL_TARGET_EXISTS: i32 = 17;

fn run_internal_commit_new(paths: &[PathBuf]) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let [source, target] = paths else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "internal commit requires SOURCE and TARGET",
        ));
    };
    let target_parent = target.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "internal commit target has no parent directory",
        )
    })?;
    if !std::fs::symlink_metadata(source)?.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "internal commit source must be a regular file",
        ));
    }
    let mode = sentinel0_agent::fsutil::regular_create_mode(target_parent)?;
    std::fs::set_permissions(source, std::fs::Permissions::from_mode(mode))?;
    sentinel0_agent::fsutil::install_file_no_replace(source, target)
}

fn normalized_hub_base(hub: &str) -> &str {
    hub.trim_end_matches('/')
        .strip_suffix("/agent/connect")
        .unwrap_or_else(|| hub.trim_end_matches('/'))
        .trim_end_matches('/')
}

fn ws_base(hub: &str) -> String {
    let hub = normalized_hub_base(hub);
    hub.strip_prefix("https://").map_or_else(
        || {
            hub.strip_prefix("http://")
                .map_or_else(|| hub.to_owned(), |rest| format!("ws://{rest}"))
        },
        |rest| format!("wss://{rest}"),
    )
}

fn http_base(hub: &str) -> String {
    let hub = normalized_hub_base(hub);
    hub.strip_prefix("wss://").map_or_else(
        || {
            hub.strip_prefix("ws://")
                .map_or_else(|| hub.to_owned(), |rest| format!("http://{rest}"))
        },
        |rest| format!("https://{rest}"),
    )
}

fn init_tracing(log_level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_new(log_level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();
}

fn spawn_shutdown_signal(cancel: CancellationToken) {
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let term = signal(SignalKind::terminate());
            match term {
                Ok(mut term) => {
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => {}
                        _ = term.recv() => {}
                    }
                }
                Err(error) => {
                    error!(%error, "failed to install SIGTERM handler; CTRL-C remains active");
                    if let Err(error) = tokio::signal::ctrl_c().await {
                        error!(%error, "failed waiting for CTRL-C");
                    }
                }
            }
        }
        #[cfg(not(unix))]
        {
            if let Err(error) = tokio::signal::ctrl_c().await {
                error!(%error, "failed waiting for CTRL-C");
            }
        }
        cancel.cancel();
    });
}

async fn run_agent(args: Args) -> Result<(), Box<dyn Error + Send + Sync>> {
    let policy = if args.check_config {
        Policy::from_file_strict(&args.config)?
    } else {
        Policy::from_file(&args.config)?
    };
    let dispatcher = CoreDispatcher::new(policy.clone(), args.config.clone(), AGENT_VERSION);

    if args.check_config {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ok": true,
                "config_path": args.config,
                "summary": policy.config_summary(),
                "capabilities": dispatcher.capabilities(),
                "preferred_profile": policy.preferred_profile,
                "hostname_label": policy.hostname_label,
            }))?
        );
        return Ok(());
    }

    let identity = load_effective_identity(&args.identity, load_identity(&args.identity)?);
    let capabilities = dispatcher.capabilities();
    let host = host::gather_host_info(identity.host_id.clone(), Some(policy.config_summary()));
    let hub = args.hub.as_deref().unwrap_or(&identity.hub).to_owned();
    let rotation = RotationConfig {
        identity_path: args.identity.clone(),
        host_id: identity.host_id.clone(),
        hub_http_base: http_base(&hub),
        persisted_hub: identity.hub.clone(),
    };

    if args.verify_enrollment {
        let result =
            sentinel0_agent::preflight::verify_enrollment(&ws_base(&hub), &identity.token).await;
        if result.ok {
            info!(hub = %hub, "enrollment token accepted");
            return Ok(());
        }
        return Err(std::io::Error::other(format!(
            "enrollment preflight failed: {}: {}",
            result.reason, result.detail
        ))
        .into());
    }

    let _instance_lock = match instance_lock::acquire(&args.identity, &identity.host_id) {
        Ok(Some(lock)) => Some(lock),
        Ok(None) => {
            warn!("no writable state directory; running without the single-instance lock");
            None
        }
        Err(InstanceLockError::AlreadyRunning { path, holder }) => {
            let holder = holder.map_or_else(|| "?".to_owned(), |pid| pid.to_string());
            error!(
                host_id = %identity.host_id,
                lock = %path.display(),
                pid = %holder,
                "another SentinelX agent is already running for this host; exiting so the two do not keep dropping each other"
            );
            std::process::exit(EXIT_ALREADY_RUNNING);
        }
        Err(error) => return Err(error.into()),
    };

    let config = AgentConfig {
        hub_ws_base: ws_base(&hub),
        token: identity.token.clone(),
        host,
        agent_version: AGENT_VERSION.into(),
        capabilities,
        preferred_profile: match policy.preferred_profile.as_deref() {
            Some("compact") => Some(PreferredProfile::Compact),
            Some("full") => Some(PreferredProfile::Full),
            _ => None,
        },
        upload_base: policy.upload_base.clone(),
        reconnect: ReconnectPolicy::default(),
        connect_timeout: Duration::from_secs(15),
        welcome_timeout: Duration::from_secs(10),
        heartbeat_interval: Duration::from_secs(30),
        heartbeat_timeout: Duration::from_secs(90),
    };
    let agent = Agent::new(config, dispatcher)?.with_credential_rotation(rotation);
    let cancel = CancellationToken::new();
    spawn_shutdown_signal(cancel.clone());

    info!(
        host_id = %identity.host_id,
        hub = %hub,
        version = AGENT_VERSION,
        "starting SentinelX Rust compatibility agent"
    );
    agent.run(cancel).await?;
    info!("SentinelX Rust compatibility agent stopped");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = Args::parse();
    if let Some(path) = args.local_api_relay.as_deref() {
        std::process::exit(sentinel0_agent::local_api::run_local_api_relay(
            path,
            args.relay_timeout,
        ));
    }
    if let Some(destination) = args.ssh_execution_target.as_deref() {
        sentinel0_agent::ssh_target::run_helper(destination).await?;
        return Ok(());
    }
    if let Some(paths) = args.internal_commit_new.as_deref() {
        match run_internal_commit_new(paths) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                eprintln!("target already exists");
                std::process::exit(EXIT_INTERNAL_TARGET_EXISTS);
            }
            Err(error) => return Err(error.into()),
        }
    }
    init_tracing(&args.log_level);
    run_agent(args).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hub_url_forms_normalize_to_the_same_bases() {
        for (given, http, ws) in [
            (
                "wss://localhost:8000/agent/connect",
                "https://localhost:8000",
                "wss://localhost:8000",
            ),
            (
                "wss://localhost:8000/agent/connect/",
                "https://localhost:8000",
                "wss://localhost:8000",
            ),
            (
                "https://localhost:8000",
                "https://localhost:8000",
                "wss://localhost:8000",
            ),
            (
                "https://mcp.sentinelx.app/",
                "https://mcp.sentinelx.app",
                "wss://mcp.sentinelx.app",
            ),
            (
                "ws://10.0.0.5:8000",
                "http://10.0.0.5:8000",
                "ws://10.0.0.5:8000",
            ),
            (
                "http://10.0.0.5:8000/agent/connect",
                "http://10.0.0.5:8000",
                "ws://10.0.0.5:8000",
            ),
        ] {
            assert_eq!(http_base(given), http, "{given}");
            assert_eq!(ws_base(given), ws, "{given}");
        }
    }
    #[test]
    fn internal_commit_cli_requires_exactly_two_paths() {
        let args = Args::try_parse_from([
            "sentinelx-core",
            "--internal-commit-new",
            "/tmp/source",
            "/tmp/target",
        ])
        .expect("internal commit arguments");
        assert_eq!(
            args.internal_commit_new.as_deref(),
            Some(&[PathBuf::from("/tmp/source"), PathBuf::from("/tmp/target")][..])
        );
        assert!(
            Args::try_parse_from(["sentinelx-core", "--internal-commit-new", "/tmp/only"]).is_err()
        );
    }

    #[test]
    fn internal_commit_is_no_clobber_and_applies_plain_create_mode() {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("source");
        let target = dir.path().join("target");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&source)
            .expect("source");
        std::fs::write(&source, b"payload").expect("source content");
        let expected_mode =
            sentinel0_agent::fsutil::regular_create_mode(dir.path()).expect("plain create mode");
        run_internal_commit_new(&[source.clone(), target.clone()]).expect("commit");
        assert_eq!(std::fs::read(&target).expect("target content"), b"payload");
        assert_eq!(
            std::fs::metadata(&target)
                .expect("target metadata")
                .permissions()
                .mode()
                & 0o777,
            expected_mode
        );

        let second = dir.path().join("second");
        std::fs::write(&second, b"replacement").expect("second source");
        let error = run_internal_commit_new(&[second.clone(), target.clone()])
            .expect_err("existing target must win");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(&target).expect("preserved target"),
            b"payload"
        );
    }
}
