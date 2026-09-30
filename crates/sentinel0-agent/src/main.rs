#![forbid(unsafe_code)]

use clap::Parser;
use sentinel0_agent::{
    Agent, AgentConfig, ReconnectPolicy,
    core::CoreDispatcher,
    host,
    identity::load_identity,
    policy::Policy,
    rotation::{RotationConfig, load_effective_identity},
};
use sentinel0_proto::PreferredProfile;
use std::{error::Error, path::PathBuf, time::Duration};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

const AGENT_VERSION: &str = "0.22.0-rust.1";

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
}

fn ws_base(hub: &str) -> String {
    hub.strip_prefix("https://").map_or_else(
        || {
            hub.strip_prefix("http://")
                .map_or_else(|| hub.to_owned(), |rest| format!("ws://{rest}"))
        },
        |rest| format!("wss://{rest}"),
    )
}

fn http_base(hub: &str) -> String {
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

async fn run_agent(args: Args) -> Result<(), Box<dyn Error>> {
    let policy = Policy::from_file(&args.config)?;
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
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    if let Some(path) = args.local_api_relay.as_deref() {
        std::process::exit(sentinel0_agent::local_api::run_local_api_relay(
            path,
            args.relay_timeout,
        ));
    }
    init_tracing(&args.log_level);
    run_agent(args).await
}
