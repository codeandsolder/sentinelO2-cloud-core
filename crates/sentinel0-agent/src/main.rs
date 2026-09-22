#![forbid(unsafe_code)]

use clap::Parser;
use sentinel0_agent::{
    Agent, AgentConfig, ReconnectPolicy, core::CoreDispatcher, host, identity::load_identity,
    policy::Policy,
};
use std::{error::Error, path::PathBuf, time::Duration};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

const AGENT_VERSION: &str = "0.18.4-rust.1";

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
}

fn ws_base(hub: &str) -> String {
    if let Some(rest) = hub.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = hub.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        hub.to_owned()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let filter = tracing_subscriber::EnvFilter::try_new(&args.log_level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();

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

    let identity = load_identity(&args.identity)?;
    let capabilities = dispatcher.capabilities();
    let host = host::gather_host_info(identity.host_id.clone(), Some(policy.config_summary()));
    let hub = args.hub.as_deref().unwrap_or(&identity.hub);

    if args.verify_enrollment {
        let result =
            sentinel0_agent::preflight::verify_enrollment(&ws_base(hub), &identity.token).await;
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
        hub_ws_base: ws_base(hub),
        token: identity.token.clone(),
        host,
        agent_version: AGENT_VERSION.into(),
        capabilities,
        upload_base: policy.upload_base.clone(),
        reconnect: ReconnectPolicy::default(),
        connect_timeout: Duration::from_secs(15),
        welcome_timeout: Duration::from_secs(10),
        heartbeat_interval: Duration::from_secs(30),
        heartbeat_timeout: Duration::from_secs(90),
    };
    let agent = Agent::new(config, dispatcher)?;

    let cancel = CancellationToken::new();
    let signal_cancel = cancel.clone();
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
                    let _ = tokio::signal::ctrl_c().await;
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        signal_cancel.cancel();
    });

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
