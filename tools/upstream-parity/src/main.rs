mod api;
mod model;
mod render;

use std::{
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

use api::Api;
use clap::Parser;
use model::{Baseline, Component, ComponentMeta, Metadata, ReleaseMeta};
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
    #[error(transparent)]
    Url(#[from] url::ParseError),
    #[error(transparent)]
    Http(#[from] wreq::Error),
    #[error(transparent)]
    Body(#[from] sentinel0_transport::BodyError),
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
    #[error("{0}")]
    Contract(String),
}

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Parser)]
#[command(about = "Build immutable, release-scoped SentinelX upstream parity dossiers")]
struct Args {
    #[arg(long, default_value = ".github/upstream-parity.json")]
    baseline: PathBuf,
    #[arg(long)]
    meta: PathBuf,
    #[arg(long)]
    out_dir: PathBuf,
}

async fn component_report(
    api: &Api,
    name: &str,
    config: &Component,
    out_dir: &Path,
    metadata: &mut Metadata,
) -> Result<()> {
    let head = api.head(&config.repo, &config.branch).await?;
    let mut versions = Vec::new();
    if head != config.reviewed_sha {
        let comparison = api
            .compare(&config.repo, &config.reviewed_sha, &head)
            .await?;
        if !matches!(comparison.status.as_str(), "ahead" | "identical") {
            return Err(Error::Contract(format!(
                "{name} baseline is not an ancestor of upstream head: {}",
                comparison.status
            )));
        }
        for commit in comparison.commits {
            let version = api.version(&config.repo, &commit.sha).await?;
            versions.push((commit, version));
        }
    }
    let commits_since_review = versions.len();
    let head_version = match versions.last() {
        Some((commit, version)) if commit.sha == head => version.clone(),
        _ => api.version(&config.repo, &head).await?,
    };
    let releases = model::plan_releases(name, config, versions);
    metadata.components.insert(
        name.to_owned(),
        ComponentMeta {
            repo: config.repo.clone(),
            reviewed_sha: config.reviewed_sha.clone(),
            reviewed_version: config.reviewed_version.clone(),
            head_sha: head,
            head_version,
            commits_since_review,
            release_count: releases.len(),
        },
    );
    for release in releases {
        let delta = api
            .compare(&release.repo, &release.previous_sha, &release.sha)
            .await?;
        if delta.files.len() >= 300 {
            return Err(Error::Contract(format!(
                "release {}@{} reached GitHub's 300-file limit; complete dossier unavailable",
                release.repo, release.sha
            )));
        }
        let changelog = api
            .file(&release.repo, "CHANGELOG.md", &release.sha)
            .await?
            .map_or_else(String::new, |text| {
                render::changelog_section(&text, &release.version)
            });
        let body = out_dir.join(format!(
            "{name}-{}.md",
            render::safe_version(&release.version)
        ));
        fs::write(
            &body,
            render::markdown_for_release(&release, &delta, &changelog),
        )?;
        let marker = format!("automation-upstream-release:{name}:{}", release.version);
        let title = format!("upstream {name} {} parity", release.version);
        metadata.releases.push(ReleaseMeta {
            release,
            marker,
            title,
            body_file: body,
        });
    }
    Ok(())
}

async fn run(args: Args) -> Result<()> {
    let baseline: Baseline = serde_json::from_slice(&fs::read(&args.baseline)?)?;
    fs::create_dir_all(&args.out_dir)?;
    let token = std::env::var("GITHUB_TOKEN")
        .or_else(|_| std::env::var("GH_TOKEN"))
        .ok();
    let api = Api::new(token)?;
    let mut metadata = Metadata::default();
    component_report(&api, "core", &baseline.core, &args.out_dir, &mut metadata).await?;
    component_report(
        &api,
        "protocol",
        &baseline.protocol,
        &args.out_dir,
        &mut metadata,
    )
    .await?;
    let mut serialized = serde_json::to_vec_pretty(&metadata)?;
    serialized.push(b'\n');
    fs::write(args.meta, serialized)?;
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("upstream parity detector failed: {error}");
            ExitCode::FAILURE
        }
    }
}
