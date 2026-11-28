use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct Baseline {
    pub core: Component,
    pub protocol: Component,
}

#[derive(Deserialize)]
pub struct Component {
    pub repo: String,
    pub reviewed_sha: String,
    pub reviewed_version: Option<String>,
    #[serde(default = "main_branch")]
    pub branch: String,
}

fn main_branch() -> String {
    String::from("main")
}

#[derive(Deserialize)]
pub struct Commit {
    pub sha: String,
    pub commit: CommitBody,
}

#[derive(Deserialize)]
pub struct CommitBody {
    message: String,
}

impl Commit {
    pub fn subject(&self) -> &str {
        self.commit.message.lines().next().unwrap_or_default()
    }
}

#[derive(Deserialize)]
pub struct Change {
    pub filename: String,
    pub status: Option<String>,
    #[serde(default)]
    pub additions: u64,
    #[serde(default)]
    pub deletions: u64,
    pub patch: Option<String>,
}

#[derive(Deserialize)]
pub struct Comparison {
    pub status: String,
    pub total_commits: usize,
    pub commits: Vec<Commit>,
    #[serde(default)]
    pub files: Vec<Change>,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub struct Release {
    pub component: String,
    pub repo: String,
    pub previous_version: Option<String>,
    pub previous_sha: String,
    pub version: String,
    #[serde(rename = "release_sha")]
    pub sha: String,
    pub subject: String,
}

#[derive(Serialize)]
pub struct ReleaseMeta {
    #[serde(flatten)]
    pub release: Release,
    pub marker: String,
    pub title: String,
    pub body_file: std::path::PathBuf,
}

#[derive(Serialize)]
pub struct ComponentMeta {
    pub repo: String,
    pub reviewed_sha: String,
    pub reviewed_version: Option<String>,
    pub head_sha: String,
    pub head_version: Option<String>,
    pub commits_since_review: usize,
    pub release_count: usize,
}

#[derive(Serialize, Default)]
pub struct Metadata {
    pub releases: Vec<ReleaseMeta>,
    pub components: std::collections::BTreeMap<String, ComponentMeta>,
}

pub fn plan_releases(
    name: &str,
    cfg: &Component,
    versions: impl IntoIterator<Item = (Commit, Option<String>)>,
) -> Vec<Release> {
    let mut previous_version = cfg.reviewed_version.clone();
    let mut previous_sha = cfg.reviewed_sha.clone();
    let mut releases = Vec::new();
    for (commit, version) in versions {
        let Some(version) = version.filter(|version| Some(version) != previous_version.as_ref())
        else {
            continue;
        };
        let subject = commit.subject().to_owned();
        releases.push(Release {
            component: name.to_owned(),
            repo: cfg.repo.clone(),
            previous_version,
            previous_sha,
            version: version.clone(),
            sha: commit.sha.clone(),
            subject,
        });
        previous_version = Some(version);
        previous_sha = commit.sha;
    }
    releases
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_bumps_partition_commits() -> crate::Result<()> {
        let cfg: Component = serde_json::from_value(serde_json::json!({
            "repo": "upstream/core", "reviewed_sha": "a", "reviewed_version": "1.0.0"
        }))?;
        let versions = [
            ("b", "fix: prep", Some("1.0.0")),
            ("c", "release 1.1.0", Some("1.1.0")),
            ("d", "docs only", Some("1.1.0")),
            ("e", "release 1.2.0\nDetails", Some("1.2.0")),
        ]
        .map(|(sha, message, version)| {
            (
                Commit {
                    sha: sha.to_owned(),
                    commit: CommitBody {
                        message: message.to_owned(),
                    },
                },
                version.map(str::to_owned),
            )
        });
        let releases = plan_releases("core", &cfg, versions);
        assert_eq!(releases.len(), 2);
        assert_eq!(releases[0].previous_sha, "a");
        assert_eq!(releases[0].sha, "c");
        assert_eq!(releases[1].previous_sha, "c");
        assert_eq!(releases[1].sha, "e");
        assert_eq!(releases[1].subject, "release 1.2.0");
        Ok(())
    }

    #[test]
    fn same_version_and_missing_version_do_not_create_dossiers() -> crate::Result<()> {
        let cfg: Component = serde_json::from_value(serde_json::json!({
            "repo": "upstream/core", "reviewed_sha": "a", "reviewed_version": "1.0.0"
        }))?;
        let versions = [Some("1.0.0"), None].map(|version| {
            (
                Commit {
                    sha: String::from("b"),
                    commit: CommitBody {
                        message: String::from("fix"),
                    },
                },
                version.map(str::to_owned),
            )
        });
        assert_eq!(plan_releases("core", &cfg, versions), [] as [Release; 0]);
        Ok(())
    }
}
