use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, de::DeserializeOwned};
use std::time::Duration;
use url::Url;

use crate::{Error, Result, model::Comparison};

// Compare responses may include patches for hundreds of files.
const MAX_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;

pub struct Api {
    client: wreq::Client,
    origin: Url,
    token: Option<String>,
}

#[derive(Deserialize)]
struct Head {
    sha: String,
}

#[derive(Deserialize)]
struct Contents {
    encoding: String,
    content: String,
}

#[derive(Deserialize)]
struct Manifest {
    project: Project,
}

#[derive(Deserialize)]
struct Project {
    version: Option<String>,
}

pub fn package_version(text: &str) -> Result<Option<String>> {
    Ok(toml::from_str::<Manifest>(text)?.project.version)
}

impl Api {
    pub fn new(token: Option<String>) -> Result<Self> {
        Ok(Self {
            client: sentinel0_transport::client_builder()
                .timeout(Duration::from_secs(30))
                .user_agent("sentinelo2-upstream-parity/3.0")
                .build()?,
            origin: Url::parse("https://api.github.com/")?,
            token,
        })
    }

    fn endpoint(&self, repo: &str, tail: &[&str]) -> Result<Url> {
        let (owner, name) = repo
            .split_once('/')
            .ok_or_else(|| Error::Contract(format!("invalid GitHub repository: {repo}")))?;
        if owner.is_empty() || name.is_empty() || name.contains('/') {
            return Err(Error::Contract(format!(
                "invalid GitHub repository: {repo}"
            )));
        }
        let mut url = self.origin.clone();
        url.path_segments_mut()
            .map_err(|()| {
                Error::Contract(String::from("GitHub API URL cannot hold path segments"))
            })?
            .clear()
            .push("repos")
            .push(owner)
            .push(name)
            .extend(tail.iter().copied());
        Ok(url)
    }

    async fn get<T: DeserializeOwned>(&self, url: Url) -> Result<Option<T>> {
        let mut request = self
            .client
            .get(url.as_str())
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28");
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await?;
        if response.status() == wreq::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(Error::Contract(format!(
                "GitHub API returned {} for {url}",
                response.status()
            )));
        }
        let body = sentinel0_transport::read_bounded(response, MAX_RESPONSE_BYTES).await?;
        Ok(Some(serde_json::from_slice(&body)?))
    }

    async fn require<T: DeserializeOwned>(&self, url: Url) -> Result<T> {
        self.get(url.clone())
            .await?
            .ok_or_else(|| Error::Contract(format!("GitHub resource not found: {url}")))
    }

    pub async fn head(&self, repo: &str, branch: &str) -> Result<String> {
        let head: Head = self
            .require(self.endpoint(repo, &["commits", branch])?)
            .await?;
        Ok(head.sha)
    }

    pub async fn compare(&self, repo: &str, base: &str, head: &str) -> Result<Comparison> {
        let range = format!("{base}...{head}");
        let mut url = self.endpoint(repo, &["compare", &range])?;
        url.query_pairs_mut().append_pair("per_page", "100");
        let mut result: Comparison = self.require(url.clone()).await?;
        let mut page = 2_u64;
        while result.commits.len() < result.total_commits {
            let mut next = url.clone();
            next.query_pairs_mut()
                .append_pair("page", &page.to_string());
            let mut continuation: Comparison = self.require(next).await?;
            if continuation.commits.is_empty() || continuation.total_commits != result.total_commits
            {
                return Err(Error::Contract(format!(
                    "incomplete compare pagination for {repo}:{range}"
                )));
            }
            result.commits.append(&mut continuation.commits);
            page += 1;
        }
        if result.commits.len() != result.total_commits {
            return Err(Error::Contract(format!(
                "unexpected compare commit count for {repo}:{range}"
            )));
        }
        Ok(result)
    }

    pub async fn file(&self, repo: &str, path: &str, reference: &str) -> Result<Option<String>> {
        let segments: Vec<_> = std::iter::once("contents").chain(path.split('/')).collect();
        let mut url = self.endpoint(repo, &segments)?;
        url.query_pairs_mut().append_pair("ref", reference);
        let Some(contents): Option<Contents> = self.get(url).await? else {
            return Ok(None);
        };
        if contents.encoding != "base64" {
            return Err(Error::Contract(format!(
                "unexpected encoding for {repo}:{path}@{reference}"
            )));
        }
        let compact: String = contents
            .content
            .chars()
            .filter(|ch| !ch.is_ascii_whitespace())
            .collect();
        let bytes = STANDARD.decode(compact)?;
        Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
    }

    pub async fn version(&self, repo: &str, reference: &str) -> Result<Option<String>> {
        let manifest = self
            .file(repo, "pyproject.toml", reference)
            .await?
            .ok_or_else(|| Error::Contract(format!("missing pyproject.toml at {repo}")))?;
        package_version(&manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_uses_project_version_not_build_metadata() -> Result<()> {
        assert_eq!(
            package_version("[tool.fake]\nversion = \"2\"\n[project]\nversion = \"1.0.0\"")?
                .as_deref(),
            Some("1.0.0")
        );
        assert_eq!(package_version("[project]\nname = \"example\"")?, None);
        Ok(())
    }

    #[test]
    fn endpoint_encodes_branch_as_single_segment() -> Result<()> {
        let api = Api::new(None)?;
        let url = api.endpoint("owner/repo", &["commits", "feature/branch"])?;
        assert_eq!(
            url.as_str(),
            "https://api.github.com/repos/owner/repo/commits/feature%2Fbranch"
        );
        assert!(api.endpoint("owner/repo/extra", &[]).is_err());
        Ok(())
    }
}

#[cfg(test)]
mod transport_tests {
    use super::*;
    use crate::{
        component_report,
        model::{Component, Metadata},
    };
    use serde_json::{Value, json};
    use std::collections::BTreeMap;
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        net::TcpListener,
        time::timeout,
    };

    fn commit(sha: &str, subject: &str) -> Value {
        json!({"sha": sha, "commit": {"message": subject}})
    }

    fn comparison(total: usize, commits: &[Value]) -> Value {
        json!({"status":"ahead","total_commits":total,"commits":commits,"files":[]})
    }

    fn contents(text: &str) -> Value {
        json!({"encoding":"base64", "content":STANDARD.encode(text)})
    }

    type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

    async fn serve(
        listener: TcpListener,
        mut responses: BTreeMap<String, Option<Value>>,
    ) -> TestResult {
        while !responses.is_empty() {
            let (stream, _) = timeout(Duration::from_secs(10), listener.accept()).await??;
            let mut stream = BufReader::new(stream);
            let mut line = String::new();
            stream.read_line(&mut line).await?;
            let path = line
                .split_whitespace()
                .nth(1)
                .ok_or("missing request path")?;
            let response = responses
                .remove(path)
                .ok_or_else(|| format!("unexpected request: {path}"))?;
            loop {
                line.clear();
                if stream.read_line(&mut line).await? == 0 || line == "\r\n" {
                    break;
                }
            }
            let (status, body) = response.map_or_else(
                || ("404 Not Found", String::from("{}")),
                |value| ("200 OK", value.to_string()),
            );
            let http = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.get_mut().write_all(http.as_bytes()).await?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn paginated_upstream_release_dossiers_are_immutable_and_distinct() -> TestResult {
        let b = commit("b", "unreleased fix");
        let c = commit("c", "release 1.1.0");
        let d = commit("d", "release 1.2.0");
        let responses = [
            ("/commits/main", Some(json!({"sha":"d"}))),
            (
                "/compare/a...d?per_page=100",
                Some(comparison(3, &[b.clone(), c.clone()])),
            ),
            (
                "/compare/a...d?per_page=100&page=2",
                Some(comparison(3, std::slice::from_ref(&d))),
            ),
            (
                "/contents/pyproject.toml?ref=b",
                Some(contents("[project]\nversion = \"1.0.0\"")),
            ),
            (
                "/contents/pyproject.toml?ref=c",
                Some(contents("[project]\nversion = \"1.1.0\"")),
            ),
            (
                "/contents/pyproject.toml?ref=d",
                Some(contents("[project]\nversion = \"1.2.0\"")),
            ),
            ("/compare/a...c?per_page=100", Some(comparison(2, &[b, c]))),
            ("/compare/c...d?per_page=100", Some(comparison(1, &[d]))),
            (
                "/contents/CHANGELOG.md?ref=c",
                Some(contents("## 1.1.0\n- first\n## 1.0.0\n- older")),
            ),
            ("/contents/CHANGELOG.md?ref=d", None),
        ]
        .into_iter()
        .map(|(path, response)| (format!("/repos/upstream/core{path}"), response))
        .collect();
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let mut api = Api::new(None)?;
        api.origin = Url::parse(&format!("http://{}/", listener.local_addr()?))?;
        let server = tokio::spawn(serve(listener, responses));
        let config = Component {
            repo: "upstream/core".to_owned(),
            reviewed_sha: "a".to_owned(),
            reviewed_version: Some("1.0.0".to_owned()),
            branch: "main".to_owned(),
        };
        let output = tempfile::tempdir()?;
        let mut metadata = Metadata::default();
        component_report(&api, "core", &config, output.path(), &mut metadata).await?;
        server.await??;
        assert_eq!(metadata.releases.len(), 2);
        assert_eq!(metadata.components["core"].commits_since_review, 3);
        let first = &metadata.releases[0];
        let second = &metadata.releases[1];
        assert_eq!(first.release.previous_sha, "a");
        assert_eq!(second.release.previous_sha, "c");
        assert_eq!(first.marker, "automation-upstream-release:core:1.1.0");
        assert_eq!(second.marker, "automation-upstream-release:core:1.2.0");
        let first_body = std::fs::read_to_string(&first.body_file)?;
        let second_body = std::fs::read_to_string(&second.body_file)?;
        assert!(first_body.contains("## 1.1.0\n- first"));
        assert!(!first_body.contains("- older"));
        assert!(!second_body.contains("## Release notes"));
        Ok(())
    }
}
