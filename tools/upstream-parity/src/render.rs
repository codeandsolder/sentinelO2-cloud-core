use std::collections::BTreeMap;

use crate::model::{Change, Comparison, Release};

const MAX_PATCH_PER_FILE: usize = 5000;
const MAX_PATCH_TOTAL: usize = 32000;
const MAX_CHANGELOG: usize = 9000;

fn clip(text: &str, limit: usize) -> &str {
    text.char_indices()
        .nth(limit)
        .map_or(text, |(index, _)| &text[..index])
}

fn heading(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("##")?;
    rest.starts_with(char::is_whitespace)
        .then(|| rest.trim_start())
}

pub fn changelog_section(changelog: &str, version: &str) -> String {
    let mut offset = 0;
    let mut start = None;
    for line in changelog.split_inclusive('\n') {
        if let Some(title) = heading(line) {
            if let Some(start) = start {
                return clip(changelog[start..offset].trim(), MAX_CHANGELOG).to_owned();
            }
            if title.strip_prefix(version).is_some_and(|tail| {
                tail.chars()
                    .next()
                    .is_none_or(|ch| !ch.is_alphanumeric() && ch != '_')
            }) {
                start = Some(offset);
            }
        }
        offset += line.len();
    }
    start.map_or_else(String::new, |start| {
        clip(changelog[start..].trim(), MAX_CHANGELOG).to_owned()
    })
}

fn classify(path: &str) -> &'static str {
    let path = path.to_lowercase();
    if ["windows", "winspawn", "powershell", "sc.exe"]
        .iter()
        .any(|word| path.contains(*word))
    {
        "platform/windows"
    } else if ["darwin", "macos", "launchd"]
        .iter()
        .any(|word| path.contains(*word))
    {
        "platform/macos"
    } else if path.starts_with("python/sentinelx_protocol/") {
        "protocol-contract"
    } else if path.starts_with("src/sentinelx_core/") {
        "core-implementation"
    } else if path.starts_with("tests/") {
        "tests"
    } else if matches!(path.as_str(), "pyproject.toml" | "config.example.yaml")
        || path.starts_with(".github/")
    {
        "build/config"
    } else if std::path::Path::new(&path)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("md"))
        || path.starts_with("docs/")
    {
        "docs/release-notes"
    } else {
        "other"
    }
}

fn render_changed_files(lines: &mut Vec<String>, files: &[Change]) {
    lines.extend([String::new(), String::from("## Changed files")]);
    if files.is_empty() {
        lines.push(String::from("- No changed files returned."));
    }
    let mut grouped = BTreeMap::<_, Vec<_>>::new();
    for file in files {
        grouped
            .entry(classify(&file.filename))
            .or_default()
            .push(file);
    }
    for (category, files) in grouped {
        lines.push(format!("- {category}"));
        for file in files {
            lines.push(format!(
                "  - {} ({}, +{}/-{})",
                file.filename,
                file.status.as_deref().unwrap_or("?"),
                file.additions,
                file.deletions,
            ));
        }
    }
}

fn render_patches(lines: &mut Vec<String>, repo: &str, files: &[Change]) {
    let mut budget = MAX_PATCH_TOTAL;
    let mut started = false;
    for file in files {
        if budget == 0 {
            break;
        }
        if matches!(classify(&file.filename), "docs/release-notes" | "other") {
            continue;
        }
        let Some(patch) = file.patch.as_deref().filter(|patch| !patch.is_empty()) else {
            continue;
        };
        let clipped = clip(patch, MAX_PATCH_PER_FILE.min(budget));
        budget -= clipped.chars().count();
        if !started {
            lines.extend([String::new(), String::from("## Relevant patch excerpts")]);
            started = true;
        }
        lines.extend([
            String::new(),
            format!("### {repo}:{}", file.filename),
            String::from("~~~~diff"),
            clipped.to_owned(),
        ]);
        if clipped.len() != patch.len() {
            lines.push(String::from("\n# ... patch clipped by detector ..."));
        }
        lines.push(String::from("~~~~"));
    }
}

fn render_checklist(lines: &mut Vec<String>, release: &Release) {
    let component = &release.component;
    let version = &release.version;
    let new = &release.sha;
    lines.extend([
        String::new(),
        String::from("## Maintenance checklist"),
        String::new(),
        String::from("- Review every changed behavior and upstream regression test in this release delta."),
        String::from("- Port Linux/cross-platform behavior unless there is a documented intentional divergence."),
        String::from("- Platform-specific changes may be marked not-applicable only after checking shared wire/config semantics."),
        String::from("- Prefer translating upstream regression tests with each behavior port."),
        String::from("- Re-run protocol fixtures/differentials, pinned Rust CI, fuzz and real-WebSocket tests."),
        String::from("- Update COMPATIBILITY.md and the project Notion summary for material differences."),
        format!("- Advance only the `{component}` entry in `.github/upstream-parity.json` to version `{version}` and SHA `{new}` in the commit that resolves this issue."),
        String::from("- Use `Closes #<this issue>` in that update commit/PR so the release issue closes when the commit lands on main."),
        String::from("- Record intentional non-ports next to the compatibility baseline so they are not rediscovered."),
        String::new(),
        String::from("Do not refresh this issue for later upstream commits or releases. A later release gets a new issue."),
        String::new(),
    ]);
}

pub fn markdown_for_release(release: &Release, delta: &Comparison, changelog: &str) -> String {
    let repo = &release.repo;
    let component = &release.component;
    let version = &release.version;
    let old = &release.previous_sha;
    let new = &release.sha;
    let mut lines = vec![
        format!("<!-- automation-upstream-release:{component}:{version} -->"),
        String::from("<!-- automation-queue:upstream-parity -->"),
        String::new(),
        format!("# SentinelX upstream {component} {version}"),
        String::new(),
        String::from(
            "This issue is an immutable release-scoped port/review dossier. It should be closed by the SentinelO² update commit that ports or explicitly reviews this release.",
        ),
        String::new(),
        format!("- Repository: {repo}"),
        format!(
            "- Previous reviewed release: {} ({})",
            release.previous_version.as_deref().unwrap_or("?"),
            clip(old, 12)
        ),
        format!("- Release: {version} ({})", clip(new, 12)),
        format!("- Release commit subject: {}", release.subject),
        format!("- Compare: https://github.com/{repo}/compare/{old}...{new}"),
        format!("- Compare status: {}", delta.status),
        String::new(),
        String::from("## Commits in this release delta"),
    ];
    if delta.commits.is_empty() {
        lines.push(String::from("- No commits returned by compare API."));
    }
    for commit in &delta.commits {
        let sha = &commit.sha;
        lines.push(format!(
            "- https://github.com/{repo}/commit/{sha} {} {}",
            clip(sha, 12),
            commit.subject()
        ));
    }
    render_changed_files(&mut lines, &delta.files);
    if !changelog.is_empty() {
        lines.extend([
            String::new(),
            String::from("## Release notes"),
            String::new(),
            changelog.to_owned(),
        ]);
    }
    render_patches(&mut lines, repo, &delta.files);
    render_checklist(&mut lines, release);
    lines.join("\n")
}

pub fn safe_version(version: &str) -> String {
    let mut result = String::new();
    let mut invalid = false;
    for ch in version.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
            result.push(ch);
            invalid = false;
        } else if !invalid {
            result.push('_');
            invalid = true;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changelog_extracts_only_requested_release() {
        let changelog =
            "# Changelog\n\n## 1.10.0\nnewer\n\n## 1.1.0 - first\n- notes\n\n## 1.0.0\n- old\n";
        assert_eq!(
            changelog_section(changelog, "1.1.0"),
            "## 1.1.0 - first\n- notes"
        );
        assert_eq!(changelog_section(changelog, "1.0.0"), "## 1.0.0\n- old");
        assert_eq!(
            changelog_section(changelog, "1.1"),
            "## 1.1.0 - first\n- notes"
        );
        assert_eq!(changelog_section(changelog, "2.0.0"), "");
    }

    #[test]
    fn patch_clipping_is_unicode_safe() {
        let value = "あéx";
        assert_eq!(clip(value, 2), "あé");
        assert_eq!(safe_version("1.0+dev/🚀 build"), "1.0_dev_build");
    }

    #[test]
    fn dossier_matches_frozen_python_reference() -> crate::Result<()> {
        #[derive(serde::Deserialize)]
        struct Fixture {
            release: Release,
            delta: Comparison,
            changelog: String,
        }
        let fixture: Fixture = serde_json::from_str(include_str!("../fixtures/dossier.json"))?;
        let actual = markdown_for_release(&fixture.release, &fixture.delta, &fixture.changelog);
        assert_eq!(actual, include_str!("../fixtures/dossier.md"));
        Ok(())
    }
}
