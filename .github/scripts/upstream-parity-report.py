#!/usr/bin/env python3
"""Build immutable, release-scoped SentinelX upstream parity dossiers."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

API = "https://api.github.com"
USER_AGENT = "sentinelo2-upstream-parity/2.0"
MAX_PATCH_PER_FILE = 5000
MAX_PATCH_TOTAL = 32000
MAX_CHANGELOG = 9000


def request_json(path: str):
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": USER_AGENT,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(API + path, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.load(response)


def repo_head(repo: str, branch: str) -> dict:
    return request_json(
        f"/repos/{repo}/commits/{urllib.parse.quote(branch, safe='')}"
    )


def compare(repo: str, base: str, head: str) -> dict:
    return request_json(f"/repos/{repo}/compare/{base}...{head}?per_page=100")


def file_text(repo: str, path: str, ref: str) -> str:
    payload = request_json(
        f"/repos/{repo}/contents/{urllib.parse.quote(path, safe='/')}?ref={urllib.parse.quote(ref, safe='')}"
    )
    if payload.get("encoding") != "base64":
        return ""
    return base64.b64decode(payload["content"]).decode("utf-8", "replace")


def package_version(pyproject: str) -> str | None:
    match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.M)
    return match.group(1) if match else None


def changelog_section(changelog: str, version: str) -> str:
    start = re.search(rf"^##\s+{re.escape(version)}\b.*$", changelog, re.M)
    if not start:
        return ""
    next_heading = re.search(r"^##\s+", changelog[start.end() :], re.M)
    end = start.end() + next_heading.start() if next_heading else len(changelog)
    return changelog[start.start() : end].strip()[:MAX_CHANGELOG]


def classify(path: str) -> str:
    p = path.lower()
    if any(word in p for word in ("windows", "winspawn", "powershell", "sc.exe")):
        return "platform/windows"
    if any(word in p for word in ("darwin", "macos", "launchd")):
        return "platform/macos"
    if p.startswith("python/sentinelx_protocol/"):
        return "protocol-contract"
    if p.startswith("src/sentinelx_core/"):
        return "core-implementation"
    if p.startswith("tests/"):
        return "tests"
    if p in {"pyproject.toml", "config.example.yaml"} or p.startswith(".github/"):
        return "build/config"
    if p.endswith(".md") or p.startswith("docs/"):
        return "docs/release-notes"
    return "other"


def relevant_for_patch(path: str) -> bool:
    return classify(path) in {
        "protocol-contract",
        "core-implementation",
        "tests",
        "build/config",
        "platform/windows",
        "platform/macos",
    }


def short_sha(value: str) -> str:
    return value[:12]


def release_points(component: str, cfg: dict, head_sha: str) -> tuple[list[dict], int]:
    """Return version-bump commits after the reviewed baseline, in commit order."""
    if head_sha == cfg["reviewed_sha"]:
        return [], 0

    overall = compare(cfg["repo"], cfg["reviewed_sha"], head_sha)
    if overall.get("status") not in {"ahead", "identical"}:
        raise ValueError(
            f"{component} baseline is not an ancestor of upstream head: "
            f"{overall.get('status', 'unknown')}"
        )

    commits = overall.get("commits") or []
    previous_version = cfg.get("reviewed_version")
    previous_sha = cfg["reviewed_sha"]
    releases: list[dict] = []

    for commit in commits:
        sha = commit["sha"]
        version = package_version(file_text(cfg["repo"], "pyproject.toml", sha))
        if not version or version == previous_version:
            continue

        releases.append(
            {
                "component": component,
                "repo": cfg["repo"],
                "previous_version": previous_version,
                "previous_sha": previous_sha,
                "version": version,
                "release_sha": sha,
                "subject": commit["commit"]["message"].splitlines()[0],
            }
        )
        previous_version = version
        previous_sha = sha

    return releases, len(commits)


def markdown_for_release(release: dict, delta: dict, changelog: str) -> str:
    repo = release["repo"]
    old = release["previous_sha"]
    new = release["release_sha"]
    component = release["component"]
    version = release["version"]
    files = delta.get("files") or []
    commits = delta.get("commits") or []

    lines = [
        f"<!-- automation-upstream-release:{component}:{version} -->",
        "<!-- automation-queue:upstream-parity -->",
        "",
        f"# SentinelX upstream {component} {version}",
        "",
        "This issue is an immutable release-scoped port/review dossier. "
        "It should be closed by the SentinelO² update commit that ports or explicitly reviews this release.",
        "",
        f"- Repository: {repo}",
        f"- Previous reviewed release: {release.get('previous_version') or '?'} ({short_sha(old)})",
        f"- Release: {version} ({short_sha(new)})",
        f"- Release commit subject: {release['subject']}",
        f"- Compare: https://github.com/{repo}/compare/{old}...{new}",
        f"- Compare status: {delta.get('status', 'unknown')}",
        "",
        "## Commits in this release delta",
    ]

    if commits:
        for commit in commits:
            sha = commit["sha"]
            subject = commit["commit"]["message"].splitlines()[0]
            lines.append(
                f"- https://github.com/{repo}/commit/{sha} {short_sha(sha)} {subject}"
            )
    else:
        lines.append("- No commits returned by compare API.")

    grouped: dict[str, list[str]] = {}
    by_name = {}
    for item in files:
        grouped.setdefault(classify(item["filename"]), []).append(item["filename"])
        by_name[item["filename"]] = item

    lines += ["", "## Changed files"]
    if not files:
        lines.append("- No changed files returned.")
    for category in sorted(grouped):
        lines.append(f"- {category}")
        for path in grouped[category]:
            item = by_name[path]
            lines.append(
                f"  - {path} ({item.get('status', '?')}, "
                f"+{item.get('additions', 0)}/-{item.get('deletions', 0)})"
            )

    if changelog:
        lines += ["", "## Release notes", "", changelog]

    patch_budget = MAX_PATCH_TOTAL
    patches = []
    for item in files:
        path = item["filename"]
        patch = item.get("patch")
        if not patch or not relevant_for_patch(path) or patch_budget <= 0:
            continue
        clipped = patch[: min(MAX_PATCH_PER_FILE, patch_budget)]
        patch_budget -= len(clipped)
        patches.append((path, clipped, len(patch) > len(clipped)))

    if patches:
        lines += ["", "## Relevant patch excerpts"]
        for path, patch, clipped in patches:
            lines += ["", f"### {repo}:{path}", "~~~~diff", patch]
            if clipped:
                lines.append("\n# ... patch clipped by detector ...")
            lines.append("~~~~")

    lines += [
        "",
        "## Maintenance checklist",
        "",
        "- Review every changed behavior and upstream regression test in this release delta.",
        "- Port Linux/cross-platform behavior unless there is a documented intentional divergence.",
        "- Platform-specific changes may be marked not-applicable only after checking shared wire/config semantics.",
        "- Prefer translating upstream regression tests with each behavior port.",
        "- Re-run protocol fixtures/differentials, stable CI, MSRV, fuzz and real-WebSocket tests.",
        "- Update COMPATIBILITY.md and the project Notion summary for material differences.",
        f"- Advance only the `{component}` entry in `.github/upstream-parity.json` "
        f"to version `{version}` and SHA `{new}` in the commit that resolves this issue.",
        "- Use `Closes #<this issue>` in that update commit/PR so the release issue closes when the commit lands on main.",
        "- Record intentional non-ports next to the compatibility baseline so they are not rediscovered.",
        "",
        "Do not refresh this issue for later upstream commits or releases. A later release gets a new issue.",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", default=".github/upstream-parity.json", type=Path)
    parser.add_argument("--meta", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()

    baseline = json.loads(args.baseline.read_text())
    args.out_dir.mkdir(parents=True, exist_ok=True)

    meta = {"releases": [], "components": {}}
    for component in ("core", "protocol"):
        cfg = baseline[component]
        head = repo_head(cfg["repo"], cfg.get("branch", "main"))
        releases, commits_since_review = release_points(component, cfg, head["sha"])

        current_version = package_version(
            file_text(cfg["repo"], "pyproject.toml", head["sha"])
        )
        meta["components"][component] = {
            "repo": cfg["repo"],
            "reviewed_sha": cfg["reviewed_sha"],
            "reviewed_version": cfg.get("reviewed_version"),
            "head_sha": head["sha"],
            "head_version": current_version,
            "commits_since_review": commits_since_review,
            "release_count": len(releases),
        }

        for release in releases:
            delta = compare(
                release["repo"], release["previous_sha"], release["release_sha"]
            )
            changelog = ""
            try:
                text = file_text(release["repo"], "CHANGELOG.md", release["release_sha"])
                changelog = changelog_section(text, release["version"])
            except (OSError, KeyError, ValueError):
                # Some upstreams do not carry a changelog. The release commit,
                # changed files and patch excerpts are still sufficient.
                pass

            safe_version = re.sub(r"[^A-Za-z0-9._-]+", "_", release["version"])
            body = args.out_dir / f"{component}-{safe_version}.md"
            body.write_text(markdown_for_release(release, delta, changelog))
            marker = f"automation-upstream-release:{component}:{release['version']}"
            meta["releases"].append(
                {
                    **release,
                    "marker": marker,
                    "title": f"upstream {component} {release['version']} parity",
                    "body_file": str(body),
                }
            )

    args.meta.write_text(json.dumps(meta, indent=2) + "\n")
    return 0


def cli() -> int:
    try:
        return main()
    except (OSError, KeyError, ValueError) as exc:
        print(f"upstream parity detector failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(cli())
