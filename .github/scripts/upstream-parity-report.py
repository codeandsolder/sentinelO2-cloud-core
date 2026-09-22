#!/usr/bin/env python3
"""Build a compact, pre-digested SentinelX upstream parity report."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

API = "https://api.github.com"
USER_AGENT = "sentinelo2-upstream-parity/1.0"
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


def first_core_version(changelog: str) -> str | None:
    match = re.search(r"^##\s+(\d+\.\d+\.\d+)\b", changelog, re.M)
    return match.group(1) if match else None


def changelog_since(changelog: str, reviewed_version: str | None) -> str:
    if not reviewed_version:
        return changelog[:MAX_CHANGELOG]
    marker = re.search(
        rf"^##\s+{re.escape(reviewed_version)}\b", changelog, re.M
    )
    before = changelog[: marker.start()] if marker else changelog
    return before[:MAX_CHANGELOG].rstrip()


def protocol_version(pyproject: str) -> str | None:
    match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.M)
    return match.group(1) if match else None


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


def markdown_for_repo(label: str, cfg: dict, head: dict, delta: dict):
    repo = cfg["repo"]
    old = cfg["reviewed_sha"]
    new = head["sha"]
    files = delta.get("files") or []
    commits = delta.get("commits") or []

    lines = [
        f"### {label}",
        "",
        f"- Repository: {repo}",
        f"- Reviewed SHA: {short_sha(old)}",
        f"- Current SHA: {short_sha(new)}",
        f"- Compare: https://github.com/{repo}/compare/{old}...{new}",
        f"- Compare status: {delta.get('status', 'unknown')}",
        "",
        "#### Commits",
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

    lines += ["", "#### Changed files"]
    if not files:
        lines.append("- No changed files returned.")
    for category in sorted(grouped):
        lines.append(f"- {category}")
        for path in grouped[category]:
            item = by_name[path]
            lines.append(
                f"  - {path} ({item.get('status', '?')}, +{item.get('additions', 0)}/-{item.get('deletions', 0)})"
            )

    return "\n".join(lines), files


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", default=".github/upstream-parity.json", type=Path)
    parser.add_argument("--meta", required=True, type=Path)
    args = parser.parse_args()

    baseline = json.loads(args.baseline.read_text())
    core_cfg = baseline["core"]
    proto_cfg = baseline["protocol"]

    core_head = repo_head(core_cfg["repo"], core_cfg.get("branch", "main"))
    proto_head = repo_head(proto_cfg["repo"], proto_cfg.get("branch", "main"))
    core_changed = core_head["sha"] != core_cfg["reviewed_sha"]
    proto_changed = proto_head["sha"] != proto_cfg["reviewed_sha"]

    core_delta = (
        compare(core_cfg["repo"], core_cfg["reviewed_sha"], core_head["sha"])
        if core_changed
        else {"status": "identical", "commits": [], "files": []}
    )
    proto_delta = (
        compare(proto_cfg["repo"], proto_cfg["reviewed_sha"], proto_head["sha"])
        if proto_changed
        else {"status": "identical", "commits": [], "files": []}
    )

    core_changelog = file_text(core_cfg["repo"], "CHANGELOG.md", core_head["sha"])
    core_version = first_core_version(core_changelog)
    proto_pyproject = file_text(proto_cfg["repo"], "pyproject.toml", proto_head["sha"])
    proto_version = protocol_version(proto_pyproject)

    changed = core_changed or proto_changed
    meta = {
        "changed": changed,
        "core": {
            "repo": core_cfg["repo"],
            "reviewed_sha": core_cfg["reviewed_sha"],
            "head_sha": core_head["sha"],
            "reviewed_version": core_cfg.get("reviewed_version"),
            "head_version": core_version,
        },
        "protocol": {
            "repo": proto_cfg["repo"],
            "reviewed_sha": proto_cfg["reviewed_sha"],
            "head_sha": proto_head["sha"],
            "reviewed_version": proto_cfg.get("reviewed_version"),
            "head_version": proto_version,
        },
    }
    args.meta.write_text(json.dumps(meta, indent=2) + "\n")

    print("<!-- automation-upstream-parity -->")
    print("<!-- automation-queue:upstream-parity -->")
    print()
    print("# SentinelX upstream parity delta")
    print()
    print(
        "Generated from the last reviewed upstream SHAs in .github/upstream-parity.json. "
        "This is a prepared port/review dossier, not a request to rediscover upstream history."
    )
    print()
    print(
        f"Core: {core_cfg.get('reviewed_version', '?')} -> {core_version or '?'}. "
        f"Protocol: {proto_cfg.get('reviewed_version', '?')} -> {proto_version or '?'}."
    )
    print()

    core_md, core_files = markdown_for_repo(
        "sentinelx-cloud-core", core_cfg, core_head, core_delta
    )
    proto_md, proto_files = markdown_for_repo(
        "sentinelx-cloud-protocol", proto_cfg, proto_head, proto_delta
    )
    print(core_md)
    print()
    print(proto_md)

    release_delta = changelog_since(core_changelog, core_cfg.get("reviewed_version"))
    if release_delta:
        print()
        print("## Upstream changelog since reviewed release")
        print()
        print(release_delta)

    patch_budget = MAX_PATCH_TOTAL
    patches = []
    for repo, files in (
        (core_cfg["repo"], core_files),
        (proto_cfg["repo"], proto_files),
    ):
        for item in files:
            path = item["filename"]
            patch = item.get("patch")
            if not patch or not relevant_for_patch(path) or patch_budget <= 0:
                continue
            clipped = patch[: min(MAX_PATCH_PER_FILE, patch_budget)]
            patch_budget -= len(clipped)
            patches.append((repo, path, clipped, len(patch) > len(clipped)))

    if patches:
        print()
        print("## Relevant patch excerpts")
        for repo, path, patch, clipped in patches:
            print()
            print(f"### {repo}:{path}")
            print("~~~~diff")
            print(patch)
            if clipped:
                print("\n# ... patch clipped by detector ...")
            print("~~~~")

    print()
    print("## Maintenance checklist")
    print()
    print("- Review every changed core/protocol behavior and upstream test.")
    print("- Port Linux/cross-platform behavior unless there is a documented intentional divergence.")
    print("- Platform-specific changes may be marked not-applicable only after checking shared wire/config semantics.")
    print("- Prefer translating upstream regression tests with each behavior port.")
    print("- Re-run protocol fixtures/differentials, stable CI, MSRV, fuzz and real-WebSocket tests.")
    print("- Update COMPATIBILITY.md and the project Notion summary for material differences.")
    print("- When resolved, advance .github/upstream-parity.json to the exact current SHAs/versions shown above.")
    print("- Record intentional non-ports next to the baseline so the same delta is not investigated again.")
    print()
    print("This same issue is refreshed if upstream advances before the current range is reviewed.")
    return 0


def cli() -> int:
    try:
        return main()
    except (OSError, KeyError, ValueError) as exc:
        print(f"upstream parity detector failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(cli())
