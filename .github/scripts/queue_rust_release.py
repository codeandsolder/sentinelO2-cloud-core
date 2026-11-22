#!/usr/bin/env python3
"""Queue one maintenance review per stable Rust release."""

import argparse
import json
import re
import subprocess
import tomllib
from urllib.request import urlopen

STABLE_MANIFEST = "https://static.rust-lang.org/dist/channel-rust-stable.toml"
LABEL = "automation:rust-release"


def queue_release(repository: str, manifest: dict) -> None:
    version = manifest["pkg"]["rust"]["version"].split()[0]
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError(f"invalid stable Rust version: {version!r}")
    print(f"Current stable Rust: {version} (release date {manifest['date']})")
    marker = f"rust-stable-{version}"

    subprocess.run(
        [
            "gh",
            "label",
            "create",
            LABEL,
            "--repo",
            repository,
            "--color",
            "8250df",
            "--description",
            "Queued automatically when stable Rust changes",
            "--force",
        ],
        check=True,
    )
    existing = subprocess.run(
        [
            "gh",
            "api",
            "--method",
            "GET",
            "--paginate",
            "--slurp",
            f"repos/{repository}/issues",
            "-f",
            "state=all",
            "-f",
            f"labels={LABEL}",
            "-F",
            "per_page=100",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    # Match the exact marker in the issue inventory, not a delayed search index.
    for page in json.loads(existing.stdout):
        for issue in page:
            if "pull_request" not in issue and f"<!-- {marker} -->" in (
                issue["body"] or ""
            ):
                print(
                    f"Rust {version} review already exists as issue #{issue['number']}"
                )
                return

    body = f"""<!-- {marker} -->
<!-- automation-queue:rust-release -->

Rust **{version}** is now the stable toolchain.

Do a complete repository refresh against this release rather than only replacing the toolchain version:

- Read the official Rust {version} announcement and detailed release notes/changelog.
- Review relevant language, standard-library, rustc, Cargo, Clippy, rustfmt, target/platform, and tooling changes.
- Review all Rust code, `Cargo.toml`/`Cargo.lock`, CI, Docker/build tooling, `SKILL.md`, README/docs, examples, lints, and project conventions for newly preferable patterns or obsolete workarounds.
- Adopt useful newly-stable features and current best practices where they improve the project; remove workarounds that the new stable release makes unnecessary.
- Update the single supported Rust toolchain everywhere, including `rust-version`, CI, release builds, and documentation. This application intentionally does not maintain a separate older MSRV.
- Run the full CI-equivalent test matrix and fix fallout.
- If the release genuinely requires no changes beyond what is already present, document what was reviewed and close this issue as a no-op.

This issue is generated automatically. A ChatGPT maintenance automation is expected to implement it.
"""
    subprocess.run(
        [
            "gh",
            "issue",
            "create",
            "--repo",
            repository,
            "--title",
            f"Rust {version}: full best-practices refresh",
            "--label",
            LABEL,
            "--body",
            body,
        ],
        check=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", help="GitHub owner/repository")
    args = parser.parse_args()
    with urlopen(STABLE_MANIFEST, timeout=30) as response:
        manifest = tomllib.load(response)
    queue_release(args.repository, manifest)


if __name__ == "__main__":
    main()
