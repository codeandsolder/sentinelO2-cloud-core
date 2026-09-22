#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).with_name("upstream-parity-report.py")
SPEC = importlib.util.spec_from_file_location("upstream_parity_report", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class UpstreamParityReportTests(unittest.TestCase):
    def test_cli_reports_operational_failure_without_secondary_exception(self):
        stderr = io.StringIO()
        with (
            mock.patch.object(MODULE, "main", side_effect=urllib.error.URLError("boom")),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(MODULE.cli(), 1)
        self.assertIn("upstream parity detector failed", stderr.getvalue())
        self.assertIn("boom", stderr.getvalue())

    def test_unreleased_commits_do_not_create_issue_dossiers(self):
        cfg = {
            "repo": "upstream/core",
            "reviewed_sha": "a" * 40,
            "reviewed_version": "1.0.0",
        }
        head = "c" * 40
        overall = {
            "status": "ahead",
            "commits": [
                {"sha": "b" * 40, "commit": {"message": "fix: unreleased"}},
                {"sha": head, "commit": {"message": "docs: still unreleased"}},
            ],
            "files": [],
        }

        with (
            mock.patch.object(MODULE, "compare", return_value=overall),
            mock.patch.object(
                MODULE,
                "file_text",
                return_value='name = "pkg"\nversion = "1.0.0"\n',
            ),
        ):
            releases, count = MODULE.release_points("core", cfg, head)

        self.assertEqual(count, 2)
        self.assertEqual(releases, [])

    def test_multiple_version_bumps_become_distinct_release_dossiers(self):
        baseline = {
            "core": {
                "repo": "upstream/core",
                "branch": "main",
                "reviewed_sha": "a" * 40,
                "reviewed_version": "1.0.0",
            },
            "protocol": {
                "repo": "upstream/protocol",
                "branch": "main",
                "reviewed_sha": "p" * 40,
                "reviewed_version": "2.0.0",
            },
        }
        b = "b" * 40
        c = "c" * 40
        d = "d" * 40
        overall = {
            "status": "ahead",
            "commits": [
                {"sha": b, "commit": {"message": "fix: unreleased prep"}},
                {"sha": c, "commit": {"message": "release 1.1.0"}},
                {"sha": d, "commit": {"message": "release 1.2.0"}},
            ],
            "files": [],
        }
        release_11 = {
            "status": "ahead",
            "commits": overall["commits"][:2],
            "files": [
                {
                    "filename": "src/sentinelx_core/handlers/fileops.py",
                    "status": "modified",
                    "additions": 3,
                    "deletions": 1,
                    "patch": "@@ -1 +1 @@\n-old\n+new",
                }
            ],
        }
        release_12 = {
            "status": "ahead",
            "commits": [overall["commits"][2]],
            "files": [
                {
                    "filename": "tests/test_release.py",
                    "status": "added",
                    "additions": 5,
                    "deletions": 0,
                    "patch": "@@ -0,0 +1 @@\n+test",
                }
            ],
        }

        def repo_head(repo, _branch):
            return {"sha": d if repo == "upstream/core" else "p" * 40}

        def compare(repo, base, head):
            if repo != "upstream/core":
                raise AssertionError("protocol compare should not run")
            if (base, head) == ("a" * 40, d):
                return overall
            if (base, head) == ("a" * 40, c):
                return release_11
            if (base, head) == (c, d):
                return release_12
            raise AssertionError((base, head))

        def file_text(repo, path, ref):
            if path == "pyproject.toml":
                versions = {
                    "a" * 40: "1.0.0",
                    b: "1.0.0",
                    c: "1.1.0",
                    d: "1.2.0",
                    "p" * 40: "2.0.0",
                }
                return f'name = "pkg"\nversion = "{versions[ref]}"\n'
            if path == "CHANGELOG.md":
                return (
                    "# Changelog\n\n"
                    "## 1.2.0 - second\n- second notes\n\n"
                    "## 1.1.0 - first\n- first notes\n\n"
                    "## 1.0.0 - old\n- old\n"
                )
            return ""

        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            baseline_path = tmp / "baseline.json"
            meta_path = tmp / "meta.json"
            out_dir = tmp / "dossiers"
            baseline_path.write_text(json.dumps(baseline))
            argv = [
                str(SCRIPT),
                "--baseline",
                str(baseline_path),
                "--meta",
                str(meta_path),
                "--out-dir",
                str(out_dir),
            ]
            with (
                mock.patch.object(MODULE, "repo_head", side_effect=repo_head),
                mock.patch.object(MODULE, "compare", side_effect=compare),
                mock.patch.object(MODULE, "file_text", side_effect=file_text),
                mock.patch.object(sys, "argv", argv),
            ):
                self.assertEqual(MODULE.main(), 0)

            meta = json.loads(meta_path.read_text())
            releases = meta["releases"]
            self.assertEqual([r["version"] for r in releases], ["1.1.0", "1.2.0"])
            self.assertEqual(releases[0]["previous_sha"], "a" * 40)
            self.assertEqual(releases[1]["previous_sha"], c)

            first = Path(releases[0]["body_file"]).read_text()
            second = Path(releases[1]["body_file"]).read_text()
            self.assertIn("automation-upstream-release:core:1.1.0", first)
            self.assertIn("## 1.1.0 - first", first)
            self.assertNotIn("## 1.2.0 - second", first)
            self.assertIn("Closes #<this issue>", first)
            self.assertIn("automation-upstream-release:core:1.2.0", second)
            self.assertIn("tests/test_release.py", second)


if __name__ == "__main__":
    unittest.main()
