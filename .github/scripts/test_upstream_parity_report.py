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

    def test_changed_range_emits_single_dossier_and_meta(self):
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
                "reviewed_sha": "b" * 40,
                "reviewed_version": "2.0.0",
            },
        }
        heads = {
            "upstream/core": {"sha": "c" * 40},
            "upstream/protocol": {"sha": "b" * 40},
        }
        core_delta = {
            "status": "ahead",
            "commits": [
                {
                    "sha": "d" * 40,
                    "commit": {"message": "fix(core): useful change\n\nbody"},
                }
            ],
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

        def repo_head(repo, _branch):
            return heads[repo]

        def compare(repo, _base, _head):
            self.assertEqual(repo, "upstream/core")
            return core_delta

        def file_text(repo, path, _ref):
            if repo == "upstream/core" and path == "CHANGELOG.md":
                return "# Changelog\n\n## 1.1.0\n- useful change\n\n## 1.0.0\n- old\n"
            if repo == "upstream/protocol" and path == "pyproject.toml":
                return 'version = "2.0.0"\n'
            return ""

        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            baseline_path = tmp / "baseline.json"
            meta_path = tmp / "meta.json"
            baseline_path.write_text(json.dumps(baseline))
            stdout = io.StringIO()
            argv = [
                str(SCRIPT),
                "--baseline",
                str(baseline_path),
                "--meta",
                str(meta_path),
            ]
            with (
                mock.patch.object(MODULE, "repo_head", side_effect=repo_head),
                mock.patch.object(MODULE, "compare", side_effect=compare),
                mock.patch.object(MODULE, "file_text", side_effect=file_text),
                mock.patch.object(sys, "argv", argv),
                contextlib.redirect_stdout(stdout),
            ):
                self.assertEqual(MODULE.main(), 0)

            meta = json.loads(meta_path.read_text())
            self.assertTrue(meta["changed"])
            self.assertEqual(meta["core"]["head_sha"], "c" * 40)
            self.assertEqual(meta["protocol"]["head_sha"], "b" * 40)

            report = stdout.getvalue()
            self.assertEqual(report.count("<!-- automation-upstream-parity -->"), 1)
            self.assertIn("fix(core): useful change", report)
            self.assertIn("src/sentinelx_core/handlers/fileops.py", report)
            self.assertIn("@@ -1 +1 @@", report)
            self.assertIn("## 1.1.0", report)
            self.assertNotIn("## 1.0.0", report)


if __name__ == "__main__":
    unittest.main()
