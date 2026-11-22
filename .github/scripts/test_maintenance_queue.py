import subprocess
import unittest
from unittest.mock import patch

from queue_rust_release import queue_release

REPOSITORY = "example/agent"
MANIFEST = {"date": "2026-11-12", "pkg": {"rust": {"version": "1.100.0 (abc 2026-11-12)"}}}


class RustReleaseQueueTests(unittest.TestCase):
    @patch("queue_rust_release.subprocess.run")
    def test_new_release_creates_immutable_review(self, run):
        run.side_effect = [
            subprocess.CompletedProcess([], 0),
            subprocess.CompletedProcess([], 0, stdout='[[{"number":41,"body":"<!-- rust-stable-1.99.1 -->"}]]'),
            subprocess.CompletedProcess([], 0),
        ]
        queue_release(REPOSITORY, MANIFEST)
        self.assertEqual(run.call_count, 3)
        label, search, create = [call.args[0] for call in run.call_args_list]
        self.assertEqual(label[:4], ["gh", "label", "create", "automation:rust-release"])
        self.assertEqual(search[:2], ["gh", "api"])
        self.assertIn("--paginate", search)
        self.assertIn("--slurp", search)
        self.assertIn("state=all", search)
        self.assertIn("labels=automation:rust-release", search)
        self.assertIn("repos/example/agent/issues", search)
        self.assertEqual(create[:3], ["gh", "issue", "create"])
        for args in (label, create):
            self.assertEqual(args[args.index("--repo") + 1], REPOSITORY)
        self.assertEqual(create[create.index("--title") + 1], "Rust 1.100.0: full best-practices refresh")
        body = create[create.index("--body") + 1]
        self.assertIn("<!-- rust-stable-1.100.0 -->", body)
        self.assertIn("Rust **1.100.0**", body)
        self.assertIn("`Cargo.toml`/`Cargo.lock`", body)
        self.assertNotIn("${", body)

    @patch("queue_rust_release.subprocess.run")
    def test_existing_release_never_creates_or_edits_issue(self, run):
        run.side_effect = [
            subprocess.CompletedProcess([], 0),
            subprocess.CompletedProcess([], 0, stdout='[[{"number":41,"body":null},{"number":43,"body":"<!-- rust-stable-1.100.0 -->","pull_request":{}}],[{"number":42,"body":"<!-- rust-stable-1.100.0 -->"}]]'),
        ]
        queue_release(REPOSITORY, MANIFEST)
        self.assertEqual(run.call_count, 2)

    @patch("queue_rust_release.subprocess.run")
    def test_invalid_version_is_rejected_before_side_effects(self, run):
        with self.assertRaises(ValueError):
            queue_release(REPOSITORY, {"pkg": {"rust": {"version": "nightly"}}})
        run.assert_not_called()

    @patch("queue_rust_release.subprocess.run")
    def test_inventory_failure_propagates_without_creating_issue(self, run):
        run.side_effect = [
            subprocess.CompletedProcess([], 0),
            subprocess.CalledProcessError(1, ["gh", "api"]),
        ]
        with self.assertRaises(subprocess.CalledProcessError):
            queue_release(REPOSITORY, MANIFEST)
        self.assertEqual(run.call_count, 2)


if __name__ == "__main__":
    unittest.main()
