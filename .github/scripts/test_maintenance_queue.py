from pathlib import Path
import unittest


class MaintenanceQueueWorkflowTests(unittest.TestCase):
    def test_rust_release_queue_checks_out_repository_before_repo_scripts(self):
        workflow = Path(".github/workflows/maintenance-queue.yml").read_text()
        rust_job = workflow.split("  rust-release-queue:", 1)[1].split("  upstream-parity-queue:", 1)[0]
        checkout = rust_job.index("uses: actions/checkout@")
        renderer = rust_job.index(".github/scripts/render-maintenance-template.py")
        self.assertLess(checkout, renderer)


if __name__ == "__main__":
    unittest.main()
