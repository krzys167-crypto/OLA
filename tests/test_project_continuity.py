"""Contract tests for the isolated, standard-library-only continuity ledger."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "project_continuity.py"
COMMIT = "a" * 40
RUN = "https://github.com/krzysztofcieciwa07-ship-it/OLA/actions/runs/123456"


class ContinuityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "module.txt").write_text("stable code", encoding="utf8")
        self.registry = self.root / "registry.json"
        self.registry.write_text(json.dumps({
            "schema_version": 1,
            "project": "OLA-DI-OS",
            "bootstrap_inventory_incomplete": True,
            "tasks": [{"id": "OLA-001", "title": "Test", "priority": 0,
                       "state": "TODO", "verification": "UNVERIFIED",
                       "proof": None, "watched_files": {}}]
        }), encoding="utf8")

    def cli(self, *args, ok=True):
        p = subprocess.run([sys.executable, str(SCRIPT), "--root", str(self.root),
                            "--registry", str(self.registry), *args],
                           text=True, capture_output=True)
        if ok:
            self.assertEqual(p.returncode, 0, p.stderr)
        else:
            self.assertNotEqual(p.returncode, 0, p.stdout)
        return json.loads(p.stdout) if p.stdout else {"error": p.stderr}

    def verify_task(self):
        self.cli("set", "OLA-001", "--state", "DONE", "--verification", "VERIFIED",
                 "--source-commit", COMMIT, "--verification-url", RUN,
                 "--watch", "module.txt")

    def test_verified_unchanged_skips_duplicate_execution(self):
        self.verify_task()
        r = self.cli("check", "OLA-001")
        self.assertEqual(r["decision"], "SKIP")
        self.assertEqual(self.cli("next")["decision"], "NONE")

    def test_changed_file_requires_reverification_not_rerun(self):
        self.verify_task()
        (self.root / "module.txt").write_text("changed code", encoding="utf8")
        self.assertEqual(self.cli("check", "OLA-001")["decision"], "REVERIFY")
        self.assertEqual(self.cli("next")["decision"], "REVERIFY")

    def test_verified_without_proof_is_rejected_and_not_written(self):
        self.cli("set", "OLA-001", "--state", "DONE", "--verification", "VERIFIED", ok=False)
        self.assertEqual(self.cli("check", "OLA-001")["decision"], "RUN")

    def test_verified_missing_watch_is_rejected(self):
        self.cli("set", "OLA-001", "--state", "DONE", "--verification", "VERIFIED",
                 "--source-commit", COMMIT, "--verification-url", RUN, ok=False)

    def test_in_progress_continues_instead_of_creating_duplicate(self):
        self.cli("set", "OLA-001", "--state", "IN_PROGRESS")
        self.assertEqual(self.cli("next")["task_id"], "OLA-001")
        self.cli("add", "OLA-001", "--title", "Duplicate", ok=False)
        self.assertEqual(len(json.loads(self.registry.read_text())["tasks"]), 1)

    def test_blocked_task_not_executed(self):
        self.cli("set", "OLA-001", "--state", "BLOCKED", "--verification", "BLOCKED")
        self.assertEqual(self.cli("check", "OLA-001")["decision"], "BLOCKED")
        self.assertEqual(self.cli("next")["decision"], "NONE")

    def test_invalid_registry_fails_closed(self):
        self.registry.write_text('{"schema_version": 1, "tasks": [{"id":"X"}]}')
        self.cli("next", ok=False)

    def test_rejected_path_traversal(self):
        self.cli("set", "OLA-001", "--state", "DONE", "--verification", "VERIFIED",
                 "--source-commit", COMMIT, "--verification-url", RUN,
                 "--watch", "../secret.txt", ok=False)


if __name__ == "__main__":
    unittest.main()
