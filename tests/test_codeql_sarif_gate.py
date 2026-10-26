"""SARIF contract: high CodeQL findings block a release, even when severity is on the rule."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check_codeql_sarif.py"


def run_gate(rules, results):
    with tempfile.TemporaryDirectory() as workdir:
        directory = Path(workdir)
        payload = {"runs": [{
            "tool": {"driver": {"name": "CodeQL", "rules": rules}},
            "results": results,
        }]}
        (directory / "scan.sarif").write_text(json.dumps(payload), encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(CHECKER), str(directory)],
            capture_output=True, text=True, check=False,
        )


class CodeQLSecurityPolicyTest(unittest.TestCase):
    def test_high_severity_rule_blocks_without_result_severity(self):
        result = run_gate(
            [{"id": "py/unsafe", "properties": {"security-severity": "8.1"}}],
            [{"ruleId": "py/unsafe", "message": {"text": "Example security issue"}}],
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("BLOCK", result.stdout)
        self.assertIn("py/unsafe", result.stdout)

    def test_high_severity_result_blocks(self):
        result = run_gate(
            [{"id": "py/unsafe"}],
            [{"ruleId": "py/unsafe", "properties": {"security-severity": "9.8"}}],
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_medium_severity_passes(self):
        result = run_gate(
            [{"id": "py/medium", "properties": {"security-severity": "5.0"}}],
            [{"ruleId": "py/medium"}],
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS", result.stdout)

    def test_missing_sarif_is_blocked(self):
        with tempfile.TemporaryDirectory() as workdir:
            result = subprocess.run(
                [sys.executable, str(CHECKER), workdir],
                capture_output=True, text=True, check=False,
            )
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
