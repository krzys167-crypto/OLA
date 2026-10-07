import ast
import json
import os
from pathlib import Path
import re
from tempfile import TemporaryDirectory
import textwrap
import unittest
from unittest.mock import patch


class FinalGateSelection(unittest.TestCase):
    def setUp(self):
        workflow = Path(__file__).resolve().parents[1] / ".github/workflows/final-production-gate.yml"
        blocks = re.findall(r"python - <<'PY'\n(.*?)\n          PY", workflow.read_text(), re.S)
        self.code = next(textwrap.dedent(block) for block in blocks if "ALL_REQUIRED_EVIDENCE_GATES=SUCCESS" in block)
        tree = ast.parse(self.code)
        assignment = next(node for node in tree.body if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "required" for target in node.targets))
        self.required = ast.literal_eval(assignment.value.args[0])
        self.runs = [{"name": name, "head_sha": "target", "created_at": "2026-10-04T10:00:00Z", "updated_at": "2026-10-04T10:05:00Z", "run_attempt": 1, "id": index, "status": "completed", "conclusion": "success"} for index, name in enumerate(self.required)]

    def check(self, runs):
        original = Path.cwd()
        with TemporaryDirectory() as directory, patch.dict(os.environ, {"TARGET_SHA": "target"}):
            try:
                os.chdir(directory)
                Path("required-runs.json").write_text(json.dumps({"workflow_runs": runs}))
                exec(compile(self.code, "final-gate-selection", "exec"), {})
            finally:
                os.chdir(original)

    def test_latest_failure_cannot_be_hidden_by_old_success(self):
        failed = dict(self.runs[0], created_at="2026-10-04T11:00:00Z", conclusion="failure")
        for runs in ([failed] + self.runs, self.runs + [failed]):
            with self.subTest(order=runs[0]["created_at"]), self.assertRaises(AssertionError):
                self.check(runs)

    def test_latest_success_is_not_overwritten_by_old_failure(self):
        old = dict(self.runs[0], created_at="2026-10-04T09:00:00Z", conclusion="failure")
        self.check(self.runs + [old])

    def test_foreign_source_success_cannot_fill_missing_gate(self):
        foreign = dict(self.runs[0], head_sha="foreign")
        with self.assertRaises(AssertionError):
            self.check(self.runs[1:] + [foreign])

    def test_failed_rerun_cannot_use_previous_attempt_success(self):
        failed = dict(self.runs[0], run_attempt=2, conclusion="failure")
        with self.assertRaises(AssertionError):
            self.check([failed] + self.runs)


if __name__ == "__main__":
    unittest.main()
