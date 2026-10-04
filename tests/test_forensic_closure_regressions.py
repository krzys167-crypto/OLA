import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts.forensic_gate import _verify_source_signature, _verify_runtime_execution


class ForensicClosureRegressions(unittest.TestCase):
    def test_unsigned_source_is_blocked_without_exception(self):
        with TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "github-source-verification.json").write_text(json.dumps({
                "sha": "test-source", "commit": {"verification": {"verified": False, "reason": "unsigned"}}
            }))
            result = _verify_source_signature(path, "test-source")
            self.assertEqual(result["status"], "BLOCKED")
            self.assertEqual(result["verification_reason"], "unsigned")

    def test_missing_agent_source_stays_blocked(self):
        with TemporaryDirectory() as directory:
            path = Path(directory)
            names = ["codeact", "react", "agentic_rag", "mcp_tool_use", "self_reflection", "multi_agent"]
            (path / "agent-run.json").write_text(json.dumps({
                "evidence_count": 6,
                "execution": [{"agent": name, "provider": "ollama", "model": "qwen2.5:0.5b-instruct", "invocation_type": "real_llm", "response_digest": "synthetic"} for name in names],
            }))
            result = _verify_runtime_execution(path, "test-source")
            self.assertEqual(result["status"], "BLOCKED")
            self.assertEqual(result["reason"], "agent execution source mismatch")


if __name__ == "__main__":
    unittest.main()
