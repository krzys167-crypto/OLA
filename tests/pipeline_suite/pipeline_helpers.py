"""Shared helpers for the pipeline suite (kept out of conftest.py: OLA has its own tests/conftest.py)."""
import json


def igor_json(decision="PASS", score=92, corrections=(), findings=(), reason="ok"):
    return json.dumps({"decision": decision, "quality_score": score, "findings": list(findings),
                       "required_corrections": list(corrections), "reason": reason})
