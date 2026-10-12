#!/usr/bin/env python3
"""Independent, fail-closed check of the NINA -> Ollama -> IGOR run summary.

This verifies a *CI execution proof*, NOT a production deployment, human
authorization, or a cryptographic signature. The separate database-level
standalone verifier must also pass.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

_SHA = re.compile(r"[0-9a-f]{40}\Z")
_FLOW = ["NINA", "REAL_OLLAMA_LLM", "IGOR", "PROVENANCE", "REPLAY", "HUMAN_GATE"]
_FIELDS = {
    "RUNTIME": "VERIFIED",
    "EVIDENCE": "VERIFIED",
    "REPLAY_INTEGRITY": "VERIFIED",
    "POLICY": "VERIFIED",
    "HUMAN_GATE": "REVIEW",
    "EXECUTION_ALLOWED": "REVIEW",
}
_STATUSES = {
    "nina_status": "VERIFIED",
    "igor_status": "VERIFIED",
    "provenance_status": "VERIFIED",
    "replay_status": "VERIFIED",
    "policy_status": "VERIFIED",
    "human_gate_status": "BLOCK",
    "status": "REVIEW",
}


class ProofRejected(ValueError):
    """A supplied execution report is incomplete or contradictory."""


def verify(proof: object, expected_source_sha: str) -> dict:
    if not isinstance(expected_source_sha, str) or not _SHA.fullmatch(expected_source_sha):
        raise ProofRejected("expected source SHA is invalid")
    if not isinstance(proof, dict):
        raise ProofRejected("proof must be a JSON object")
    for key in ("commit", "source_sha"):
        if proof.get(key) != expected_source_sha:
            raise ProofRejected(f"{key} does not match exact checked-out source SHA")
    event_sha = proof.get("workflow_event_sha")
    if not isinstance(event_sha, str) or not _SHA.fullmatch(event_sha):
        raise ProofRejected("missing or invalid workflow event SHA")
    if proof.get("flow") != _FLOW:
        raise ProofRejected("agent execution flow is not complete or ordered")
    if proof.get("provider") != "ollama":
        raise ProofRejected("real Ollama provider was not reported")
    model = proof.get("model")
    if not isinstance(model, str) or not model.strip():
        raise ProofRejected("LLM model identity is missing")
    if type(proof.get("llm_invocations")) is not int or proof["llm_invocations"] != 6:
        raise ProofRejected("expected exactly six real model invocations")
    for key, value in _STATUSES.items():
        if proof.get(key) != value:
            raise ProofRejected(f"{key} must equal {value}")
    if proof.get("status_fields") != _FIELDS:
        raise ProofRejected("derived status fields are missing, forged or inconsistent")
    for key in ("run_id", "tenant_id"):
        v = proof.get(key)
        if not isinstance(v, str) or not v.strip():
            raise ProofRejected(f"{key} is missing")
    return {
        "status": "VERIFIED_CI_PROOF",
        "source_sha": expected_source_sha,
        "workflow_event_sha": event_sha,
        "provider": proof["provider"],
        "model": model,
        "llm_invocations": 6,
        "igor": "VERIFIED",
        "replay": "VERIFIED",
        "human_gate": "BLOCK",
        "deployment": "NOT_PERFORMED",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--expected-source-sha", required=True)
    parser.add_argument("--result-out", type=Path, required=True)
    args = parser.parse_args()
    raw = args.proof.read_bytes()
    try:
        result = verify(json.loads(raw), args.expected_source_sha)
    except (ProofRejected, json.JSONDecodeError) as exc:
        raise SystemExit(f"BLOCKED: {exc}") from exc
    result["proof_sha256"] = hashlib.sha256(raw).hexdigest()
    args.result_out.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
