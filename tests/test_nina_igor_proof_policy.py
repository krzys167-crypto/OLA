"""Mutation and source-binding regression tests for OLA NINA/IGOR workflows."""
import copy
from pathlib import Path

import pytest

from scripts.assert_nina_igor_proof import ProofRejected, verify

SOURCE_SHA = "a" * 40
MERGE_EVENT_SHA = "b" * 40


def valid_proof():
    return {
        "commit": SOURCE_SHA,
        "source_sha": SOURCE_SHA,
        "workflow_event_sha": MERGE_EVENT_SHA,
        "flow": ["NINA", "REAL_OLLAMA_LLM", "IGOR", "PROVENANCE", "REPLAY", "HUMAN_GATE"],
        "provider": "ollama",
        "model": "qwen2.5:0.5b-instruct",
        "llm_invocations": 6,
        "nina_status": "VERIFIED",
        "igor_status": "VERIFIED",
        "provenance_status": "VERIFIED",
        "replay_status": "VERIFIED",
        "policy_status": "VERIFIED",
        "human_gate_status": "BLOCK",
        "status": "REVIEW",
        "status_fields": {
            "RUNTIME": "VERIFIED",
            "EVIDENCE": "VERIFIED",
            "REPLAY_INTEGRITY": "VERIFIED",
            "POLICY": "VERIFIED",
            "HUMAN_GATE": "REVIEW",
            "EXECUTION_ALLOWED": "REVIEW",
        },
        "run_id": "run-example",
        "tenant_id": "tenant-example",
    }


def test_good_ci_proof_binds_head_without_promoting_human_gate():
    result = verify(valid_proof(), SOURCE_SHA)
    assert result["status"] == "VERIFIED_CI_PROOF"
    assert result["source_sha"] == SOURCE_SHA
    assert result["workflow_event_sha"] == MERGE_EVENT_SHA
    assert result["human_gate"] == "BLOCK"
    assert result["deployment"] == "NOT_PERFORMED"


@pytest.mark.parametrize("key,value", [
    ("source_sha", MERGE_EVENT_SHA),
    ("commit", MERGE_EVENT_SHA),
    ("workflow_event_sha", "not-a-sha"),
    ("flow", ["NINA", "IGOR"]),
    ("provider", "deterministic"),
    ("model", ""),
    ("llm_invocations", 5),
    ("llm_invocations", True),
    ("igor_status", "UNKNOWN"),
    ("provenance_status", "UNKNOWN"),
    ("replay_status", "BLOCK"),
    ("policy_status", "BLOCK"),
    ("human_gate_status", "VERIFIED"),
    ("status", "VERIFIED"),
    ("run_id", ""),
    ("tenant_id", None),
])
def test_mutated_proof_is_rejected(key, value):
    proof = valid_proof()
    proof[key] = value
    with pytest.raises(ProofRejected):
        verify(proof, SOURCE_SHA)


def test_status_field_forgery_rejected():
    proof = copy.deepcopy(valid_proof())
    proof["status_fields"]["EXECUTION_ALLOWED"] = "VERIFIED"
    with pytest.raises(ProofRejected):
        verify(proof, SOURCE_SHA)


def test_proof_with_missing_status_field_rejected():
    proof = copy.deepcopy(valid_proof())
    del proof["status_fields"]["EVIDENCE"]
    with pytest.raises(ProofRejected):
        verify(proof, SOURCE_SHA)


def test_expected_source_must_be_full_commit_sha():
    with pytest.raises(ProofRejected):
        verify(valid_proof(), "short-sha")


def test_workflow_checks_out_and_runs_exact_pr_head():
    workflow = (Path(__file__).resolve().parents[1] /
                ".github/workflows/nina-igor-ollama.yml").read_text(encoding="utf-8")
    assert "github.event.pull_request.head.sha || github.sha" in workflow
    assert workflow.count("ref: ${{ env.SOURCE_SHA }}") == 2
    assert 'OLA_RUNTIME_COMMIT="$SOURCE_SHA"' in workflow
    assert '--expected-commit "$SOURCE_SHA"' in workflow
    assert 'body["provenance"]["commit"]==os.environ["SOURCE_SHA"]' in workflow
    assert "scripts/assert_nina_igor_proof.py" in workflow
    assert 'assert body["human_gate"]["status"]=="BLOCK"' in workflow
    assert 'OLA_RUNTIME_COMMIT="$GITHUB_SHA"' not in workflow
