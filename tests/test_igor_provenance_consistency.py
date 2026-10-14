"""Adversarial provenance tests: any-match must not promote a contradictory run."""
import json

from app.hashchain import GENESIS_HASH, canonical_json, compute_record_hash
from app.igor import IgorVerifier


def _records(*payloads):
    previous = GENESIS_HASH
    rows = []
    for index, payload in enumerate(payloads):
        raw = canonical_json(payload)
        digest = compute_record_hash("tenant-a", index, previous, raw)
        rows.append({
            "id": f"e-{index}",
            "tenant_id": "tenant-a",
            "seq": index,
            "prev_hash": previous,
            "record_hash": digest,
            "record_type": "provenance.runtime",
            "payload_json": raw,
        })
        previous = digest
    return rows


def _valid(**overrides):
    return {
        "run_id": "run-1",
        "commit": "frozen-source-sha",
        "task": "Calculate 17 * 23",
        "result": "391",
        "provider": "ollama",
        "model": "qwen2.5:0.5b-instruct",
        "invocation_type": "real_llm",
        "response_ids": ["ollama:response-1"],
        **overrides,
    }


def _verify(rows):
    return IgorVerifier().verify_records(
        rows,
        expected_commit="frozen-source-sha",
        expected_task="Calculate 17 * 23",
        expected_result="391",
        expected_provider="ollama",
        expected_model="qwen2.5:0.5b-instruct",
        expected_run_id="run-1",
    )


def test_igor_rejects_mixed_source_sha_within_same_run():
    rows = _records(_valid(), _valid(commit="attacker-source-sha"))
    verdict = _verify(rows)
    assert verdict.status == "BLOCK"
    assert verdict.reason == "commit provenance mismatch"


def test_igor_rejects_mixed_provider_within_same_run():
    rows = _records(_valid(), _valid(provider="untrusted-provider"))
    verdict = _verify(rows)
    assert verdict.status == "BLOCK"
    assert verdict.reason == "provider provenance mismatch"


def test_igor_rejects_mixed_model_within_same_run():
    rows = _records(_valid(), _valid(model="untrusted-model"))
    verdict = _verify(rows)
    assert verdict.status == "BLOCK"
    assert verdict.reason == "model provenance mismatch"


def test_igor_accepts_consistent_provenance_only():
    rows = _records(_valid(), _valid(response_ids=["ollama:response-2"]))
    verdict = _verify(rows)
    assert verdict.status == "VERIFIED"
    assert verdict.checks["commit"] is True
    assert verdict.checks["provider"] is True
    assert verdict.checks["model"] is True


def test_igor_ignores_historical_other_run_for_current_run_comparison():
    rows = _records(_valid(run_id="old-run", commit="old-sha"), _valid())
    verdict = _verify(rows)
    assert verdict.status == "VERIFIED"
