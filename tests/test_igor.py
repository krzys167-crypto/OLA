import json

from app.igor import IgorVerifier
from app.hashchain import compute_record_hash


def _record(commit="abc", result="391"):
    payload = {"run_id": "r1", "commit": commit, "task": "Calculate 17 * 23", "result": result}
    record = {
        "tenant_id": "tenant-1",
        "seq": 0,
        "prev_hash": "0" * 64,
        "record_hash": "",
        "payload_json": json.dumps(payload, sort_keys=True, separators=(",", ":")),
    }
    record["record_hash"] = compute_record_hash(record["tenant_id"], record["seq"], record["prev_hash"], record["payload_json"])
    return record


def test_igor_clean_run_verifies():
    result = IgorVerifier().verify_records([_record()], "abc", "Calculate 17 * 23", "391")
    assert result.status == "VERIFIED"
    assert result.checks["chain"] is True


def test_igor_wrong_commit_blocks():
    result = IgorVerifier().verify_records([_record()], "wrong", "Calculate 17 * 23", "391")
    assert result.status == "BLOCK"
    assert result.reason == "commit provenance mismatch"


def test_igor_missing_evidence_is_not_verified():
    result = IgorVerifier().verify_records([], "abc", "task", "result")
    assert result.status == "UNKNOWN"

def test_igor_verifies_real_ollama_provenance():
    payload = {
        "run_id": "r1",
        "commit": "abc",
        "task": "Calculate 17 * 23",
        "result": "391",
        "provider": "ollama",
        "model": "qwen2.5:0.5b-instruct",
        "invocation_type": "real_llm",
        "response_id": "ollama:resp-1",
    }
    record = {
        "id": "e1",
        "tenant_id": "tenant-1",
        "seq": 0,
        "prev_hash": "0" * 64,
        "record_hash": "",
        "payload_json": json.dumps(payload, sort_keys=True, separators=(",", ":")),
    }
    record["record_hash"] = compute_record_hash(
        record["tenant_id"], record["seq"], record["prev_hash"], record["payload_json"]
    )
    result = IgorVerifier().verify_records(
        [record],
        "abc",
        "Calculate 17 * 23",
        "391",
        expected_provider="ollama",
        expected_model="qwen2.5:0.5b-instruct",
    )
    assert result.status == "VERIFIED"
    assert result.checks["provider"] is True
