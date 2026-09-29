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
        "response_ids": ["ollama:resp-1"],
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

def test_igor_scopes_checks_to_current_run_but_verifies_full_chain():
    first_payload = {"run_id": "old", "commit": "abc", "task": "old", "result": "old"}
    second_payload = {
        "run_id": "r2",
        "commit": "abc",
        "task": "Calculate 17 * 23",
        "result": "391",
        "provider": "ollama",
        "model": "qwen2.5:0.5b-instruct",
        "invocation_type": "real_llm",
        "response_id": "ollama:resp-2",
    }

    first = {
        "id": "old",
        "tenant_id": "tenant-1",
        "seq": 0,
        "prev_hash": "0" * 64,
        "record_hash": "",
        "payload_json": json.dumps(first_payload, sort_keys=True, separators=(",", ":")),
    }
    first["record_hash"] = compute_record_hash(
        first["tenant_id"], first["seq"], first["prev_hash"], first["payload_json"]
    )
    second = {
        "id": "new",
        "tenant_id": "tenant-1",
        "seq": 1,
        "prev_hash": first["record_hash"],
        "record_hash": "",
        "payload_json": json.dumps(second_payload, sort_keys=True, separators=(",", ":")),
    }
    second["record_hash"] = compute_record_hash(
        second["tenant_id"], second["seq"], second["prev_hash"], second["payload_json"]
    )

    result = IgorVerifier().verify_records(
        [first, second],
        "abc",
        "Calculate 17 * 23",
        "391",
        expected_run_id="r2",
        expected_provider="ollama",
        expected_model="qwen2.5:0.5b-instruct",
    )
    assert result.status == "VERIFIED"
    assert result.evidence_ids == ("new",)
