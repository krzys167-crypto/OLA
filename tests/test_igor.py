import json

from app.igor import IgorVerifier
from app.hashchain import compute_record_hash_v2, sealed_payload_json


def _record(commit="abc", result="391"):
    payload = {"run_id": "r1", "commit": commit, "task": "Calculate 17 * 23", "result": result}
    record = {
        "tenant_id": "tenant-1",
        "record_type": "provenance.runtime",
        "seq": 0,
        "prev_hash": "0" * 64,
        "record_hash": "",
        "payload_json": sealed_payload_json("provenance.runtime", payload),
    }
    record["record_hash"] = compute_record_hash_v2(record["tenant_id"], record["seq"], record["prev_hash"], record["record_type"], "ola_runtime", record["payload_json"])
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
        "record_type": "provenance.runtime",
        "seq": 0,
        "prev_hash": "0" * 64,
        "record_hash": "",
        "payload_json": sealed_payload_json("provenance.runtime", payload),
    }
    record["record_hash"] = compute_record_hash_v2(
        record["tenant_id"], record["seq"], record["prev_hash"], record["record_type"], "ola_runtime", record["payload_json"]
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
        "response_ids": ["ollama:resp-2"],
    }

    first = {
        "id": "old",
        "tenant_id": "tenant-1",
        "record_type": "provenance.runtime",
        "seq": 0,
        "prev_hash": "0" * 64,
        "record_hash": "",
        "payload_json": sealed_payload_json("provenance.runtime", first_payload),
    }
    first["record_hash"] = compute_record_hash_v2(
        first["tenant_id"], first["seq"], first["prev_hash"], first["record_type"], "ola_runtime", first["payload_json"]
    )
    second = {
        "id": "new",
        "tenant_id": "tenant-1",
        "record_type": "provenance.runtime",
        "seq": 1,
        "prev_hash": first["record_hash"],
        "record_hash": "",
        "payload_json": sealed_payload_json("provenance.runtime", second_payload),
    }
    second["record_hash"] = compute_record_hash_v2(
        second["tenant_id"], second["seq"], second["prev_hash"], second["record_type"], "ola_runtime", second["payload_json"]
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
