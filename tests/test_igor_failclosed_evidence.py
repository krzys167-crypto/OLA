"""IGOR must not infer a result or assemble provenance from unrelated records."""
import json

from app.hashchain import GENESIS_HASH, compute_record_hash
from app.igor import IgorVerifier


def chain(*payloads):
    rows = []
    prev = GENESIS_HASH
    for seq, payload in enumerate(payloads):
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        h = compute_record_hash("tenant-A", seq, prev, raw)
        rows.append({"tenant_id": "tenant-A", "seq": seq, "prev_hash": prev,
                     "payload_json": raw, "record_hash": h})
        prev = h
    return rows


def test_missing_result_never_verifies_as_none():
    rows = chain({"run_id": "r1", "commit": "abc", "task": "task"})
    outcome = IgorVerifier().verify_records(rows, "abc", "task", None, expected_run_id="r1")
    assert outcome.status == "BLOCK"


def test_provider_model_and_response_ids_cannot_be_spliced():
    rows = chain(
        {"run_id": "r1", "commit": "abc", "task": "task", "result": "391", "provider": "ollama", "invocation_type": "real_llm", "response_ids": []},
        {"run_id": "r1", "model": "qwen", "response_ids": ["other:response"]},
    )
    outcome = IgorVerifier().verify_records(rows, "abc", "task", "391", expected_run_id="r1", expected_provider="ollama", expected_model="qwen")
    assert outcome.status == "BLOCK"


def test_single_coherent_provenance_remains_verified():
    rows = chain({"run_id":"r1","commit":"abc","task":"task","result":"391",
                  "provider":"ollama","model":"qwen","invocation_type":"real_llm","response_ids":["ollama:real"]})
    outcome = IgorVerifier().verify_records(rows, "abc", "task", "391", expected_run_id="r1", expected_provider="ollama", expected_model="qwen")
    assert outcome.status == "VERIFIED"
