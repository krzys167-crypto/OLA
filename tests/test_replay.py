import json

from app.hashchain import GENESIS_HASH, compute_record_hash
from app.replay import build_replay, verify_replay


def _record(seq, run_id="r1", tenant_id="tenant-1", record_type="agent.codeact", status="VERIFIED", payload_override=None):
    payload = payload_override if payload_override is not None else {
        "run_id": run_id,
        "agent": record_type.removeprefix("agent."),
        "input_digest": f"in-{seq}",
        "tool": "safe_expression",
        "status": status,
    }
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    row = {
        "id": f"e{seq}",
        "tenant_id": tenant_id,
        "seq": seq,
        "record_type": record_type,
        "payload_json": payload_json,
        "prev_hash": GENESIS_HASH if seq == 0 else "",
        "record_hash": "",
    }
    if seq:
        previous = _record(seq - 1, run_id=run_id, tenant_id=tenant_id, record_type=record_type, status=status)
        row["prev_hash"] = previous["record_hash"]
    row["record_hash"] = compute_record_hash(row["tenant_id"], row["seq"], row["prev_hash"], row["payload_json"])
    return row


def _chain(count=2, run_id="r1", tenant_id="tenant-1"):
    return [_record(seq, run_id=run_id, tenant_id=tenant_id) for seq in range(count)]


def test_replay_verifies_raw_records_and_full_hash_chain():
    rows = _chain(count=2)
    result = verify_replay(rows, expected_run_id="r1", expected_tenant_id="tenant-1", expected_record_count=2, expected_tip_hash=rows[-1]["record_hash"])
    assert result["status"] == "VERIFIED"
    assert result["event_count"] == 2
    assert result["first_seq"] == 0
    assert result["last_seq"] == 1
    assert result["tip_hash"] == rows[-1]["record_hash"]


def test_replay_requires_expected_tip_hash():
    rows = _chain(count=2)
    result = verify_replay(rows, expected_run_id="r1", expected_tenant_id="tenant-1", expected_record_count=2, expected_tip_hash="f" * 64)
    assert result["status"] == "BLOCK"
    assert result["reason"] == "tip hash mismatch"


def test_replay_regression_checks_record_type_and_status():
    rows = _chain(count=2)
    rows[1]["record_type"] = "agent.tampered"
    result = verify_replay(rows, expected_run_id="r1", expected_tenant_id="tenant-1", expected_record_count=2, expected_tip_hash=rows[-1]["record_hash"])
    assert result["status"] == "BLOCK"
    assert result["reason"] == "run record type mismatch"

    rows = _chain(count=2)
    rows[1]["payload_json"] = json.dumps({
        "run_id": "r1", "agent": "codeact", "input_digest": "in-1", "tool": "safe_expression", "status": "BLOCK"
    }, sort_keys=True, separators=(",", ":"))
    rows[1]["record_hash"] = compute_record_hash(rows[1]["tenant_id"], rows[1]["seq"], rows[1]["prev_hash"], rows[1]["payload_json"])
    result = verify_replay(rows, expected_run_id="r1", expected_tenant_id="tenant-1", expected_record_count=2, expected_tip_hash=rows[-1]["record_hash"])
    assert result["status"] == "BLOCK"
    assert result["reason"] == "run record status mismatch"


def test_replay_blocks_non_dict_payload_without_exception():
    rows = _chain(count=1)
    rows[0]["payload_json"] = json.dumps(["not", "a", "dict"])
    rows[0]["record_hash"] = compute_record_hash(rows[0]["tenant_id"], rows[0]["seq"], rows[0]["prev_hash"], rows[0]["payload_json"])
    result = verify_replay(rows, expected_run_id="r1", expected_tenant_id="tenant-1", expected_record_count=1, expected_tip_hash=rows[-1]["record_hash"])
    assert result["status"] == "BLOCK"
    assert result["reason"] == "payload must be a dict"


def test_replay_uses_existing_verify_chain(monkeypatch):
    rows = _chain(count=2)
    def reject_chain(_records):
        return False, "forced verify_chain failure"
    monkeypatch.setattr("app.replay.verify_chain", reject_chain)
    result = verify_replay(rows, expected_run_id="r1", expected_tenant_id="tenant-1", expected_record_count=2, expected_tip_hash=rows[-1]["record_hash"])
    assert result["status"] == "BLOCK"
    assert result["reason"] == "forced verify_chain failure"


def test_replay_blocks_tampered_record_hash():
    rows = _chain(count=2)
    rows[1]["record_hash"] = "f" * 64
    result = verify_replay(rows, expected_run_id="r1", expected_tenant_id="tenant-1", expected_record_count=2, expected_tip_hash=rows[-1]["record_hash"])
    assert result["status"] == "BLOCK"
    assert result["reason"] == "record hash mismatch"


def test_replay_blocks_tampered_predecessor_hash():
    rows = _chain(count=2)
    rows[1]["prev_hash"] = "e" * 64
    result = verify_replay(rows, expected_run_id="r1", expected_tenant_id="tenant-1", expected_record_count=2, expected_tip_hash=rows[-1]["record_hash"])
    assert result["status"] == "BLOCK"
    assert result["reason"] == "sequence or predecessor mismatch"


def test_replay_requires_genesis_hash_at_sequence_zero():
    rows = _chain(count=2)
    rows[0]["prev_hash"] = "1" * 64
    result = verify_replay(rows, expected_run_id="r1", expected_tenant_id="tenant-1", expected_record_count=2, expected_tip_hash=rows[-1]["record_hash"])
    assert result["status"] == "BLOCK"
    assert result["reason"] == "sequence or predecessor mismatch"


def test_replay_requires_sequence_to_start_at_zero():
    rows = _chain(count=2)
    rows[0]["seq"] = 1
    result = verify_replay(rows, expected_run_id="r1", expected_tenant_id="tenant-1", expected_record_count=2, expected_tip_hash=rows[-1]["record_hash"])
    assert result["status"] == "BLOCK"
    assert result["reason"] == "sequence or predecessor mismatch"


def test_replay_blocks_wrong_tenant():
    rows = _chain(count=2)
    result = verify_replay(rows, expected_run_id="r1", expected_tenant_id="tenant-other", expected_record_count=2, expected_tip_hash=rows[-1]["record_hash"])
    assert result["status"] == "BLOCK"
    assert result["reason"] == "tenant provenance mismatch"


def test_replay_blocks_wrong_expected_record_count():
    rows = _chain(count=2)
    result = verify_replay(rows, expected_run_id="r1", expected_tenant_id="tenant-1", expected_record_count=3, expected_tip_hash=rows[-1]["record_hash"])
    assert result["status"] == "BLOCK"
    assert result["reason"] == "record count mismatch"


def test_replay_blocks_wrong_run_id():
    rows = _chain(count=2, run_id="actual-run")
    result = verify_replay(rows, expected_run_id="expected-run", expected_tenant_id="tenant-1", expected_record_count=2, expected_tip_hash=rows[-1]["record_hash"])
    assert result["status"] == "BLOCK"
    assert result["reason"] == "run provenance mismatch"


def test_replay_rejects_empty_records():
    result = verify_replay([], expected_run_id="r1", expected_tenant_id="tenant-1", expected_record_count=0, expected_tip_hash=None)
    assert result["status"] == "UNKNOWN"
    assert result["reason"] == "replay is empty"
