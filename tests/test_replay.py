import json

from app.hashchain import compute_record_hash
from app.replay import build_replay, verify_replay


def _record(seq, run_id="r1", record_type="agent.codeact", status="VERIFIED"):
    payload = {
        "run_id": run_id,
        "input_digest": f"in-{seq}",
        "tool": "safe_expression",
        "status": status,
    }
    row = {
        "id": f"e{seq}",
        "tenant_id": "tenant-1",
        "seq": seq,
        "record_type": record_type,
        "payload_json": json.dumps(payload, sort_keys=True, separators=(",", ":")),
        "prev_hash": "0" * 64 if seq == 0 else "",
        "record_hash": "",
    }
    if seq:
        row["prev_hash"] = _record(seq - 1)["record_hash"]
    row["record_hash"] = compute_record_hash(
        row["tenant_id"], row["seq"], row["prev_hash"], row["payload_json"]
    )
    return row


def test_replay_is_verified_for_ordered_runtime_records():
    rows = [_record(0), _record(1)]
    replay = build_replay(rows)
    result = verify_replay(replay, expected_run_id="r1")
    assert result["status"] == "PASS"
    assert result["event_count"] == 2


def test_replay_blocks_missing_sequence():
    rows = [_record(0), _record(2)]
    replay = build_replay(rows)
    result = verify_replay(replay, expected_run_id="r1")
    assert result["status"] == "BLOCK"
    assert "sequence" in result["reason"]
