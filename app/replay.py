import json

from .hashchain import GENESIS_HASH, compute_record_hash


def build_replay(records):
    replay = []
    for record in records:
        payload = json.loads(record["payload_json"])
        replay.append({
            "id": record.get("id"),
            "tenant_id": record.get("tenant_id"),
            "seq": record["seq"],
            "record_type": record.get("record_type"),
            "run_id": payload.get("run_id"),
            "input_digest": payload.get("input_digest"),
            "tool": payload.get("tool"),
            "status": payload.get("status"),
        })
    return replay


def verify_replay(
    records,
    expected_run_id,
    expected_tenant_id,
    expected_record_count=None,
):
    if not records:
        return {
            "status": "UNKNOWN",
            "reason": "replay is empty",
            "event_count": 0,
        }

    if expected_record_count is not None and len(records) != expected_record_count:
        return {
            "status": "BLOCK",
            "reason": "record count mismatch",
            "event_count": len(records),
            "expected_record_count": expected_record_count,
        }

    expected_seq = 0
    expected_prev_hash = GENESIS_HASH
    run_record_count = 0
    tip_hash = None

    for record in records:
        if record.get("tenant_id") != expected_tenant_id:
            return {
                "status": "BLOCK",
                "reason": "tenant provenance mismatch",
                "event_count": len(records),
            }

        if record.get("seq") != expected_seq:
            return {
                "status": "BLOCK",
                "reason": "sequence or predecessor mismatch",
                "event_count": len(records),
            }

        if record.get("prev_hash") != expected_prev_hash:
            return {
                "status": "BLOCK",
                "reason": "sequence or predecessor mismatch",
                "event_count": len(records),
            }

        payload_json = record.get("payload_json")
        if not isinstance(payload_json, str):
            return {
                "status": "BLOCK",
                "reason": "missing payload_json",
                "event_count": len(records),
            }

        try:
            payload = json.loads(payload_json)
        except json.JSONDecodeError:
            return {
                "status": "BLOCK",
                "reason": "invalid payload_json",
                "event_count": len(records),
            }

        if payload.get("run_id") == expected_run_id:
            run_record_count += 1

        expected_hash = compute_record_hash(
            expected_tenant_id,
            expected_seq,
            expected_prev_hash,
            payload_json,
        )
        if record.get("record_hash") != expected_hash:
            return {
                "status": "BLOCK",
                "reason": "record hash mismatch",
                "event_count": len(records),
            }

        tip_hash = record["record_hash"]
        expected_prev_hash = tip_hash
        expected_seq += 1

    if run_record_count == 0:
        return {
            "status": "BLOCK",
            "reason": "run provenance mismatch",
            "event_count": len(records),
        }

    return {
        "status": "VERIFIED",
        "reason": "raw evidence records, provenance and hash chain verified",
        "event_count": len(records),
        "run_event_count": run_record_count,
        "run_id": expected_run_id,
        "tenant_id": expected_tenant_id,
        "first_seq": 0,
        "last_seq": expected_seq - 1,
        "tip_hash": tip_hash,
    }
