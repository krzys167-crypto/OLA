import json

from .hashchain import GENESIS_HASH, verify_chain


def build_replay(records):
    replay = []
    for record in sorted(records, key=lambda item: item["seq"]):
        try:
            payload = json.loads(record["payload_json"])
        except (TypeError, json.JSONDecodeError):
            payload = None
        if isinstance(payload, dict):
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
        else:
            replay.append({
                "id": record.get("id"),
                "tenant_id": record.get("tenant_id"),
                "seq": record.get("seq"),
                "record_type": record.get("record_type"),
                "run_id": None,
                "input_digest": None,
                "tool": None,
                "status": None,
            })
    return replay


def verify_replay(
    records,
    expected_run_id,
    expected_tenant_id,
    expected_record_count=None,
    expected_tip_hash=None,
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

    for record in records:
        if not isinstance(record, dict):
            return {
                "status": "BLOCK",
                "reason": "record must be a dict",
                "event_count": len(records),
            }
        required = {"tenant_id", "seq", "prev_hash", "record_hash", "record_type", "payload_json"}
        if not required.issubset(record):
            return {
                "status": "BLOCK",
                "reason": "evidence record is incomplete",
                "event_count": len(records),
            }
        if record.get("tenant_id") != expected_tenant_id:
            return {
                "status": "BLOCK",
                "reason": "tenant provenance mismatch",
                "event_count": len(records),
            }
        if not isinstance(record.get("record_type"), str) or not record["record_type"]:
            return {
                "status": "BLOCK",
                "reason": "record type is missing",
                "event_count": len(records),
            }
        if not isinstance(record.get("payload_json"), str):
            return {
                "status": "BLOCK",
                "reason": "missing payload_json",
                "event_count": len(records),
            }
        try:
            payload = json.loads(record["payload_json"])
        except json.JSONDecodeError:
            return {
                "status": "BLOCK",
                "reason": "invalid payload_json",
                "event_count": len(records),
            }
        if not isinstance(payload, dict):
            return {
                "status": "BLOCK",
                "reason": "payload must be a dict",
                "event_count": len(records),
            }

        if payload.get("run_id") == expected_run_id and record["record_type"].startswith("agent."):
            if payload.get("status") != "VERIFIED":
                return {
                    "status": "BLOCK",
                    "reason": "run record status mismatch",
                    "event_count": len(records),
                }

    chain_ok, reason = verify_chain(records)
    if not chain_ok:
        return {
            "status": "BLOCK",
            "reason": reason,
            "event_count": len(records),
        }

    if expected_tip_hash is not None and records[-1].get("record_hash") != expected_tip_hash:
        return {
            "status": "BLOCK",
            "reason": "tip hash mismatch",
            "event_count": len(records),
            "tip_hash": records[-1].get("record_hash"),
        }

    run_record_count = 0
    for record in records:
        try:
            payload = json.loads(record["payload_json"])
        except json.JSONDecodeError:
            continue
        if (
            isinstance(payload, dict)
            and payload.get("run_id") == expected_run_id
            and record.get("record_type", "").startswith("agent.")
        ):
            run_record_count += 1

    if run_record_count == 0:
        return {
            "status": "BLOCK",
            "reason": "run provenance mismatch",
            "event_count": len(records),
        }

    tip_hash = records[-1]["record_hash"]
    return {
        "status": "VERIFIED",
        "reason": "raw evidence records, provenance and hash chain verified",
        "event_count": len(records),
        "run_event_count": run_record_count,
        "run_id": expected_run_id,
        "tenant_id": expected_tenant_id,
        "first_seq": 0,
        "last_seq": records[-1]["seq"],
        "tip_hash": tip_hash,
    }
