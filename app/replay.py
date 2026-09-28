import json


def build_replay(records):
    replay = []
    for record in sorted(records, key=lambda item: item["seq"]):
        payload = json.loads(record["payload_json"])
        replay.append({
            "seq": record["seq"],
            "record_type": record.get("record_type"),
            "run_id": payload.get("run_id"),
            "input_digest": payload.get("input_digest"),
            "tool": payload.get("tool"),
            "status": payload.get("status"),
        })
    return replay


def verify_replay(replay, expected_run_id):
    if not replay:
        return {"status": "UNKNOWN", "reason": "replay is empty", "event_count": 0}

    sequences = [item.get("seq") for item in replay]
    if sequences != list(range(sequences[0], sequences[0] + len(sequences))):
        return {"status": "BLOCK", "reason": "replay sequence is not contiguous", "event_count": len(replay)}

    run_ids = {item.get("run_id") for item in replay}
    if run_ids != {expected_run_id}:
        return {"status": "BLOCK", "reason": "replay run provenance mismatch", "event_count": len(replay)}

    if any(not item.get("record_type") or not item.get("status") for item in replay):
        return {"status": "BLOCK", "reason": "replay event is incomplete", "event_count": len(replay)}

    return {
        "status": "PASS",
        "reason": "ordered runtime replay reconstructed and provenance checked",
        "event_count": len(replay),
        "run_id": expected_run_id,
        "first_seq": sequences[0],
        "last_seq": sequences[-1],
    }
