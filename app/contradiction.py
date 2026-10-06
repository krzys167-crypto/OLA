import json


def detect_contradictions(records):
    """Findings over a list of evidence records (dicts with `seq`, `payload_json`, optionally `record_type`).

    - `terminal_result_conflict`: the SAME kind of record (same run_id and record_type) reports a different
      (status, result) than an earlier one. Different agents of one run legitimately have different results, so
      they are compared only with themselves; comparing them with each other flagged every normal six-agent run.
    - `unreadable_payload`: a record whose payload is not a JSON object. It used to raise (JSONDecodeError /
      AttributeError), which hid every other finding; an unreadable record is itself a finding.
    """
    findings = []
    terminal = {}
    for record in records:
        seq = record.get("seq") if isinstance(record, dict) else None
        try:
            payload = json.loads(record["payload_json"])
        except (KeyError, TypeError, ValueError):
            payload = None
        if not isinstance(payload, dict):
            findings.append({"type": "unreadable_payload", "seq": seq})
            continue
        run_id = payload.get("run_id")
        if run_id is None:
            continue
        key = (run_id, record.get("record_type"))
        current = (payload.get("status"), str(payload.get("result")))
        if key in terminal and terminal[key][1] != current:
            findings.append({"type": "terminal_result_conflict", "run_id": run_id, "seq": seq,
                             "record_type": record.get("record_type"),
                             "previous": terminal[key][1], "current": current})
        terminal[key] = (seq, current)
    return findings
