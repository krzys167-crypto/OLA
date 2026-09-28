import json

KNOWN_STATUSES = {"ALLOW", "BLOCK", "UNKNOWN", "VERIFIED"}
STATUS_FIELDS = ("status", "nina_status", "igor_status", "human_gate_status", "candidate_status")


def _payload(record):
    try:
        value = json.loads(record.payload_json)
    except (TypeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _status_values(payload):
    values = []
    for key in STATUS_FIELDS:
        value = payload.get(key)
        if isinstance(value, str) and value in KNOWN_STATUSES:
            values.append((key, value))
    return values


def build_gate_funnel(records):
    counts = {status: 0 for status in sorted(KNOWN_STATUSES)}
    latest = {}
    observed = []

    for record in records:
        payload = _payload(record)
        for field, status in _status_values(payload):
            item = {
                "seq": record.seq,
                "record_type": record.record_type,
                "field": field,
                "status": status,
            }
            counts[status] += 1
            latest[field] = item
            observed.append(item)

    stages = {}
    for stage, field in (
        ("nina", "nina_status"),
        ("igor", "igor_status"),
        ("human_gate", "human_gate_status"),
    ):
        stages[stage] = {"status": latest.get(field, {}).get("status", "UNKNOWN")}

    return {
        "source": "evidence_records.payload_json",
        "rule": "only explicit runtime decision fields are classified; absent stages stay UNKNOWN",
        "counts": counts,
        "stages": stages,
        "observed": observed,
    }


def classify_impact(records):
    explicit = []

    for record in records:
        payload = _payload(record)
        risk = payload.get("risk")
        if risk is None:
            risk = payload.get("impact")
        if isinstance(risk, str) and risk.strip():
            explicit.append(
                {
                    "seq": record.seq,
                    "record_type": record.record_type,
                    "risk": risk.strip().upper(),
                    "source": "payload_json",
                }
            )

    if explicit:
        latest = explicit[-1]
        return {
            "classification": latest["risk"],
            "confidence": "EXPLICIT",
            "source": "evidence_records.payload_json",
            "rule": "latest explicit payload_json.risk or payload_json.impact wins",
            "observations": explicit,
        }

    return {
        "classification": "UNKNOWN" if not records else "NO_EXPLICIT_RISK",
        "confidence": "UNKNOWN",
        "source": "evidence_records.payload_json",
        "rule": "no explicit risk/impact field => UNKNOWN",
        "observed_records": len(records),
    }
