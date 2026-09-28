import json
from types import SimpleNamespace

from app.gate_impact import build_gate_funnel, classify_impact


def record(seq, record_type, payload):
    return SimpleNamespace(
        seq=seq,
        record_type=record_type,
        payload_json=json.dumps(payload),
    )


def test_gate_funnel_uses_only_explicit_runtime_fields():
    rows = [
        record(0, "runtime", {"nina_status": "ALLOW", "igor_status": "VERIFIED"}),
        record(1, "runtime", {"human_gate_status": "BLOCK"}),
    ]

    result = build_gate_funnel(rows)

    assert result["stages"]["nina"]["status"] == "ALLOW"
    assert result["stages"]["igor"]["status"] == "VERIFIED"
    assert result["stages"]["human_gate"]["status"] == "BLOCK"
    assert result["counts"]["ALLOW"] == 1
    assert result["counts"]["VERIFIED"] == 1
    assert result["counts"]["BLOCK"] == 1


def test_gate_funnel_keeps_missing_stages_unknown():
    result = build_gate_funnel([record(0, "audit", {"status": "VERIFIED"})])

    assert result["stages"]["nina"]["status"] == "UNKNOWN"
    assert result["stages"]["igor"]["status"] == "UNKNOWN"
    assert result["stages"]["human_gate"]["status"] == "UNKNOWN"


def test_impact_prefers_latest_explicit_risk():
    rows = [
        record(0, "audit", {"risk": "medium"}),
        record(1, "audit", {"impact": "HIGH"}),
    ]

    result = classify_impact(rows)

    assert result["classification"] == "HIGH"
    assert result["confidence"] == "EXPLICIT"


def test_impact_does_not_invent_risk():
    result = classify_impact([record(0, "audit", {"status": "VERIFIED"})])

    assert result["classification"] == "NO_EXPLICIT_RISK"
    assert result["confidence"] == "UNKNOWN"


def test_impact_empty_evidence_is_unknown():
    result = classify_impact([])

    assert result["classification"] == "UNKNOWN"
    assert result["confidence"] == "UNKNOWN"
