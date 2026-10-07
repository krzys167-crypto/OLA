import json

from app.contradiction import detect_contradictions
from app.replay import build_replay


def test_detects_conflicting_terminal_results():
    records = [
        {"seq": 0, "payload_json": json.dumps({"run_id": "r1", "status": "VERIFIED", "result": "391"})},
        {"seq": 1, "payload_json": json.dumps({"run_id": "r1", "status": "BLOCK", "result": "392"})},
    ]
    findings = detect_contradictions(records)
    assert findings[0]["type"] == "terminal_result_conflict"


def test_replay_is_ordered_and_deterministic():
    records = [
        {"seq": 1, "record_type": "agent.react", "payload_json": json.dumps({"run_id": "r1", "input_digest": "b", "tool": "react"})},
        {"seq": 0, "record_type": "agent.codeact", "payload_json": json.dumps({"run_id": "r1", "input_digest": "a", "tool": "safe_expression"})},
    ]
    first = build_replay(records)
    second = build_replay(records)
    assert first == second
    assert [item["seq"] for item in first] == [0, 1]


def _run_records():
    import uuid
    from app.agent_runtime import run_agent_task
    from app.database import SessionLocal
    from app.models import Tenant
    from app import pipeline_bridge as pb
    tenant = str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(Tenant(id=tenant, name="contradiction"))
        db.commit()
    run_agent_task(tenant, "calculate 6 * 7")
    return pb.load_chain(tenant)


def test_a_normal_six_agent_run_has_no_contradiction():
    """Reproduced before the fix: every normal run produced 5 false 'terminal_result_conflict' findings."""
    records = _run_records()
    assert len(records) >= 6
    assert detect_contradictions(records) == []


def test_the_same_agent_reporting_two_different_results_is_a_conflict():
    base = {"run_id": "r1", "status": "VERIFIED", "result": "391"}
    records = [
        {"seq": 0, "record_type": "agent.codeact", "payload_json": json.dumps(base)},
        {"seq": 1, "record_type": "agent.react", "payload_json": json.dumps(dict(base, result="other agent, other result"))},
        {"seq": 2, "record_type": "agent.codeact", "payload_json": json.dumps(dict(base, result="392"))},
    ]
    findings = detect_contradictions(records)
    assert [f["type"] for f in findings] == ["terminal_result_conflict"]
    assert findings[0]["record_type"] == "agent.codeact" and findings[0]["seq"] == 2


def test_unreadable_payloads_are_findings_not_crashes():
    ok = {"seq": 0, "payload_json": json.dumps({"run_id": "r1", "status": "VERIFIED", "result": "1"})}
    clash = {"seq": 3, "payload_json": json.dumps({"run_id": "r1", "status": "BLOCK", "result": "2"})}
    bad = [{"seq": 1, "payload_json": "not json"}, {"seq": 2, "payload_json": "[1,2]"}, {"seq": 4, "payload_json": "null"},
           {"seq": 5}, {"seq": 6, "payload_json": None}]
    findings = detect_contradictions([ok, *bad[:2], clash, *bad[2:]])
    kinds = sorted(f["type"] for f in findings)
    assert kinds == ["terminal_result_conflict"] + ["unreadable_payload"] * 5, kinds
