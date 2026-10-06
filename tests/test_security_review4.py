"""Fourth review: human gate input strictness, judge JSON strictness (fake Ollama, no network)."""
import json

import pytest

from ola_pipeline.igor import parse_judge
from tests.test_pipeline_bridge import HUMAN, anchors, env, fake, make_tenant, post  # noqa: F401

_GOOD = {"decision": "PASS", "quality_score": 90, "findings": [], "required_corrections": [], "reason": "ok"}


# ---------------------------------------------------------------- item 1: human_approved must be JSON true
@pytest.mark.parametrize("value", ["false", "False", "no", "0", "false ", "", "off", 1, 2, [], {}, None, "true", "yes"])
def test_item1_only_json_true_approves(env, value):
    _, key = make_tenant()
    r = post(key, human_approved=value, human_actor="reviewer-1", human_reason="checked")
    if r.status_code == 200:
        assert r.json()["human_gate"]["status"] != "VERIFIED" and r.json()["status"] != "VERIFIED", r.text
    else:
        assert r.status_code == 400, r.text


@pytest.mark.parametrize("actor", [None, 5, [], {}, "", "   ", "​", "​​", "⁠", "﻿", "\t\n", " ​ "])
def test_item1_actor_must_be_a_real_name(env, actor):
    _, key = make_tenant()
    r = post(key, human_approved=True, human_actor=actor, human_reason="checked")
    assert r.status_code == 400, r.text


@pytest.mark.parametrize("reason", [None, 5, [], {}, "", "  ", "​"])
def test_item1_reason_must_be_a_real_text(env, reason):
    _, key = make_tenant()
    r = post(key, human_approved=True, human_actor="reviewer-1", human_reason=reason)
    assert r.status_code == 400, r.text


def test_item1_oversized_actor_or_reason_is_400(env):
    _, key = make_tenant()
    assert post(key, human_approved=True, human_actor="a" * 201, human_reason="x").status_code == 400
    assert post(key, human_approved=True, human_actor="a", human_reason="x" * 1001).status_code == 400


def test_item1_an_explicit_false_without_actor_is_still_a_block_not_an_error(env):
    _, key = make_tenant()
    r = post(key)                                           # no human_* at all
    assert r.status_code == 200 and r.json()["status"] == "BLOCK"
    r = post(key, human_approved=False, human_actor="r", human_reason="no")
    assert r.status_code == 200 and r.json()["status"] == "BLOCK"


def test_item1_a_proper_approval_still_verifies(env):
    _, key = make_tenant()
    r = post(key, **HUMAN)
    assert r.status_code == 200 and r.json()["status"] == "VERIFIED", r.text


# ---------------------------------------------------------------- items 4 / 5: judge JSON strictness
def test_item4_duplicate_keys_in_judge_json_are_rejected():
    dup = ('{"decision":"BLOCK","decision":"PASS","quality_score":90,"findings":[],'
           '"required_corrections":[],"reason":"x"}')
    obj, why = parse_judge(dup)
    assert obj is None and "duplicate" in why
    dup2 = ('{"decision":"PASS","quality_score":10,"quality_score":95,"findings":[],'
            '"required_corrections":[],"reason":"x"}')
    assert parse_judge(dup2)[0] is None


def test_item4_nested_duplicate_keys_are_rejected_too():
    s = '{"decision":"PASS","quality_score":90,"findings":[],"required_corrections":[],"reason":"x","extra":{"a":1,"a":2}}'
    assert parse_judge(s)[0] is None


@pytest.mark.parametrize("decision", [["PASS"], {"a": 1}, 1, None, True, 1.5, "pass", "PASS "])
def test_item5_a_non_string_decision_is_invalid_not_a_crash(decision):
    obj = dict(_GOOD, decision=decision)
    parsed, why = parse_judge(json.dumps(obj))
    assert parsed is None and why == "invalid decision"


def test_item4_valid_judge_json_still_parses():
    parsed, why = parse_judge(json.dumps(_GOOD))
    assert parsed is not None and parsed["decision"] == "PASS" and why == ""


# ---------------------------------------------------------------- item 9: "UNKNOWN" commit is not provenance
import hashlib
import os
import uuid

from fastapi.testclient import TestClient

from app.main import app


def _nina_run(key, task="Calculate 2+2"):
    return TestClient(app).post("/nina-run", headers={"X-API-Key": key}, json={"task": task})


@pytest.mark.parametrize("commit", ["UNKNOWN", "unknown", " UNKNOWN ", " ", ""])
def test_item9_unknown_or_blank_commit_never_verifies(monkeypatch, commit):
    for k in ("OLA_SOURCE_COMMIT", "OLA_RUNTIME_COMMIT"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("OLA_SOURCE_COMMIT", commit)
    _, key = make_tenant()
    r = _nina_run(key)
    assert r.status_code == 200, r.text
    b = r.json()
    assert b["status"] != "VERIFIED" and b["igor"]["status"] != "VERIFIED", b["igor"]


def test_item9_a_real_commit_still_verifies(monkeypatch):
    for k in ("OLA_SOURCE_COMMIT", "OLA_RUNTIME_COMMIT"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("OLA_SOURCE_COMMIT", "abc1234")
    _, key = make_tenant()
    b = _nina_run(key).json()
    assert b["igor"]["status"] == "VERIFIED", b["igor"]


# ---------------------------------------------------------------- item 3: task input shape
@pytest.mark.parametrize("task", [5, ["a"], {"a": 1}, True, 1.5, "\ud800", "x" * 8001, "", "   "],
                         ids=["int", "list", "dict", "bool", "float", "surrogate", "too-long", "empty", "blank"])
def test_item3_nina_run_task_must_be_a_bounded_string(monkeypatch, task):
    monkeypatch.setenv("OLA_SOURCE_COMMIT", "abc1234")
    _, key = make_tenant()
    r = TestClient(app, raise_server_exceptions=False).post(
        "/nina-run", headers={"X-API-Key": key, "Content-Type": "application/json"}, content=json.dumps({"task": task}))
    assert r.status_code == 400, (r.status_code, r.text[:200])


def test_item3_pipeline_run_task_is_bounded_too(env):
    _, key = make_tenant()
    assert post(key, task="x" * 8001).status_code == 400
    r = TestClient(app, raise_server_exceptions=False).post(
        "/pipeline-run", headers={"X-API-Key": key, "Content-Type": "application/json"},
        content=json.dumps({"task": "\ud800", **HUMAN}))
    assert r.status_code == 400, r.status_code


# ---------------------------------------------------------------- item 7: arithmetic that cannot be computed is not a 500
from app.agent_runtime import _safe_expression


@pytest.mark.parametrize("task", ["Calculate 1/0", "Calculate 1.5/0", "Calculate 1e999 * 0", "Calculate 1e308 * 10",
                                  "Calculate " + "1+" * 3000 + "1", "Calculate " + "(" * 500 + "1" + ")" * 500,
                                  "Calculate 1\x00"])
def test_item7_uncomputable_expressions_are_refused_in_the_record(task):
    out = _safe_expression(task)
    assert out.startswith("task accepted:"), out


def test_item7_computable_expressions_are_unchanged():
    assert _safe_expression("Calculate 17 * 23") == "391"
    assert _safe_expression("Calculate 7 / 2") == "3.5"


def test_item7_division_by_zero_over_http_is_not_a_500(monkeypatch):
    monkeypatch.setenv("OLA_SOURCE_COMMIT", "abc1234")
    _, key = make_tenant()
    r = TestClient(app, raise_server_exceptions=False).post(
        "/nina-run", headers={"X-API-Key": key}, json={"task": "Calculate 1/0"})
    assert r.status_code == 200, r.text[:200]
    assert r.json()["status"] != "VERIFIED" or "not computable" in json.dumps(r.json())


# ---------------------------------------------------------------- item 6: Stripe webhook payload shape and FAILED rows
import hmac
import time

from sqlalchemy import select

from app import stripe_webhook as sw
from app.database import SessionLocal
from app.models import StripeEvent

_SECRET = "whsec_r4"


def _post_webhook(payload: bytes):
    ts = int(time.time())
    sig = hmac.new(_SECRET.encode(), f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()
    return TestClient(app, raise_server_exceptions=False).post(
        "/stripe/webhook", content=payload, headers={"Stripe-Signature": f"t={ts},v1={sig}"})


def _event(tenant_id, **session_over):
    # one checkout session per event: the old fixture reused "cs_1" for every event, i.e. it modelled several payments
    # as ONE session, which per-session idempotency (review 6) rightly answers from the cache
    session = {"id": "cs_" + uuid.uuid4().hex, "payment_status": "paid", "status": "complete", "amount_total": 9900, "currency": "eur",
               "metadata": {"offer": "ola-execution-audit", "product": "OLA Execution Audit",
                            "task": "Calculate 2+2", "tenant_id": tenant_id}}
    session.update(session_over)
    return {"id": "evt_" + uuid.uuid4().hex, "type": "checkout.session.completed", "data": {"object": session}}


@pytest.mark.parametrize("body", [[], "x", 5, None, {"id": 5, "type": "x"}, {"id": {"a": 1}, "type": "x"},
                                  {"id": "e", "type": ["x"]},
                                  {"id": "e", "type": "checkout.session.completed", "data": []},
                                  {"id": "e", "type": "checkout.session.completed", "data": {"object": []}},
                                  {"id": "e", "type": "checkout.session.completed", "data": {"object": {"metadata": []}}}],
                         ids=["list", "str", "int", "null", "int-id", "dict-id", "list-type", "data-list", "object-list",
                              "metadata-list"])
def test_item6_malformed_stripe_payloads_are_400_not_500(monkeypatch, body):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", _SECRET)
    r = _post_webhook(json.dumps(body).encode())
    assert r.status_code == 400, (r.status_code, r.text[:200])


@pytest.mark.parametrize("over", [{"line_items": [1]}, {"line_items": {"data": {}}}, {"line_items": {"data": [5]}},
                                  {"metadata": {"offer": "ola-execution-audit"}, "custom_fields": {"a": 1}}, {"metadata": {"offer": "ola-execution-audit", "task": "t",
                                                                             "tenant_id": {"a": 1}}}],
                         ids=["items-list", "data-dict", "item-int", "custom-fields-dict", "tenant-dict"])
def test_item6_malformed_checkout_sections_are_rejected_not_500(monkeypatch, over):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", _SECRET)
    tenant, _ = make_tenant()
    r = _post_webhook(json.dumps(_event(tenant, **over)).encode())
    assert r.status_code == 400, (r.status_code, r.text[:200])


def test_item6_an_unknown_tenant_is_400_and_leaves_no_row(monkeypatch):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", _SECRET)
    ev = _event("no-such-tenant-" + uuid.uuid4().hex)
    r = _post_webhook(json.dumps(ev).encode())
    assert r.status_code == 400, r.text[:200]
    with SessionLocal() as db:
        assert db.scalar(select(StripeEvent).where(StripeEvent.event_id == ev["id"])) is None


def test_item6_a_valid_paid_event_still_completes(monkeypatch):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", _SECRET)
    tenant, _ = make_tenant()
    ev = _event(tenant)
    r = _post_webhook(json.dumps(ev).encode())
    assert r.status_code == 200 and r.json()["status"] == "COMPLETED", r.text[:300]


def test_item6_a_failure_after_the_row_exists_marks_it_FAILED_not_PROCESSING(monkeypatch):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", _SECRET)
    tenant, _ = make_tenant()
    ev = _event(tenant)

    def boom(*a, **k):
        raise RuntimeError("chain unavailable")
    monkeypatch.setattr(sw, "_append_evidence", boom)
    r = _post_webhook(json.dumps(ev).encode())
    assert r.status_code == 500
    with SessionLocal() as db:
        row = db.scalar(select(StripeEvent).where(StripeEvent.event_id == ev["id"]))
        assert row is not None and row.status == "FAILED", row and row.status


# ---------------------------------------------------------------- item 10: ExecutionSafetyGate is strict about its inputs
from app.execution_safety_gate import ExecutionSafetyGate


def _gate_run(gate, **kw):
    hits = []
    kw.setdefault("action", "wire_transfer")
    d = gate.execute(agent_id="a", effect=lambda: hits.append(1) or "done", **kw)
    return d.status, len(hits)


@pytest.mark.parametrize("risk", ["HGIH", "CRITICAL", "HIGH ", "HI​GH", None, 3, ["HIGH"], ""])
def test_item10_an_unknown_risk_label_never_executes(risk):
    assert _gate_run(ExecutionSafetyGate({"wire_transfer"}), risk=risk) == ("BLOCK", 0)


@pytest.mark.parametrize("approved", ["false", "yes", 1, [1], {"x": 1}, None])
def test_item10_only_boolean_true_approves_a_high_risk_action(approved):
    assert _gate_run(ExecutionSafetyGate({"wire_transfer"}), risk="HIGH", human_approved=approved) == ("REVIEW", 0)


def test_item10_the_known_paths_still_work():
    g = ExecutionSafetyGate({"wire_transfer"})
    assert _gate_run(g, risk="HIGH", human_approved=True) == ("ALLOW", 1)
    assert _gate_run(g, risk="low") == ("ALLOW", 1) and _gate_run(g, risk="MEDIUM") == ("ALLOW", 1)
    assert _gate_run(g, risk="HIGH") == ("REVIEW", 0) and _gate_run(g, risk="high") == ("REVIEW", 0)
    assert _gate_run(g, action="rm_rf") == ("BLOCK", 0)


@pytest.mark.parametrize("action", [["wire_transfer"], {"a": 1}, None, 5, " wire_transfer"])
def test_item10_a_non_string_or_padded_action_is_blocked_not_a_crash(action):
    assert _gate_run(ExecutionSafetyGate({"wire_transfer"}), action=action) == ("BLOCK", 0)


def test_item10_a_str_subclass_cannot_fake_equality():
    class Liar(str):
        def __eq__(self, other):
            return True
        __hash__ = lambda self: hash("wire_transfer")
    assert _gate_run(ExecutionSafetyGate({"wire_transfer"}), action=Liar("evil")) == ("BLOCK", 0)


@pytest.mark.parametrize("bad", ["read", b"read", [1], {"a", 2}])
def test_item10_allowed_actions_must_be_a_collection_of_str(bad):
    with pytest.raises(TypeError):
        ExecutionSafetyGate(bad)


# ---------------------------------------------------------------- item 13: judge endpoint is not echoed in errors
from types import SimpleNamespace

from app import ambient
from ola_pipeline.errors import OlaPipelineError


def test_item13_the_judge_host_is_not_echoed_to_the_caller_or_the_chain(monkeypatch):
    def failing(cfg):
        raise OlaPipelineError("cannot reach http://user:pw@ollama-prod.internal.corp.example:11434/api/chat (refused)")
    monkeypatch.setattr(ambient, "build_provider", failing)
    cfg = SimpleNamespace(igor=SimpleNamespace(provider="ollama-local", model="m"))
    j = ambient._judge("task", "output", cfg, None)
    blob = json.dumps(j)
    assert "internal.corp" not in blob and "pw@" not in blob and "<url>" in j["detail"], j["detail"]
    assert "OlaPipelineError" in j["detail"]


# ---------------------------------------------------------------- item 14: approval reason is a bounded string
def test_item14_the_approval_reason_is_bounded_and_must_be_a_string(monkeypatch):
    monkeypatch.setenv("OLA_SOURCE_COMMIT", "abc1234")
    from app.models import ApiKey
    tenant, req = make_tenant()
    appr = "k-" + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(ApiKey(id=str(uuid.uuid4()), tenant_id=tenant, key_hash=hashlib.sha256(appr.encode()).hexdigest()))
        db.commit()
    c = TestClient(app, raise_server_exceptions=False)
    run = c.post("/nina-run", headers={"X-API-Key": req}, json={"task": "Calculate 1+1"}).json()

    def approve(reason):
        return c.post(f"/nina-run/{run['run_id']}/approve", headers={"Authorization": f"Bearer {appr}"},
                      json={"tip_hash": run["tip_hash"], "reason": reason})
    assert approve("A" * 1001).status_code == 400
    assert approve({"a": 1}).status_code == 400
    assert approve(["x"]).status_code == 400
    ok = approve("looked at the evidence")
    assert ok.status_code == 200, ok.text[:200]


# ---------------------------------------------------------------- item 8: /agent-run tells the judge which model produced the output
from app import main as main_mod


def test_item8_agent_producer_is_the_last_real_llm_model():
    steps = [{"invocation_type": "local_deterministic_model", "model": "deterministic-runtime-v1"},
             {"invocation_type": "real_llm", "model": "m-a"}, {"invocation_type": "real_llm", "model": "m-b"},
             {"invocation_type": "local_deterministic_model", "model": "deterministic-runtime-v1"}]
    assert main_mod._agent_producer({"execution": steps}) == "m-b"
    assert main_mod._agent_producer({"execution": steps[:1]}) is None
    assert main_mod._agent_producer({"execution": "x"}) is None and main_mod._agent_producer({}) is None


def test_item8_agent_run_passes_the_producer_to_the_ambient_judge(monkeypatch):
    seen = {}
    monkeypatch.setattr(main_mod, "_ambient_mode", lambda: "enforce")
    monkeypatch.setattr(main_mod, "run_agent_task", lambda tid, task: {
        "status": "VERIFIED", "final_result": "4", "execution": [{"invocation_type": "real_llm", "model": "same-model"}]})

    def fake_apply(amb, background, tenant_id, surface, task, output, response, produced_by):
        seen["produced_by"] = produced_by
        return response
    monkeypatch.setattr(main_mod, "_ambient_apply", fake_apply)
    _, key = make_tenant()
    r = TestClient(app).post("/agent-run", headers={"X-API-Key": key}, json={"task": "Calculate 2+2"})
    assert r.status_code == 200 and seen["produced_by"] == "same-model", (r.status_code, seen)
