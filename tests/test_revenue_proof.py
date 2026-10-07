"""Revenue proof: "first paid customer" is a computation over records, not a flag.

docs/revenue-marketing-flow.md says the status stays NOT PROVEN until a live payment is observed end to end, and that a
sandbox payment is never promoted to revenue. These tests drive the real webhook, the real /payment-success and the real
chain, and check that revenue_proof() says PROVEN only when every step is in the records, and names the missing step
otherwise. The evidence did not carry Stripe's `livemode` before: a test payment and a live one were indistinguishable."""
import hashlib
import hmac
import json
import time
import types
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text

from app import main
from app import stripe_webhook as sw
from app.database import SessionLocal, install_append_only_triggers
from app.hashchain import canonical_json
from app.main import app, append_record
from app.models import ApiKey, EvidenceRecord, StripeEvent, Tenant
from app.revenue_proof import NOT_OBSERVABLE, STEPS, revenue_proof

WHSEC = "whsec_proof"
OMIT = object()                                  # the key is not in the JSON at all
client = TestClient(app, raise_server_exceptions=False)
PERFORMED_OK = {"status": "VERIFIED", "computation": "PERFORMED", "final_result": "4", "evidence_ids": []}


def make_tenant():
    tenant_id, raw = str(uuid.uuid4()), "proof-" + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="proof"))
        db.add(ApiKey(id=str(uuid.uuid4()), tenant_id=tenant_id, key_hash=hashlib.sha256(raw.encode()).hexdigest()))
        db.commit()
    return tenant_id, raw


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", WHSEC)
    state = types.SimpleNamespace(result=dict(PERFORMED_OK), sessions={}, calls=[])

    def run(tenant_id, task):
        state.calls.append(task)
        return dict(state.result, run_id="run-" + uuid.uuid4().hex)

    monkeypatch.setattr(sw, "run_agent_task", run)
    monkeypatch.setattr(main, "retrieve_checkout", lambda session_id: state.sessions[session_id])
    return state


def _session(tenant_id, live=True, **over):
    session = {"id": "cs_" + uuid.uuid4().hex, "payment_status": "paid", "status": "complete", "amount_total": 9900,
               "currency": "eur", "metadata": {"offer": sw.OLA_OFFER, "product": sw.OLA_PRODUCT,
                                               "task": "calculate 2 + 2", "tenant_id": tenant_id}}
    if live is not OMIT:
        session["livemode"] = live
    session.update(over)
    return session


def _deliver(env, session, event_live=OMIT):
    event = {"id": "evt_" + uuid.uuid4().hex, "type": "checkout.session.completed", "data": {"object": session}}
    if event_live is not OMIT:
        event["livemode"] = event_live
    body = json.dumps(event).encode()
    ts = int(time.time())
    sig = hmac.new(WHSEC.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    env.sessions[session["id"]] = session
    return client.post("/stripe/webhook", content=body, headers={"Stripe-Signature": f"t={ts},v1={sig}",
                                                                  "Content-Type": "application/json"})


def _paid(env, tenant_id, live=True, event_live=None, serve=True, **over):
    """One paid session through the real webhook, then (optionally) served through the real /payment-success.
    `event_live=None` means: the event carries the same livemode as the session."""
    session = _session(tenant_id, live=live, **over)
    response = _deliver(env, session, event_live=live if event_live is None else event_live)
    assert response.status_code == 200 and response.json()["status"] == "COMPLETED", response.text[:300]
    if serve:
        assert main.payment_success(session["id"])["status"] == "COMPLETED"
    return session


def _rows(tenant_id, record_type):
    with SessionLocal() as db:
        rows = db.scalars(select(EvidenceRecord).where(EvidenceRecord.tenant_id == tenant_id,
                                                       EvidenceRecord.record_type == record_type)
                          .order_by(EvidenceRecord.seq))
        return [(row.id, json.loads(row.payload_json)) for row in rows]


def _only(proof):
    assert len(proof["sessions"]) == 1, proof
    return proof["sessions"][0]


# ------------------------------------------------------------------ the whole chain of steps
def test_a_live_paid_executed_and_served_session_is_proven(env):
    tenant_id, _ = make_tenant()
    session = _paid(env, tenant_id)
    proof = revenue_proof(tenant_id)
    assert proof["status"] == "PROVEN" and proof["missing"] == []
    assert proof["chain"]["valid"] is True and proof["chain"]["records"] >= 3
    assert proof["counts"] == {"paid_sessions": 1, "live": 1, "test": 0, "mode_unknown": 0, "proven": 1}
    one = _only(proof)
    assert one["session_id"] == session["id"] and one["payment_mode"] == "LIVE" and one["status"] == "PROVEN"
    assert one["steps"] == {name: True for name in STEPS} and one["missing"] == []


def test_a_proof_never_hides_what_it_cannot_see(env):
    """PROVEN is not read as more than it is: the three things no record can show are always listed."""
    tenant_id, _ = make_tenant()
    _paid(env, tenant_id)
    proof = revenue_proof(tenant_id)
    assert proof["status"] == "PROVEN"
    assert [item["step"] for item in proof["not_observable"]] == ["PUBLIC_HTTPS_WEBHOOK", "CUSTOMER_RECEIPT", "INDEPENDENT_JUDGE"]
    assert all(item["reason"] for item in proof["not_observable"]) and len(NOT_OBSERVABLE) == 3
    proof["not_observable"][0]["reason"] = "changed"                        # a caller cannot edit the module's text
    assert revenue_proof(tenant_id)["not_observable"][0]["reason"] != "changed"


def test_an_empty_tenant_has_no_paid_session_and_nothing_is_proven():
    tenant_id, _ = make_tenant()
    proof = revenue_proof(tenant_id)
    assert proof["status"] == "NOT_PROVEN" and proof["missing"] == ["PAID_SESSION"] and proof["sessions"] == []
    assert proof["counts"] == {"paid_sessions": 0, "live": 0, "test": 0, "mode_unknown": 0, "proven": 0}
    assert proof["chain"] == {"valid": True, "reason": "ok", "records": 0}


# ------------------------------------------------------------------ a sandbox payment is never revenue
@pytest.mark.parametrize("live, mode", [(False, "TEST"), (None, "UNKNOWN"), ("true", "UNKNOWN"), (1, "UNKNOWN"),
                                        (0, "UNKNOWN"), ("", "UNKNOWN"), (OMIT, "UNKNOWN")], ids=repr)
def test_only_an_explicit_true_livemode_counts_as_a_live_payment(env, live, mode):
    tenant_id, _ = make_tenant()
    _paid(env, tenant_id, live=live)
    proof = revenue_proof(tenant_id)
    one = _only(proof)
    assert proof["status"] == "NOT_PROVEN" and proof["missing"] == ["LIVE_PAYMENT"]
    assert one["payment_mode"] == mode and one["missing"] == ["LIVE_PAYMENT"]
    assert {name for name, ok in one["steps"].items() if not ok} == {"LIVE_PAYMENT"}      # everything else did happen
    key = {"TEST": "test", "UNKNOWN": "mode_unknown"}[mode]
    assert proof["counts"][key] == 1 and proof["counts"]["live"] == 0 and proof["counts"]["proven"] == 0


@pytest.mark.parametrize("event_live, session_live, recorded", [
    (True, True, True), (False, False, False),
    (True, OMIT, True), (OMIT, True, True), (False, OMIT, False), (OMIT, False, False),     # one source is enough
    (True, False, None), (False, True, None),                                               # two sources that disagree
    ("true", True, None), (True, "true", None), (1, True, None), (None, True, None),         # one of them is not a boolean
    (OMIT, OMIT, None)], ids=repr)
def test_the_livemode_the_evidence_records(env, event_live, session_live, recorded):
    tenant_id, _ = make_tenant()
    session = _session(tenant_id, live=session_live)
    assert _deliver(env, session, event_live=event_live).status_code == 200
    (_, payload), = _rows(tenant_id, "stripe.payment_confirmed")
    assert "livemode" in payload and payload["livemode"] is recorded
    assert sw.stripe_livemode({"livemode": event_live} if event_live is not OMIT else {},
                              {"livemode": session_live} if session_live is not OMIT else {}) is recorded


def test_a_live_event_for_a_test_session_is_not_a_live_payment(env):
    tenant_id, _ = make_tenant()
    _paid(env, tenant_id, live=False, event_live=True)
    assert _only(revenue_proof(tenant_id))["payment_mode"] == "UNKNOWN"


def test_a_payment_recorded_before_livemode_existed_is_mode_unknown_never_live(env):
    """Chains written by an older version carry no `livemode` key at all."""
    tenant_id, _ = make_tenant()
    session_id, run_id = "cs_" + uuid.uuid4().hex, "run-" + uuid.uuid4().hex
    old = {"stripe_event_id": "evt_old", "checkout_session_id": session_id, "offer": sw.OLA_OFFER, "product": sw.OLA_PRODUCT,
           "amount_total": 9900, "currency": "eur", "task": "calculate 2 + 2", "retry_of_failed_attempt": False}
    payment_id = append_record(tenant_id, "stripe.payment_confirmed", old)["id"]
    done = {"stripe_event_id": "evt_old", "checkout_session_id": session_id, "ola_run_id": run_id, "ola_status": "VERIFIED",
            "computation": "PERFORMED", "ola_final_result": "4", "payment_evidence_id": payment_id}
    append_record(tenant_id, "stripe.ola_execution_completed", done)
    result = {"status": "COMPLETED", "event_id": "evt_old", "checkout_session_id": session_id, "payment": "CONFIRMED",
              "ola_status": "VERIFIED", "computation": "PERFORMED", "ola_run_id": run_id, "ola_final_result": "4",
              "payment_evidence_id": payment_id, "ola_evidence_ids": []}
    with SessionLocal() as db:
        db.add(StripeEvent(id=str(uuid.uuid4()), event_id="evt_old_" + uuid.uuid4().hex, status="COMPLETED", run_id=run_id,
                           task="calculate 2 + 2", result_json=canonical_json(result), checkout_session_id=session_id,
                           payment_evidence_id=payment_id))
        db.commit()
    proof = revenue_proof(tenant_id)
    assert _only(proof)["payment_mode"] == "UNKNOWN" and proof["status"] == "NOT_PROVEN"
    assert _only(proof)["steps"]["LIVE_PAYMENT"] is False


# ------------------------------------------------------------------ the run must have been work, and verified work
@pytest.mark.parametrize("runtime, missing", [
    ({"status": "UNKNOWN", "computation": "NOT_PERFORMED"}, ["RUN_PERFORMED", "RUN_VERIFIED"]),
    ({"status": "UNKNOWN", "computation": "PERFORMED"}, ["RUN_VERIFIED"]),
    ({"status": "VERIFIED", "computation": "NOT_PERFORMED"}, ["RUN_PERFORMED"]),
    ({"status": "BLOCK", "computation": "PERFORMED"}, ["RUN_VERIFIED"])], ids=lambda v: repr(v) if isinstance(v, list) else v["status"] + "-" + v["computation"])
def test_a_live_payment_whose_run_computed_nothing_or_was_not_verified_is_not_proven(env, runtime, missing):
    tenant_id, _ = make_tenant()
    env.result = dict(PERFORMED_OK, **runtime)
    _paid(env, tenant_id)
    proof = revenue_proof(tenant_id)
    assert proof["status"] == "NOT_PROVEN" and _only(proof)["missing"] == missing and proof["missing"] == missing


# ------------------------------------------------------------------ the result must have been served, as stored
def test_a_run_that_was_never_served_is_not_proven_until_it_is(env):
    tenant_id, _ = make_tenant()
    session = _paid(env, tenant_id, serve=False)
    proof = revenue_proof(tenant_id)
    assert proof["status"] == "NOT_PROVEN" and proof["missing"] == ["RESULT_SERVED"]
    assert main.payment_success(session["id"])["status"] == "COMPLETED"
    assert revenue_proof(tenant_id)["status"] == "PROVEN"


def test_serving_the_same_result_again_writes_nothing_more(env):
    tenant_id, _ = make_tenant()
    session = _paid(env, tenant_id)
    for _ in range(4):
        assert main.payment_success(session["id"])["status"] == "COMPLETED"
    assert len(_rows(tenant_id, "revenue.result_served")) == 1


def test_the_served_record_carries_the_digest_of_the_result_the_webhook_stored(env):
    tenant_id, _ = make_tenant()
    session = _paid(env, tenant_id)
    (_, served), = _rows(tenant_id, "revenue.result_served")
    with SessionLocal() as db:
        row = db.scalar(select(StripeEvent).where(StripeEvent.checkout_session_id == session["id"]))
    stored = json.loads(row.result_json)
    assert served == {"session_id": session["id"], "run_id": row.run_id,
                      "result_sha256": hashlib.sha256(canonical_json(stored).encode()).hexdigest()}
    assert stored["ola_run_id"] == row.run_id


@pytest.mark.parametrize("forge", ["other_run", "other_digest", "other_session"])
def test_a_served_record_that_does_not_match_the_run_does_not_count(env, forge):
    tenant_id, _ = make_tenant()
    session = _paid(env, tenant_id, serve=False)
    with SessionLocal() as db:
        row = db.scalar(select(StripeEvent).where(StripeEvent.checkout_session_id == session["id"]))
    digest = hashlib.sha256(canonical_json(json.loads(row.result_json)).encode()).hexdigest()
    payload = {"session_id": session["id"], "run_id": row.run_id, "result_sha256": digest}
    payload.update({"other_run": {"run_id": "run-someone-else"}, "other_digest": {"result_sha256": "0" * 64},
                    "other_session": {"session_id": "cs_other"}}[forge])
    append_record(tenant_id, "revenue.result_served", payload)
    proof = revenue_proof(tenant_id)
    assert proof["status"] == "NOT_PROVEN" and proof["missing"] == ["RESULT_SERVED"]
    append_record(tenant_id, "revenue.result_served", {"session_id": session["id"], "run_id": row.run_id, "result_sha256": digest})
    assert revenue_proof(tenant_id)["status"] == "PROVEN"                  # the right row, after the wrong one, counts


def test_a_result_that_was_changed_after_it_was_served_is_no_longer_proven(env):
    tenant_id, _ = make_tenant()
    session = _paid(env, tenant_id)
    with SessionLocal() as db:
        row = db.scalar(select(StripeEvent).where(StripeEvent.checkout_session_id == session["id"]))
        changed = json.loads(row.result_json)
        changed["ola_final_result"] = "5"
        row.result_json = canonical_json(changed)
        db.commit()
    proof = revenue_proof(tenant_id)
    assert proof["status"] == "NOT_PROVEN" and proof["missing"] == ["RESULT_SERVED"]


def test_nothing_is_served_for_a_session_that_is_not_complete_or_not_bound(env):
    tenant_id, _ = make_tenant()
    pending = _session(tenant_id)                                           # paid, but the webhook has not run
    env.sessions[pending["id"]] = pending
    assert main.payment_success(pending["id"])["status"] == "PAYMENT_CONFIRMED_EXECUTION_PENDING"
    unpaid = _session(tenant_id, payment_status="unpaid", status="open")
    env.sessions[unpaid["id"]] = unpaid
    assert main.payment_success(unpaid["id"])["status"] == "AWAITING_PAYMENT"
    assert _rows(tenant_id, "revenue.result_served") == []


# ------------------------------------------------------------------ the webhook row and the records must agree
def _change_row(session_id, **values):
    with SessionLocal() as db:
        row = db.scalar(select(StripeEvent).where(StripeEvent.checkout_session_id == session_id))
        for key, value in values.items():
            setattr(row, key, value)
        db.commit()


@pytest.mark.parametrize("values", [{"status": "FAILED"}, {"status": "PROCESSING"}, {"payment_evidence_id": "someone-elses"},
                                    {"payment_evidence_id": None}, {"run_id": "run-other"}, {"run_id": None},
                                    {"result_json": "not json"}, {"result_json": "[]"}, {"result_json": None}],
                         ids=lambda v: ",".join(f"{k}={v[k]}" for k in v))
def test_a_webhook_row_that_disagrees_with_the_records_proves_nothing(env, values):
    tenant_id, _ = make_tenant()
    session = _paid(env, tenant_id)
    _change_row(session["id"], **values)
    proof = revenue_proof(tenant_id)
    assert proof["status"] == "NOT_PROVEN"
    assert "OBSERVED_WEBHOOK" in proof["missing"] or "EVIDENCE_BOUND" in proof["missing"]
    assert "RESULT_SERVED" in proof["missing"]                              # it rests on the bound result


def test_a_missing_webhook_row_proves_nothing(env):
    tenant_id, _ = make_tenant()
    session = _paid(env, tenant_id)
    with SessionLocal() as db:
        db.execute(text("DELETE FROM stripe_events WHERE checkout_session_id = :s"), {"s": session["id"]})
        db.commit()
    proof = revenue_proof(tenant_id)
    assert proof["missing"] == ["OBSERVED_WEBHOOK", "EVIDENCE_BOUND", "RESULT_SERVED"]


def test_the_event_id_of_the_row_must_be_the_event_id_of_the_payment(env):
    tenant_id, _ = make_tenant()
    session = _paid(env, tenant_id)
    _change_row(session["id"], event_id="evt_not_the_one_in_the_evidence")
    assert revenue_proof(tenant_id)["missing"] == ["EVIDENCE_BOUND", "RESULT_SERVED"]


def test_a_result_for_another_session_or_run_is_not_the_bound_result(env):
    tenant_id, _ = make_tenant()
    for field in ("checkout_session_id", "payment_evidence_id", "ola_run_id"):
        session = _paid(env, tenant_id, serve=False)
        with SessionLocal() as db:
            row = db.scalar(select(StripeEvent).where(StripeEvent.checkout_session_id == session["id"]))
            changed = json.loads(row.result_json)
            changed[field] = "other"
            row.result_json = canonical_json(changed)
            db.commit()
    proofs = [item for item in revenue_proof(tenant_id)["sessions"]]
    assert len(proofs) == 3 and all("EVIDENCE_BOUND" in item["missing"] for item in proofs)


def test_an_execution_record_that_points_at_another_payment_is_not_this_payments_execution(env):
    tenant_id, _ = make_tenant()
    first = _paid(env, tenant_id, serve=False)
    (payment_id, _), = _rows(tenant_id, "stripe.payment_confirmed")
    (_, execution), = _rows(tenant_id, "stripe.ola_execution_completed")
    other = _paid(env, tenant_id, serve=False)
    proofs = {item["session_id"]: item for item in revenue_proof(tenant_id)["sessions"]}
    assert set(proofs) == {first["id"], other["id"]}
    assert all(item["steps"]["EVIDENCE_BOUND"] for item in proofs.values())
    assert execution["payment_evidence_id"] == payment_id
    forged = dict(execution, checkout_session_id=other["id"])               # execution of the first payment, claimed for the other
    append_record(tenant_id, "stripe.ola_execution_completed", forged)
    again = {item["session_id"]: item for item in revenue_proof(tenant_id)["sessions"]}
    assert again[other["id"]]["steps"] == proofs[other["id"]]["steps"]      # its own execution still wins; the forged row binds nothing


# ------------------------------------------------------------------ several sessions, several tenants
def test_one_proven_session_among_sandbox_ones_is_a_proof_and_the_counts_say_which(env):
    tenant_id, _ = make_tenant()
    sandbox = _paid(env, tenant_id, live=False)
    unknown = _paid(env, tenant_id, live=OMIT, event_live=OMIT)
    live = _paid(env, tenant_id, live=True)
    proof = revenue_proof(tenant_id)
    assert proof["status"] == "PROVEN" and proof["missing"] == []
    assert proof["counts"] == {"paid_sessions": 3, "live": 1, "test": 1, "mode_unknown": 1, "proven": 1}
    assert [item["session_id"] for item in proof["sessions"]] == [sandbox["id"], unknown["id"], live["id"]]
    assert [item["status"] for item in proof["sessions"]] == ["NOT_PROVEN", "NOT_PROVEN", "PROVEN"]


def test_sandbox_payments_alone_never_become_a_proof_however_many_there_are(env):
    tenant_id, _ = make_tenant()
    for _ in range(3):
        _paid(env, tenant_id, live=False)
    proof = revenue_proof(tenant_id)
    assert proof["status"] == "NOT_PROVEN" and proof["counts"]["test"] == 3 and proof["counts"]["proven"] == 0


def test_when_nothing_is_proven_the_report_names_what_is_left_on_the_closest_session(env):
    tenant_id, _ = make_tenant()
    _paid(env, tenant_id, live=False, serve=False)                           # two things missing: LIVE_PAYMENT, RESULT_SERVED
    _paid(env, tenant_id, live=False)                                        # one thing missing: LIVE_PAYMENT
    assert revenue_proof(tenant_id)["missing"] == ["LIVE_PAYMENT"]


def test_a_live_payment_of_another_tenant_is_not_this_tenants_proof(env):
    one, _ = make_tenant()
    two, _ = make_tenant()
    _paid(env, one)
    assert revenue_proof(one)["status"] == "PROVEN"
    other = revenue_proof(two)
    assert other["status"] == "NOT_PROVEN" and other["sessions"] == [] and other["missing"] == ["PAID_SESSION"]


# ------------------------------------------------------------------ a chain that does not verify proves nothing
def test_a_broken_chain_is_never_a_proof(env):
    tenant_id, _ = make_tenant()
    _paid(env, tenant_id)
    assert revenue_proof(tenant_id)["status"] == "PROVEN"
    with SessionLocal() as db:
        db.execute(text("DROP TRIGGER IF EXISTS evidence_no_update"))
        db.execute(text("UPDATE evidence_records SET payload_json = payload_json || ' ' WHERE tenant_id = :t AND seq = 0"),
                   {"t": tenant_id})
        db.commit()
    try:
        proof = revenue_proof(tenant_id)
        assert proof["status"] == "NOT_PROVEN" and proof["missing"] == ["EVIDENCE_CHAIN_VALID"]
        assert proof["chain"]["valid"] is False and proof["chain"]["reason"] != "ok"
        assert proof["sessions"] == [] and proof["counts"]["paid_sessions"] == 0
    finally:
        install_append_only_triggers()


# ------------------------------------------------------------------ the endpoint
def test_the_endpoint_needs_a_key_and_answers_for_that_tenant_only(env):
    tenant_id, key = make_tenant()
    other_id, other_key = make_tenant()
    _paid(env, tenant_id)
    assert client.get("/revenue/proof").status_code == 401
    assert client.get("/revenue/proof", headers={"X-API-Key": "nope"}).status_code == 401
    mine = client.get("/revenue/proof", headers={"X-API-Key": key})
    assert mine.status_code == 200 and mine.json() == revenue_proof(tenant_id) and mine.json()["status"] == "PROVEN"
    theirs = client.get("/revenue/proof", headers={"X-API-Key": other_key})
    assert theirs.status_code == 200 and theirs.json()["status"] == "NOT_PROVEN" and theirs.json()["sessions"] == []
    assert mine.headers.get("x-content-type-options") == "nosniff"          # it goes through the same guard as every route


def test_a_record_type_with_this_name_cannot_be_written_by_a_caller(env):
    """revenue.result_served is evidence of the server's own act: POST /evidence refuses dotted types."""
    tenant_id, key = make_tenant()
    response = client.post("/evidence", headers={"X-API-Key": key},
                           json={"record_type": "revenue.result_served", "payload": {"session_id": "cs_x", "run_id": "r"}})
    assert response.status_code == 400 and _rows(tenant_id, "revenue.result_served") == []


# ------------------------------------------------------------------ records written straight into the chain
def _synth(tenant_id, *, session_id=None, payments=(None,), exec_over=None, exec_first=None, row_over=None):
    """A paid session built record by record, to test what the proof does with records the webhook would not write.
    `payments`: livemode values, one payment record each, in order. Returns (session_id, [payment evidence ids])."""
    session_id = session_id or "cs_" + uuid.uuid4().hex
    event_id, run_id = "evt_" + uuid.uuid4().hex, "run-" + uuid.uuid4().hex
    ids = []
    for live in payments:
        payload = {"checkout_session_id": session_id, "stripe_event_id": event_id}
        if live is not OMIT:
            payload["livemode"] = live
        ids.append(append_record(tenant_id, "stripe.payment_confirmed", payload)["id"])
    if exec_first:
        append_record(tenant_id, "stripe.ola_execution_completed", dict(exec_first, checkout_session_id=session_id))
    execution = {"checkout_session_id": session_id, "stripe_event_id": event_id, "payment_evidence_id": ids[0],
                 "ola_run_id": run_id, "computation": "PERFORMED", "ola_status": "VERIFIED"}
    execution.update(exec_over or {})
    append_record(tenant_id, "stripe.ola_execution_completed", execution)
    result = {"checkout_session_id": session_id, "payment_evidence_id": ids[0], "ola_run_id": run_id}
    digest = hashlib.sha256(canonical_json(result).encode()).hexdigest()
    append_record(tenant_id, "revenue.result_served", {"session_id": session_id, "run_id": run_id, "result_sha256": digest})
    row = dict(id=str(uuid.uuid4()), event_id=event_id, status="COMPLETED", run_id=run_id, checkout_session_id=session_id,
               payment_evidence_id=ids[0], result_json=canonical_json(result))
    row.update(row_over or {})
    with SessionLocal() as db:
        db.add(StripeEvent(**row))
        db.commit()
    return session_id, ids


def test_the_synthetic_session_is_proven_so_the_negative_cases_below_fail_for_one_reason_only():
    tenant_id, _ = make_tenant()
    _synth(tenant_id, payments=(True,))
    assert revenue_proof(tenant_id)["status"] == "PROVEN"


@pytest.mark.parametrize("live", ["true", 1, "yes", [True]], ids=repr)
def test_a_truthy_but_not_boolean_livemode_written_into_the_chain_is_not_live(live):
    tenant_id, _ = make_tenant()
    _synth(tenant_id, payments=(live,))
    one = _only(revenue_proof(tenant_id))
    assert one["payment_mode"] == "UNKNOWN" and one["missing"] == ["LIVE_PAYMENT"]


def test_the_first_payment_record_of_a_session_decides_its_mode_a_later_live_one_does_not_upgrade_it():
    tenant_id, _ = make_tenant()
    _synth(tenant_id, payments=(False, True))
    one = _only(revenue_proof(tenant_id))
    assert one["payment_mode"] == "TEST" and "LIVE_PAYMENT" in one["missing"]


def test_an_execution_of_a_different_payment_recorded_first_does_not_stand_in_for_this_one():
    tenant_id, _ = make_tenant()
    _synth(tenant_id, payments=(True,), exec_first={"payment_evidence_id": "someone-else", "stripe_event_id": "evt_x",
                                                    "ola_run_id": "run-x", "computation": "PERFORMED", "ola_status": "VERIFIED"})
    one = _only(revenue_proof(tenant_id))
    assert one["status"] == "PROVEN"                                         # the matching execution is the one used


def test_an_execution_that_names_another_stripe_event_is_not_bound_to_the_payment():
    tenant_id, _ = make_tenant()
    _synth(tenant_id, payments=(True,), exec_over={"stripe_event_id": "evt_other"})
    one = _only(revenue_proof(tenant_id))
    assert one["missing"] == ["EVIDENCE_BOUND", "RESULT_SERVED"]


# ------------------------------------------------------------------ the CLI
def test_cli_exits_3_without_a_proof_and_0_with_one(env, capsys):
    import importlib.util
    spec = importlib.util.spec_from_file_location("revenue_proof_cli", "scripts/revenue_proof.py")
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    tenant_id, _ = make_tenant()
    _paid(env, tenant_id, live=False)
    assert cli.main(["--tenant", tenant_id]) == 3
    assert json.loads(capsys.readouterr().out)["proven"] == []
    _paid(env, tenant_id, live=True)
    assert cli.main(["--tenant", tenant_id]) == 0
    assert json.loads(capsys.readouterr().out)["proven"] == [tenant_id]
