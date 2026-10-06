"""Stripe strictness: what a SIGNED event may say about the money, and what a poll of /payment-success may write.

Two limits were stated in docs/pipeline-bridge.md ("Not fixed"): `amount_total: 9900.0` was accepted (9900.0 == 9900 in
Python, while Stripe sends an integer number of cents) and so was a session with no `status` at all (only a value other than
"complete" was refused), and `/payment-success` appended one `revenue.payment_blocked` row per poll for a session that is
PAID but not for this offer, so anyone holding a session id could grow that tenant's chain without bound. A valid signature
is required for the first; the second needs no secret, only an id."""
import hashlib
import hmac
import json
import time
import uuid

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import main
from app import stripe_webhook as sw
from app.database import SessionLocal
from app.main import app
from app.models import ApiKey, EvidenceRecord, StripeEvent, Tenant

WHSEC = "whsec_strict"
client = TestClient(app, raise_server_exceptions=False)


def make_tenant():
    tenant_id = str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="strict"))
        db.add(ApiKey(id=str(uuid.uuid4()), tenant_id=tenant_id,
                      key_hash=hashlib.sha256(("strict-" + uuid.uuid4().hex).encode()).hexdigest()))
        db.commit()
    return tenant_id


def _session(tenant_id, **over):
    session = {"id": "cs_" + uuid.uuid4().hex, "payment_status": "paid", "status": "complete", "amount_total": 9900,
               "currency": "eur", "metadata": {"offer": sw.OLA_OFFER, "product": sw.OLA_PRODUCT,
                                               "task": "calculate 2 + 2", "tenant_id": tenant_id}}
    session.update(over)
    return session


def _post(session, event_id=None):
    event = {"id": event_id or "evt_" + uuid.uuid4().hex, "type": "checkout.session.completed", "data": {"object": session}}
    body = json.dumps(event).encode()
    ts = int(time.time())
    sig = hmac.new(WHSEC.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return client.post("/stripe/webhook", content=body, headers={"Stripe-Signature": f"t={ts},v1={sig}",
                                                                  "Content-Type": "application/json"}), event["id"]


@pytest.fixture
def stripe_env(monkeypatch):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", WHSEC)
    calls = []

    def run(tenant_id, task):
        calls.append(task)
        return {"status": "VERIFIED", "computation": "PERFORMED", "run_id": "run-" + uuid.uuid4().hex,
                "final_result": "4", "evidence_ids": []}

    monkeypatch.setattr(sw, "run_agent_task", run)
    monkeypatch.calls = calls
    return monkeypatch


def _evidence(tenant_id, record_type=None):
    with SessionLocal() as db:
        query = select(EvidenceRecord).where(EvidenceRecord.tenant_id == tenant_id)
        if record_type:
            query = query.where(EvidenceRecord.record_type == record_type)
        return [json.loads(row.payload_json) for row in db.scalars(query.order_by(EvidenceRecord.seq))]


def _stripe_rows(event_id):
    with SessionLocal() as db:
        return db.scalars(select(StripeEvent).where(StripeEvent.event_id == event_id)).all()


# ------------------------------------------------------------------ the amount is an integer number of cents
@pytest.mark.parametrize("amount", [9900.0, 9900.00, 9899, 9901, 99, "9900", None, [9900], {"v": 9900}, False],
                         ids=repr)
def test_only_the_integer_9900_is_the_price(amount):
    session = _session("tenant-x", amount_total=amount)
    with pytest.raises(HTTPException) as caught:
        sw._validate_checkout(session)
    assert caught.value.status_code == 400 and "amount" in caught.value.detail


def test_the_integer_9900_is_still_accepted():
    assert sw._validate_checkout(_session("tenant-x")) == "calculate 2 + 2"


def test_a_signed_event_with_a_float_amount_starts_no_run_and_stores_nothing(stripe_env):
    tenant_id = make_tenant()
    session = _session(tenant_id, amount_total=9900.0)
    response, event_id = _post(session)
    assert response.status_code == 400 and "amount" in response.json()["detail"], response.text[:200]
    assert stripe_env.calls == [] and _stripe_rows(event_id) == [] and _evidence(tenant_id) == []


# ------------------------------------------------------------------ "complete" must be said, not merely not contradicted
@pytest.mark.parametrize("status", ["__missing__", None, "", "open", "expired", "Complete", "completed", 1, True],
                         ids=repr)
def test_a_paid_session_is_confirmed_only_when_its_status_says_complete(status):
    session = _session("tenant-x")
    if status == "__missing__":
        del session["status"]
    else:
        session["status"] = status
    with pytest.raises(HTTPException) as caught:
        sw._validate_checkout(session)
    assert caught.value.status_code == 400 and "not confirmed" in caught.value.detail


def test_an_asynchronous_session_is_still_valid_while_unpaid_when_complete():
    session = _session("tenant-x", payment_status="unpaid")
    assert sw._validate_checkout(session, allow_unpaid=True) == "calculate 2 + 2"
    del session["status"]
    with pytest.raises(HTTPException):
        sw._validate_checkout(session, allow_unpaid=True)


def test_a_signed_event_without_a_status_starts_no_run_and_stores_nothing(stripe_env):
    tenant_id = make_tenant()
    session = _session(tenant_id)
    del session["status"]
    response, event_id = _post(session)
    assert response.status_code == 400 and "not confirmed" in response.json()["detail"], response.text[:200]
    assert stripe_env.calls == [] and _stripe_rows(event_id) == [] and _evidence(tenant_id) == []


def test_a_well_formed_event_still_runs_once(stripe_env):
    tenant_id = make_tenant()
    response, event_id = _post(_session(tenant_id))
    assert response.status_code == 200 and response.json()["status"] == "COMPLETED", response.text[:200]
    assert stripe_env.calls == ["calculate 2 + 2"] and [row.status for row in _stripe_rows(event_id)] == ["COMPLETED"]


# ------------------------------------------------------------------ a poll writes at most one row per distinct state
def _lookup(monkeypatch, session):
    monkeypatch.setattr(main, "retrieve_checkout", lambda requested: session)
    return main.payment_success(session["id"])


def _foreign(tenant_id, **over):
    session = _session(tenant_id, **over)
    session["metadata"]["offer"] = "someone-elses-offer"
    return session


def test_polling_a_paid_session_for_another_offer_writes_one_row_not_one_per_poll(monkeypatch):
    tenant_id = make_tenant()
    session = _foreign(tenant_id)
    for _ in range(5):                                     # no secret is needed: the session id is enough
        answer = _lookup(monkeypatch, session)
        assert answer["status"] == "BLOCK" and answer["reason"] == "payment not verified", answer
    rows = _evidence(tenant_id, "revenue.payment_blocked")
    assert len(rows) == 1, rows
    assert rows[0] == {"session_id": session["id"], "payment_status": "paid", "status": "complete"}


def test_a_new_state_of_the_same_session_is_a_new_fact_and_is_recorded(monkeypatch):
    tenant_id = make_tenant()
    first = _foreign(tenant_id)
    later = dict(first, payment_status="no_payment_required")      # the same id, Stripe now says something else
    for session in (first, first, later, later, first):
        assert _lookup(monkeypatch, session)["status"] == "BLOCK"
    rows = _evidence(tenant_id, "revenue.payment_blocked")
    assert [(r["payment_status"], r["status"]) for r in rows] == [("paid", "complete"), ("no_payment_required", "complete")]


@pytest.mark.parametrize("state", [{"payment_status": "paid", "status": "open"},
                                   {"payment_status": "unpaid", "status": "complete"},
                                   {"payment_status": "no_payment_required", "status": "complete"},
                                   {"payment_status": "paid", "status": "expired"}], ids=lambda s: f"{s['payment_status']}-{s['status']}")
def test_each_field_of_the_state_counts_not_only_the_first(monkeypatch, state):
    """A mutant that compares only one of the two fields would hide a change in the other."""
    tenant_id = make_tenant()
    base = _foreign(tenant_id)                                       # paid / complete
    other = dict(base, **state)
    for session in (base, other, base, other):
        _lookup(monkeypatch, session)
    rows = _evidence(tenant_id, "revenue.payment_blocked")
    assert sorted((r["payment_status"], r["status"]) for r in rows) == sorted([("paid", "complete"),
                                                                              (state["payment_status"], state["status"])])


def test_a_checkout_row_of_the_same_session_is_not_a_block_row(monkeypatch):
    """revenue.checkout_created carries the same session id; it must not make a block look recorded (the state fields of
    a session Stripe gave no state for are None on both sides, which is equal)."""
    from app.main import append_record
    tenant_id = make_tenant()
    session = _foreign(tenant_id)
    del session["payment_status"], session["status"]
    append_record(tenant_id, "revenue.checkout_created", {"session_id": session["id"], "task": "x", "amount": 9900})
    assert _lookup(monkeypatch, session)["status"] == "BLOCK"
    assert len(_evidence(tenant_id, "revenue.payment_blocked")) == 1


def test_a_session_id_that_contains_another_is_a_different_session(monkeypatch):
    tenant_id = make_tenant()
    longer = _foreign(tenant_id, id="cs_prefix_" + uuid.uuid4().hex)
    shorter = _foreign(tenant_id, id=longer["id"][:-3])               # a substring of the first id
    _lookup(monkeypatch, longer)
    _lookup(monkeypatch, shorter)
    assert sorted(r["session_id"] for r in _evidence(tenant_id, "revenue.payment_blocked")) == sorted([longer["id"], shorter["id"]])


def test_two_sessions_are_recorded_separately(monkeypatch):
    tenant_id = make_tenant()
    one, two = _foreign(tenant_id), _foreign(tenant_id)
    for session in (one, two, one, two):
        _lookup(monkeypatch, session)
    assert sorted(r["session_id"] for r in _evidence(tenant_id, "revenue.payment_blocked")) == sorted([one["id"], two["id"]])


def test_one_tenants_block_does_not_hide_anothers(monkeypatch):
    first, second = make_tenant(), make_tenant()
    shared_id = "cs_" + uuid.uuid4().hex
    for tenant_id in (first, second):
        _lookup(monkeypatch, _foreign(tenant_id, id=shared_id))
    assert len(_evidence(first, "revenue.payment_blocked")) == 1 and len(_evidence(second, "revenue.payment_blocked")) == 1


def test_the_chain_stays_valid_after_deduplicated_polls(monkeypatch):
    from app.hashchain import verify_chain
    tenant_id = make_tenant()
    session = _foreign(tenant_id)
    for _ in range(3):
        _lookup(monkeypatch, session)
    with SessionLocal() as db:
        rows = db.scalars(select(EvidenceRecord).where(EvidenceRecord.tenant_id == tenant_id).order_by(EvidenceRecord.seq)).all()
    chain = [{"tenant_id": r.tenant_id, "seq": r.seq, "prev_hash": r.prev_hash, "record_hash": r.record_hash,
              "record_type": r.record_type, "payload_json": r.payload_json} for r in rows]
    assert verify_chain(chain)[0] is True and len(chain) == 1


def test_an_unpaid_or_expired_poll_still_writes_nothing(monkeypatch):
    tenant_id = make_tenant()
    for state in ({"status": "open", "payment_status": "unpaid"}, {"status": "expired", "payment_status": "unpaid"}):
        _lookup(monkeypatch, _session(tenant_id, **state))
    assert _evidence(tenant_id) == []
