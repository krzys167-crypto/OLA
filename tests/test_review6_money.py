"""Sixth review, money paths: the Stripe webhook state machine, /payment-success, the invoice maths and its standalone
verifier, the safe-expression evaluator and the runtime verifier's verdict on a run that computed nothing."""
import hashlib
import hmac
import json
import os
import random
import sqlite3
import subprocess
import sys
import time
import uuid
from fractions import Fraction

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError, OperationalError

from app import agent_runtime as ar
from app import business_runtime as br
from app import main
from app import stripe_webhook as sw
from app.database import SessionLocal
from app.main import app
from app.migrations import migrate_stripe_events
from app.models import ApiKey, EvidenceRecord, StripeEvent, Tenant
from scripts import verify_agent_runtime as agent_verifier
from scripts import verify_business_invoice as invoice_verifier

DB_PATH = os.environ["OLA_EG_DB_PATH"]
WHSEC = "whsec_r6"
client = TestClient(app, raise_server_exceptions=False)


def make_tenant():
    tenant_id, key = str(uuid.uuid4()), "r6-" + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="r6"))
        db.add(ApiKey(id=str(uuid.uuid4()), tenant_id=tenant_id, key_hash=hashlib.sha256(key.encode()).hexdigest()))
        db.commit()
    return tenant_id, key


@pytest.fixture
def stripe_env(monkeypatch):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", WHSEC)
    return monkeypatch


# ------------------------------------------------------------------ helpers
def _headers(body: bytes) -> dict:
    ts = int(time.time())
    sig = hmac.new(WHSEC.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return {"Stripe-Signature": f"t={ts},v1={sig}", "Content-Type": "application/json"}


def _session(tenant_id, session_id=None, task="calculate 2 + 2", **over):
    session = {"id": session_id or "cs_" + uuid.uuid4().hex, "payment_status": "paid", "status": "complete",
               "amount_total": 9900, "currency": "eur",
               "metadata": {"offer": sw.OLA_OFFER, "product": sw.OLA_PRODUCT, "task": task, "tenant_id": tenant_id}}
    session.update(over)
    return session


def _event(tenant_id, event_id=None, etype="checkout.session.completed", session=None, **session_over):
    return {"id": event_id or "evt_" + uuid.uuid4().hex, "type": etype,
            "data": {"object": session if session is not None else _session(tenant_id, **session_over)}}


def _post(event):
    body = json.dumps(event).encode()
    return client.post("/stripe/webhook", content=body, headers=_headers(body))


def _post_raw(body: bytes):
    return client.post("/stripe/webhook", content=body, headers=_headers(body))


def _fake_runner(monkeypatch, computation="PERFORMED", status="VERIFIED"):
    calls = []

    def run(tenant_id, task):
        calls.append(task)
        return {"status": status, "computation": computation, "run_id": "run-" + uuid.uuid4().hex,
                "final_result": "4", "evidence_ids": []}

    monkeypatch.setattr(sw, "run_agent_task", run)
    return calls


def _rows(event_id):
    with SessionLocal() as db:
        return db.scalars(select(StripeEvent).where(StripeEvent.event_id == event_id)).all()


def _session_rows(session_id):
    with SessionLocal() as db:
        return db.scalars(select(StripeEvent).where(StripeEvent.checkout_session_id == session_id)).all()


def _evidence(tenant_id, record_type=None):
    with SessionLocal() as db:
        query = select(EvidenceRecord).where(EvidenceRecord.tenant_id == tenant_id)
        if record_type:
            query = query.where(EvidenceRecord.record_type == record_type)
        return [json.loads(row.payload_json) for row in db.scalars(query.order_by(EvidenceRecord.seq))]


def _insert_row(event_id, session_id, status, claimed_at, task="calculate 2 + 2", **extra):
    with SessionLocal() as db:
        db.add(StripeEvent(id=str(uuid.uuid4()), event_id=event_id, status=status, task=task, claimed_at=claimed_at,
                           checkout_session_id=session_id, **extra))
        db.commit()


def _age_lease(event_id, seconds):
    with SessionLocal() as db:
        row = db.scalar(select(StripeEvent).where(StripeEvent.event_id == event_id))
        row.claimed_at = row.claimed_at - seconds
        db.commit()


# ================================================================== schema migration
OLD_STRIPE_EVENTS = (
    "CREATE TABLE stripe_events (id VARCHAR(36) NOT NULL, event_id VARCHAR(255) NOT NULL, status VARCHAR(32) NOT NULL, "
    "run_id VARCHAR(36), task TEXT, result_json TEXT, PRIMARY KEY (id))")


def _old_database(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    done = json.dumps({"status": "COMPLETED", "checkout_session_id": "cs_done"})
    with engine.begin() as conn:
        conn.exec_driver_sql(OLD_STRIPE_EVENTS)
        conn.exec_driver_sql("CREATE UNIQUE INDEX ix_stripe_events_event_id ON stripe_events (event_id)")
        for row in [("1", "evt_done", "COMPLETED", "run-1", "t", done),
                    ("2", "evt_done_again", "COMPLETED", "run-2", "t", done),      # the old code could complete a session twice
                    ("3", "evt_stuck", "PROCESSING", None, "t", None),
                    ("4", "evt_failed", "FAILED", None, "t", None)]:
            conn.exec_driver_sql("INSERT INTO stripe_events (id, event_id, status, run_id, task, result_json) "
                                 "VALUES (?, ?, ?, ?, ?, ?)", row)
    return engine


def test_migration_upgrades_a_database_created_by_the_old_schema(tmp_path):
    engine = _old_database(tmp_path)
    changes = migrate_stripe_events(engine)
    assert changes, "an old table must be changed"
    with engine.connect() as conn:
        columns = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(stripe_events)")}
        assert {"claimed_at", "checkout_session_id", "payment_evidence_id", "runtime_json"} <= columns
        owners = dict(conn.exec_driver_sql("SELECT event_id, checkout_session_id FROM stripe_events").fetchall())
        stuck = conn.exec_driver_sql("SELECT claimed_at FROM stripe_events WHERE event_id='evt_stuck'").scalar()
        failed = conn.exec_driver_sql("SELECT claimed_at FROM stripe_events WHERE event_id='evt_failed'").scalar()
    assert owners["evt_done"] == "cs_done" and owners["evt_done_again"] is None, "the first completion owns the session"
    assert stuck is not None and abs(stuck - time.time()) < 60, "a PROCESSING row of the old code gets a lease clock"
    assert failed is None
    with pytest.raises(IntegrityError):                       # the per-session unique index is in place
        with engine.begin() as conn:
            conn.exec_driver_sql("INSERT INTO stripe_events (id, event_id, status, checkout_session_id) "
                                 "VALUES ('9', 'evt_new', 'PROCESSING', 'cs_done')")


def test_migration_is_idempotent_and_safe_without_the_table(tmp_path):
    engine = _old_database(tmp_path)
    migrate_stripe_events(engine)
    assert migrate_stripe_events(engine) == []
    assert migrate_stripe_events(create_engine(f"sqlite:///{tmp_path / 'empty.db'}")) == []      # no table: nothing to do


def test_the_application_database_has_the_columns_and_the_session_index():
    """Built by create_all from the model, then run through the migration at import: both routes end in one schema."""
    with SessionLocal() as db:
        connection = db.connection()
        columns = {row[1] for row in connection.exec_driver_sql("PRAGMA table_info(stripe_events)")}
        indexes = {row[1]: row[2] for row in connection.exec_driver_sql("PRAGMA index_list(stripe_events)")}
    assert {"claimed_at", "checkout_session_id", "payment_evidence_id", "runtime_json"} <= columns
    assert indexes.get("uq_stripe_events_checkout_session") == 1, "the per-session index must exist and be unique"


def test_the_application_model_reads_a_migrated_old_row(tmp_path):
    from sqlalchemy.orm import sessionmaker
    engine = _old_database(tmp_path)
    migrate_stripe_events(engine)
    with sessionmaker(bind=engine)() as db:
        row = db.scalar(select(StripeEvent).where(StripeEvent.event_id == "evt_done"))
        assert row.status == "COMPLETED" and row.checkout_session_id == "cs_done" and row.payment_evidence_id is None


# ================================================================== webhook: one run per paid session
def test_three_event_ids_for_one_paid_session_run_it_once(stripe_env):
    tenant_id, _ = make_tenant()
    calls = _fake_runner(stripe_env)
    session_id = "cs_" + uuid.uuid4().hex
    first = _post(_event(tenant_id, session_id=session_id))
    assert first.status_code == 200 and first.json()["status"] == "COMPLETED", first.text[:200]
    for kind in ("checkout.session.completed", "checkout.session.async_payment_succeeded"):
        again = _post(_event(tenant_id, session_id=session_id, etype=kind))           # a new event id each time
        assert again.status_code == 200 and again.json() == first.json(), again.text[:200]
    assert len(calls) == 1, "one payment, one run"
    assert [p["checkout_session_id"] for p in _evidence(tenant_id, "stripe.payment_confirmed")] == [session_id]
    assert len(_evidence(tenant_id, "stripe.ola_execution_completed")) == 1
    assert len(_session_rows(session_id)) == 1


def test_an_event_id_is_bound_to_its_session(stripe_env):
    tenant_id, _ = make_tenant()
    calls = _fake_runner(stripe_env)
    event = _event(tenant_id)
    assert _post(event).status_code == 200
    other = _event(tenant_id, event_id=event["id"])
    assert _post(other).status_code == 409 and len(calls) == 1


def test_a_session_that_another_event_is_still_processing_is_409_and_runs_nothing(stripe_env):
    tenant_id, _ = make_tenant()
    calls = _fake_runner(stripe_env)
    session_id = "cs_" + uuid.uuid4().hex
    _insert_row("evt_a_" + uuid.uuid4().hex, session_id, "PROCESSING", time.time())
    r = _post(_event(tenant_id, session_id=session_id))
    assert r.status_code == 409 and calls == []


def test_concurrent_deliveries_of_one_session_run_it_once(stripe_env):
    import threading
    tenant_id, _ = make_tenant()
    calls = _fake_runner(stripe_env)
    session_id = "cs_" + uuid.uuid4().hex
    events = [_event(tenant_id, session_id=session_id) for _ in range(6)]
    answers = []

    def deliver(event):
        answers.append(_post(event).status_code)

    threads = [threading.Thread(target=deliver, args=(e,)) for e in events]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(calls) == 1, answers
    assert set(answers) <= {200, 409} and answers.count(200) >= 1, answers


# ================================================================== webhook: a row that is stuck PROCESSING recovers
def test_a_processing_row_whose_lease_ran_out_is_reclaimed(stripe_env):
    tenant_id, _ = make_tenant()
    calls = _fake_runner(stripe_env)
    event = _event(tenant_id)
    session_id = event["data"]["object"]["id"]
    _insert_row(event["id"], session_id, "PROCESSING", time.time() - 5000)       # a worker that died, long ago
    r = _post(event)
    assert r.status_code == 200 and r.json()["status"] == "COMPLETED", r.text[:200]
    assert len(calls) == 1 and _rows(event["id"])[0].status == "COMPLETED"


def test_a_processing_row_with_a_live_lease_is_left_alone(stripe_env):
    tenant_id, _ = make_tenant()
    calls = _fake_runner(stripe_env)
    event = _event(tenant_id)
    _insert_row(event["id"], event["data"]["object"]["id"], "PROCESSING", time.time() - 5)
    assert _post(event).status_code == 409 and calls == []
    stripe_env.setenv("OLA_STRIPE_LEASE_S", "1")                  # the lease is configurable
    assert _post(event).status_code == 200 and len(calls) == 1


def test_a_legacy_processing_row_without_a_lease_clock_is_in_flight_first_and_reclaimable_later(stripe_env):
    tenant_id, _ = make_tenant()
    calls = _fake_runner(stripe_env)
    event = _event(tenant_id)
    with SessionLocal() as db:
        db.add(StripeEvent(id=str(uuid.uuid4()), event_id=event["id"], status="PROCESSING", task="calculate 2 + 2"))
        db.commit()
    assert _post(event).status_code == 409 and calls == []
    assert _rows(event["id"])[0].claimed_at is not None, "the lease clock starts when the row is first seen"
    _age_lease(event["id"], 5000)
    assert _post(event).status_code == 200 and len(calls) == 1


def test_a_lock_error_that_also_blocks_the_failed_mark_recovers_when_the_lease_runs_out(stripe_env):
    """The webhook's database writes fail with 'database is locked' (503). Marking the row FAILED fails for the same
    reason, so the row stays PROCESSING; it used to stay so for ever (every redelivery 409)."""
    tenant_id, _ = make_tenant()
    sleeps = []
    stripe_env.setattr(sw, "_pause", sleeps.append)

    def locked(*args):
        raise OperationalError("UPDATE stripe_events", {}, Exception("database is locked"))

    stripe_env.setattr(sw, "_set_failed", locked)
    runs = []

    def run(tenant, task):
        runs.append(task)
        if len(runs) == 1:
            raise OperationalError("INSERT INTO evidence_records", {}, Exception("database is locked"))
        return {"status": "VERIFIED", "computation": "PERFORMED", "run_id": "run-" + uuid.uuid4().hex,
                "final_result": "4", "evidence_ids": []}

    stripe_env.setattr(sw, "run_agent_task", run)
    event = _event(tenant_id)
    first = _post(event)
    assert first.status_code == 503 and first.headers.get("retry-after"), first.text[:200]
    assert _rows(event["id"])[0].status == "PROCESSING"
    assert len(sleeps) == 3, "the FAILED write is retried (4 attempts, 3 back-offs) before the lease takes over"
    assert _post(event).status_code == 409                                       # still in flight as far as anyone can tell
    _age_lease(event["id"], 5000)                                                 # the lease runs out
    again = _post(event)
    assert again.status_code == 200 and again.json()["status"] == "COMPLETED", again.text[:200]
    assert len(runs) == 2


def test_the_failed_mark_is_retried_with_a_growing_back_off(stripe_env):
    tenant_id, _ = make_tenant()
    sleeps = []
    stripe_env.setattr(sw, "_pause", sleeps.append)
    event = _event(tenant_id)
    _insert_row(event["id"], event["data"]["object"]["id"], "PROCESSING", 123.0)
    real, calls = sw._set_failed, []

    def flaky(row_event_id, token):
        calls.append(1)
        if len(calls) < 3:
            raise OperationalError("UPDATE stripe_events", {}, Exception("database is locked"))
        real(row_event_id, token)

    stripe_env.setattr(sw, "_set_failed", flaky)
    assert sw._mark_failed(event["id"], 123.0) is True
    assert len(calls) == 3 and sleeps == sorted(sleeps) and len(sleeps) == 2 and sleeps[0] < sleeps[1]
    assert _rows(event["id"])[0].status == "FAILED"
    stripe_env.setattr(sw, "_set_failed", lambda *a: (_ for _ in ()).throw(RuntimeError("down")))
    assert sw._mark_failed(event["id"], 123.0) is False                           # gives up quietly: the lease is the backstop


def test_a_worker_that_lost_its_lease_cannot_overwrite_the_new_owner(stripe_env):
    tenant_id, _ = make_tenant()
    event = _event(tenant_id)
    session_id = event["data"]["object"]["id"]
    outcome_a, claim_a = sw._claim(event["id"], session_id, "calculate 2 + 2")
    assert outcome_a == "claimed"
    _age_lease(event["id"], 5000)                                                 # worker A's lease runs out ...
    outcome_b, claim_b = sw._claim(event["id"], session_id, "calculate 2 + 2")    # ... worker B reclaims the row
    assert outcome_b == "claimed" and claim_b["token"] != claim_a["token"]
    with pytest.raises(sw._LeaseLost):
        sw._fenced_update(event["id"], claim_a["token"], status="COMPLETED", result_json="{}")
    sw._fenced_update(event["id"], claim_b["token"], run_id="run-b")
    assert _rows(event["id"])[0].run_id == "run-b" and _rows(event["id"])[0].status == "PROCESSING"
    sw._mark_failed(event["id"], claim_a["token"])                                # A's late FAILED mark changes nothing
    assert _rows(event["id"])[0].status == "PROCESSING"


def test_a_run_that_outlives_its_lease_does_not_complete_over_the_new_owner(stripe_env):
    tenant_id, _ = make_tenant()
    event = _event(tenant_id)
    runs, second = [], {}

    def run(tenant, task):
        runs.append(task)
        result = {"status": "VERIFIED", "computation": "PERFORMED", "run_id": "run-" + uuid.uuid4().hex,
                  "final_result": "4", "evidence_ids": []}
        if len(runs) == 1:                       # worker A is still running when its lease runs out and a redelivery wins
            _age_lease(event["id"], 5000)
            second["response"] = _post(event)
            second["run_id"] = _rows(event["id"])[0].run_id
        return result

    stripe_env.setattr(sw, "run_agent_task", run)
    first = _post(event)
    assert second["response"].status_code == 200 and second["response"].json()["status"] == "COMPLETED"
    assert first.status_code == 409, first.text[:200]
    row = _rows(event["id"])[0]
    assert row.status == "COMPLETED" and row.run_id == second["response"].json()["ola_run_id"] == second["run_id"]
    assert len(_evidence(tenant_id, "stripe.ola_execution_completed")) == 1
    assert len(_evidence(tenant_id, "stripe.payment_confirmed")) == 1


# ================================================================== webhook: a retry reuses finished work
def _fail_once_on(stripe_env, record_type):
    real, state = sw._append_evidence, {"armed": True}

    def append(tenant, rtype, payload):
        if rtype == record_type and state["armed"]:
            state["armed"] = False
            raise RuntimeError("bookkeeping failed")
        return real(tenant, rtype, payload)

    stripe_env.setattr(sw, "_append_evidence", append)


def test_a_retry_after_a_failure_in_the_bookkeeping_does_not_run_or_record_the_payment_twice(stripe_env):
    tenant_id, _ = make_tenant()
    calls = _fake_runner(stripe_env)
    _fail_once_on(stripe_env, "stripe.ola_execution_completed")
    event = _event(tenant_id)
    first = _post(event)
    assert first.status_code == 500
    row = _rows(event["id"])[0]
    assert row.status == "FAILED" and row.run_id and row.payment_evidence_id and row.runtime_json, \
        "the finished work is persisted before the bookkeeping"
    second = _post(event)
    assert second.status_code == 200 and second.json()["status"] == "COMPLETED", second.text[:200]
    assert second.json()["payment_evidence_id"] == row.payment_evidence_id and second.json()["ola_run_id"] == row.run_id
    assert len(calls) == 1, "the paid task ran twice"
    assert len(_evidence(tenant_id, "stripe.payment_confirmed")) == 1, "the payment was recorded twice"
    assert len(_evidence(tenant_id, "stripe.ola_execution_completed")) == 1


def test_a_retry_uses_the_payment_evidence_id_the_row_remembers_without_searching_the_chain(stripe_env):
    tenant_id, _ = make_tenant()
    _fake_runner(stripe_env)
    _fail_once_on(stripe_env, "stripe.ola_execution_completed")
    event = _event(tenant_id)
    assert _post(event).status_code == 500
    remembered = _rows(event["id"])[0].payment_evidence_id
    assert remembered
    searched, real = [], sw._recorded

    def recorded(tenant, record_type, session_id):
        searched.append(record_type)
        return real(tenant, record_type, session_id)

    stripe_env.setattr(sw, "_recorded", recorded)
    second = _post(event)
    assert second.status_code == 200 and second.json()["payment_evidence_id"] == remembered
    assert "stripe.payment_confirmed" not in searched, "an id the row remembers must not be searched for again"
    assert len(_evidence(tenant_id, "stripe.payment_confirmed")) == 1


def test_a_retry_after_a_failed_run_runs_it_again_but_records_the_payment_once(stripe_env):
    tenant_id, _ = make_tenant()
    runs = []

    def run(tenant, task):
        runs.append(task)
        if len(runs) == 1:
            raise RuntimeError("transient")
        return {"status": "VERIFIED", "computation": "PERFORMED", "run_id": "run-" + uuid.uuid4().hex,
                "final_result": "4", "evidence_ids": []}

    stripe_env.setattr(sw, "run_agent_task", run)
    event = _event(tenant_id)
    assert _post(event).status_code == 500
    assert _rows(event["id"])[0].status == "FAILED"
    assert _post(event).status_code == 200 and len(runs) == 2
    assert len(_evidence(tenant_id, "stripe.payment_confirmed")) == 1


def test_a_failed_session_is_completed_by_a_different_event_id_and_then_answers_from_the_cache(stripe_env):
    tenant_id, _ = make_tenant()
    calls = _fake_runner(stripe_env)
    _fail_once_on(stripe_env, "stripe.ola_execution_completed")
    session_id = "cs_" + uuid.uuid4().hex
    first_event = _event(tenant_id, session_id=session_id)
    assert _post(first_event).status_code == 500
    other = _post(_event(tenant_id, session_id=session_id))           # Stripe sends another event for the same session
    assert other.status_code == 200 and other.json()["event_id"] == first_event["id"], other.text[:200]
    assert _post(first_event).json() == other.json()
    assert len(calls) == 1 and len(_session_rows(session_id)) == 1


def _crash_once_in_fenced_update(stripe_env, when):
    real, state = sw._fenced_update, {"armed": True}

    def crashing(row_event_id, token, **values):
        if state["armed"] and when(values):
            state["armed"] = False
            raise RuntimeError("process died here")
        return real(row_event_id, token, **values)

    stripe_env.setattr(sw, "_fenced_update", crashing)


def test_a_crash_between_the_payment_evidence_and_its_id_does_not_record_the_payment_twice(stripe_env):
    tenant_id, _ = make_tenant()
    calls = _fake_runner(stripe_env)
    _crash_once_in_fenced_update(stripe_env, lambda values: "payment_evidence_id" in values)
    event = _event(tenant_id)
    assert _post(event).status_code == 500
    row = _rows(event["id"])[0]
    assert row.status == "FAILED" and row.payment_evidence_id is None, "the evidence exists but the row never learned its id"
    assert _post(event).status_code == 200
    assert len(_evidence(tenant_id, "stripe.payment_confirmed")) == 1, "the retry must find the evidence the crash left"
    assert _rows(event["id"])[0].payment_evidence_id and len(calls) == 1


def test_a_crash_after_the_completion_evidence_does_not_record_the_completion_twice(stripe_env):
    tenant_id, _ = make_tenant()
    calls = _fake_runner(stripe_env)
    _crash_once_in_fenced_update(stripe_env, lambda values: values.get("status") == "COMPLETED")
    event = _event(tenant_id)
    assert _post(event).status_code == 500
    assert len(_evidence(tenant_id, "stripe.ola_execution_completed")) == 1
    assert _post(event).status_code == 200
    assert len(_evidence(tenant_id, "stripe.ola_execution_completed")) == 1
    assert len(_evidence(tenant_id, "stripe.payment_confirmed")) == 1 and len(calls) == 1
    assert _rows(event["id"])[0].status == "COMPLETED"


def test_a_legacy_row_without_a_session_defers_to_the_row_that_owns_the_session(stripe_env):
    tenant_id, _ = make_tenant()
    calls = _fake_runner(stripe_env)
    session_id = "cs_" + uuid.uuid4().hex
    done = {"status": "COMPLETED", "event_id": "evt_owner", "checkout_session_id": session_id, "ola_run_id": "run-owner"}
    _insert_row("evt_owner", session_id, "COMPLETED", None, run_id="run-owner", result_json=json.dumps(done))
    with SessionLocal() as db:                                           # written by the old code: it never knew the session
        db.add(StripeEvent(id=str(uuid.uuid4()), event_id="evt_legacy", status="FAILED", task="calculate 2 + 2"))
        db.commit()
    r = _post(_event(tenant_id, event_id="evt_legacy", session_id=session_id))
    assert r.status_code == 200 and r.json() == done and calls == []


# ================================================================== webhook: client mistakes are 400, never 500
def test_a_non_ascii_signature_is_rejected_not_a_server_error(stripe_env):
    now = int(time.time())
    for odd in ("é", "ж", "\ud800", "\u00ff" * 64):
        assert sw.verify_stripe_signature(b"{}", f"t={now},v1={odd}", "secret", now=now) is False
    for odd in ("é", "\u00ff" * 64, "\u00a0abc"):
        r = client.post("/stripe/webhook", content=b"{}", headers={
            "Stripe-Signature": f"t={now},v1={odd}".encode("latin-1"), "Content-Type": "application/json"})
        assert r.status_code == 400, (odd, r.status_code)


@pytest.mark.parametrize("raw", [
    b"\xff\xfe{}",                                   # invalid UTF-8
    b"[" * 30000 + b"]" * 30000,                     # nesting deeper than the parser's recursion limit
    b'{"id": NaN}', b"[]", b'"x"', b"null", b"",
], ids=["bad-utf8", "deep-nesting", "nan", "array", "string", "null", "empty"])
def test_signed_garbage_is_a_400(stripe_env, raw):
    assert _post_raw(raw).status_code == 400


@pytest.mark.parametrize("where", ["task", "tenant_id", "event_id", "session_id", "event_type"])
def test_lone_surrogates_in_a_signed_event_are_a_400(stripe_env, where):
    tenant_id, _ = make_tenant()
    calls = _fake_runner(stripe_env)
    event = _event(tenant_id)
    bad = "\ud800"
    if where == "task":
        event["data"]["object"]["metadata"]["task"] = "calculate " + bad
    elif where == "tenant_id":
        event["data"]["object"]["metadata"]["tenant_id"] = bad
    elif where == "event_id":
        event["id"] = "evt_" + bad
    elif where == "session_id":
        event["data"]["object"]["id"] = "cs_" + bad
    else:
        event["type"] = "checkout.session." + bad
    r = _post(event)
    assert r.status_code == 400, (where, r.status_code, r.text[:150])
    assert calls == []


@pytest.mark.parametrize("where", ["event_id", "session_id", "tenant_id", "task"])
def test_over_long_values_in_a_signed_event_are_a_400(stripe_env, where):
    tenant_id, _ = make_tenant()
    calls = _fake_runner(stripe_env)
    event = _event(tenant_id)
    if where == "event_id":
        event["id"] = "e" * 300
    elif where == "session_id":
        event["data"]["object"]["id"] = "c" * 300
    elif where == "tenant_id":
        event["data"]["object"]["metadata"]["tenant_id"] = "t" * 300
    else:
        event["data"]["object"]["metadata"]["task"] = "calculate " + "1 + " * 3000 + "1"
    r = _post(event)
    assert r.status_code == 400, (where, r.status_code, r.text[:150])
    assert calls == []


# ================================================================== webhook: the result says whether anything was computed
def _completed_payload(tenant_id):
    payloads = _evidence(tenant_id, "stripe.ola_execution_completed")
    assert len(payloads) == 1
    return payloads[0]


def test_a_paid_task_that_cannot_be_computed_is_reported_as_not_performed(stripe_env):
    tenant_id, _ = make_tenant()
    r = _post(_event(tenant_id, task="summarise my contract and list the risks"))      # the real runner
    body = r.json()
    assert r.status_code == 200 and body["status"] == "COMPLETED", r.text[:200]
    assert body["computation"] == "NOT_PERFORMED" and body["ola_status"] == "UNKNOWN", body
    assert str(body["ola_final_result"]).startswith("task accepted:")
    assert _completed_payload(tenant_id)["computation"] == "NOT_PERFORMED"


def test_a_paid_task_that_was_computed_is_reported_as_performed(stripe_env):
    tenant_id, _ = make_tenant()
    stripe_env.setenv("OLA_SOURCE_COMMIT", "abc1234")
    body = _post(_event(tenant_id, task="Calculate 17 * 23 and return the verified result.")).json()
    assert body["computation"] == "PERFORMED" and body["ola_status"] == "VERIFIED" and body["ola_final_result"] == "391", body
    assert _completed_payload(tenant_id)["computation"] == "PERFORMED"


def test_a_runner_that_does_not_say_is_judged_by_its_status(stripe_env):
    tenant_id, _ = make_tenant()
    stripe_env.setattr(sw, "run_agent_task", lambda t, task: {"status": "UNKNOWN", "run_id": "run-x", "final_result": "?", "evidence_ids": []})
    assert _post(_event(tenant_id)).json()["computation"] == "NOT_PERFORMED"


def test_a_real_llm_with_an_uncomputable_task_does_not_raise(monkeypatch):
    """With a real model the answer was parsed as a proposal and compared with the refusal text: an uncomputable task
    raised, i.e. a 500 on /agent-run and a retry loop for a paid webhook."""
    tenant_id, _ = make_tenant()
    monkeypatch.setenv("OLA_LLM_MODE", "required")
    monkeypatch.setenv("OLA_REPLAY_NONCE", "a" * 64)

    def fake(agent, task, context):
        return {"provider": "openai", "model": "m", "invocation_type": "real_llm", "prompt_digest": "x",
                "response_id": "r", "response_digest": "d", "response_id_source": "provider",
                "output": json.dumps({"action": "safe_expression", "result": "cannot compute"})}

    monkeypatch.setattr(ar, "_invoke_llm", fake)
    result = ar.run_agent_task(tenant_id, "hello world")
    assert result["computation"] == "NOT_PERFORMED" and result["status"] != "VERIFIED", result["status"]
    assert result["execution"][0]["tool_output"].startswith("task accepted:")


# ================================================================== the evaluator
@pytest.mark.parametrize("task,expected", [
    ("calculate 17 * 23", "391"), ("Calculate -5 + 2", "-3"), ("calculate +7", "7"), ("calculate 7 % 3", "1"),
    ("calculate 7 // 2", "3"), ("calculate -7 // 2", "-4"), ("calculate -(2 + 3) * 2", "-10"),
    ("CALCULATE 2 + 2", "4"), ("İİ calculate 40 + 2", "42"), ("ß ǅ İ calculate 1 + 1", "2"),
    ("please calculate 6 * 7?", "42"), ("calculate 1 + 1 and then summarise", "2"),
])
def test_safe_expression_results(task, expected):
    assert ar._safe_expression(task) == expected


@pytest.mark.parametrize("task", [
    "calculate True", "calculate True + True", "calculate -True", "calculate False", "calculate 2 ** 3",
    "calculate 9**9**9", "calculate 1 % 0", "calculate 1 // 0", "calculate 1 / 0", "calculate 'a' * 3",
    "calculate abs(1)", "calculate 1 < 2", "calculate 1e999 * 10", "calculate (", "hello", "", "calculate " + "(" * 5000,
])
def test_safe_expression_refuses_what_is_not_plain_arithmetic(task):
    assert ar._safe_expression(task).startswith(ar.NOT_COMPUTED)


def test_a_dotted_capital_i_no_longer_shifts_the_expression():
    tenant_id, _ = make_tenant()
    result = ar.run_agent_task(tenant_id, "İİ calculate 40 + 2")
    assert result["final_result"] == "42" and result["computation"] == "PERFORMED"


# ================================================================== the standalone runtime verifier
def test_the_standalone_runtime_verifier_does_not_call_a_refusal_verified(monkeypatch):
    monkeypatch.setenv("OLA_SOURCE_COMMIT", "abc1234")
    tenant_id, _ = make_tenant()
    done = ar.run_agent_task(tenant_id, "Calculate 17 * 23")
    proof = agent_verifier.verify(tenant_id, done["run_id"], "abc1234", expected_task="Calculate 17 * 23", db_path=DB_PATH)
    assert proof["status"] == "VERIFIED" and proof["computation"] == "PERFORMED"
    refused = ar.run_agent_task(tenant_id, "write me a poem")
    assert refused["status"] == "UNKNOWN" and refused["computation"] == "NOT_PERFORMED"
    verdict = agent_verifier.verify(tenant_id, refused["run_id"], "abc1234", expected_task="write me a poem", db_path=DB_PATH)
    assert verdict["status"] == "UNKNOWN" and verdict["computation"] == "NOT_PERFORMED", verdict
    assert "nothing was computed" in verdict["reason"]


def test_the_runtime_verifier_cli_exits_non_zero_for_a_refusal(monkeypatch):
    monkeypatch.setenv("OLA_SOURCE_COMMIT", "abc1234")
    tenant_id, _ = make_tenant()
    refused = ar.run_agent_task(tenant_id, "write me a poem")
    cli = subprocess.run([sys.executable, "scripts/verify_agent_runtime.py", "--db-path", DB_PATH, "--tenant-id", tenant_id,
                          "--run-id", refused["run_id"], "--expected-commit", "abc1234"], capture_output=True, text=True)
    assert cli.returncode != 0
    assert json.loads(cli.stdout.strip().splitlines()[-1])["status"] == "UNKNOWN"


# ================================================================== /payment-success agrees with the webhook
def _lookup(monkeypatch, session):
    monkeypatch.setattr(main, "retrieve_checkout", lambda requested: session)
    return main.payment_success(session["id"])


def test_payment_success_finds_a_run_whose_task_has_surrounding_spaces(stripe_env):
    tenant_id, _ = make_tenant()
    _fake_runner(stripe_env)
    session = _session(tenant_id, task="  calculate 2 + 2 \n")        # Stripe keeps metadata verbatim; the webhook strips it
    posted = _post(_event(tenant_id, session=session))
    assert posted.status_code == 200
    answer = _lookup(stripe_env, session)
    assert answer["status"] == "COMPLETED" and answer["run_id"] == posted.json()["ola_run_id"], answer
    assert answer["task"] == "calculate 2 + 2"


def test_payment_success_reads_the_task_from_the_custom_field_like_the_webhook(stripe_env):
    tenant_id, _ = make_tenant()
    _fake_runner(stripe_env)
    session = _session(tenant_id)
    del session["metadata"]["task"]
    session["custom_fields"] = [{"key": "audit_task", "text": {"value": " calculate 3 + 4 "}}]
    posted = _post(_event(tenant_id, session=session))
    assert posted.status_code == 200 and posted.json()["status"] == "COMPLETED"
    answer = _lookup(stripe_env, session)
    assert answer["status"] == "COMPLETED" and answer["run_id"] == posted.json()["ola_run_id"], answer


@pytest.mark.parametrize("state", [{"status": "complete", "payment_status": "unpaid"},
                                   {"status": "open", "payment_status": "unpaid"}], ids=["async-pending", "open"])
def test_payment_success_on_an_unpaid_session_is_awaiting_payment_and_writes_nothing(monkeypatch, state):
    tenant_id, _ = make_tenant()
    session = _session(tenant_id, **state)
    before = len(_evidence(tenant_id))
    for _ in range(3):                                               # every poll used to append a revenue.payment_blocked row
        answer = _lookup(monkeypatch, session)
        assert answer["status"] == "AWAITING_PAYMENT" and answer["session_id"] == session["id"], answer
    assert len(_evidence(tenant_id)) == before


def test_payment_success_on_an_expired_session_is_a_block_and_writes_nothing(monkeypatch):
    tenant_id, _ = make_tenant()
    session = _session(tenant_id, status="expired", payment_status="unpaid")
    answer = _lookup(monkeypatch, session)
    assert answer["status"] == "BLOCK" and "expired" in answer["reason"]
    assert _evidence(tenant_id) == []


def test_payment_success_never_confirms_what_is_not_paid_for_this_offer(monkeypatch):
    tenant_id, _ = make_tenant()
    foreign = _session(tenant_id)
    foreign["metadata"]["offer"] = "someone-elses-offer"
    assert _lookup(monkeypatch, foreign)["status"] == "BLOCK"
    unpaid_foreign = _session(tenant_id, payment_status="unpaid")
    unpaid_foreign["metadata"]["offer"] = "someone-elses-offer"
    assert _lookup(monkeypatch, unpaid_foreign)["status"] == "BLOCK"
    assert _lookup(monkeypatch, _session(tenant_id, payment_status="no_payment_required"))["status"] == "BLOCK"
    taskless = _session(tenant_id)
    del taskless["metadata"]["task"]
    assert _lookup(monkeypatch, taskless)["status"] == "BLOCK"


@pytest.mark.parametrize("answer", [None, [], "x", 5, {"id": "cs_1", "metadata": None}, {"id": "cs_1", "metadata": []},
                                    {"id": "cs_1", "metadata": {"tenant_id": 5}}], ids=repr)
def test_payment_success_with_an_odd_stripe_answer_is_a_clean_error(monkeypatch, answer):
    from fastapi import HTTPException
    monkeypatch.setattr(main, "retrieve_checkout", lambda requested: answer)
    with pytest.raises(HTTPException) as caught:
        main.payment_success("cs_1")
    assert caught.value.status_code in (403, 502)


# ================================================================== invoice maths
GOOD = {"invoice_id": "INV-R6-1", "supplier": "TEST-SUPPLIER", "currency": "EUR", "net": 1000.0, "vat_rate": 0.21}


def _task(invoice):
    return "INVOICE_JSON:" + invoice_verifier.canonical(invoice)


def test_vat_is_rounded_half_up_on_the_decimal_amount_not_the_binary_float():
    assert round(0.5 * 0.21, 2) == 0.1, "premise: the binary float gives 0.10 where the invoice means 0.105"
    assert br.money(0.5, 0.21) == (0.11, 0.61, True)
    assert invoice_verifier.money(0.5, 0.21) == (0.11, 0.61, True)
    assert br.money(0.0, 0.0)[0] == 0.0 and str(br.money(1.0, -0.0)[0]) == "0.0"       # never -0.0
    assert br.money(100.0, 0.06) == (6.0, 106.0, False)


def test_vat_matches_exact_half_up_arithmetic_on_many_nets():
    rng = random.Random(6)
    for _ in range(4000):
        cents = rng.randrange(1, 10**11) if rng.random() < 0.5 else rng.randrange(1, 10**5)
        net = cents / 100
        vat_cents = int(Fraction(cents) * Fraction(21, 100) + Fraction(1, 2))          # exact, half-up
        vat, gross, policy = br.money(net, 0.21)
        assert vat == vat_cents / 100 and gross == (cents + vat_cents) / 100 and policy is True, (net, vat, vat_cents)


def test_the_invoice_endpoint_returns_the_half_up_vat_and_the_standalone_verifier_agrees():
    tenant_id, key = make_tenant()
    invoice = {**GOOD, "net": 0.5}
    r = client.post("/business-invoice-run", json={"invoice": invoice}, headers={"X-API-Key": key})
    assert r.status_code == 200, r.text[:200]
    body = r.json()
    assert body["status"] == "VERIFIED" and body["final_result"]["vat"] == 0.11 and body["final_result"]["gross"] == 0.61
    proof = invoice_verifier.verify(DB_PATH, tenant_id, body["run_id"], invoice)
    assert proof["status"] == "VERIFIED" and proof["vat"] == 0.11 and proof["gross"] == 0.61


def _random_invoice(rng):
    """Each field is valid 80 % of the time, so both outcomes are well represented; 4 % of the fields are missing."""
    def pick(valid, invalid):
        options = valid if rng.random() < 0.8 else invalid
        return options[rng.randrange(len(options))]
    invoice = {
        "invoice_id": pick(["INV-1", "A" * 200, "ok é", "INV-" + uuid.uuid4().hex[:6]], ["", "   ", "A" * 201, 5, None, "\ud800"]),
        "supplier": pick(["S", "ACME", "ж"], ["x" * 201, "", None, ["s"]]),
        "currency": pick(["EUR", "USD", "PLN"], ["eur", "EURO", "EU", "", None, 3, "€€€", "ÉUR"]),
        "net": pick([round(rng.uniform(0.01, 5000), 2), rng.randrange(1, 10**7) / 100, 0.5, 0.05, 1000.0, 1, 10**9],
                    [10**9 + 0.01, 0.005, 0.0, -1.0, -5000, True, False, "1000", None, [1], float("nan"), float("inf"), 1e300,
                     10**400, round(rng.uniform(0.01, 99), 3), 1e-7]),
        "vat_rate": pick([0.21, 0.21, 0.21, 0.06, 0.12, 0.0, -0.0, 1.0, 0.5, 0.21000000000000002, 0.2099999, round(rng.random(), 2), 1, 0],
                         [2, -0.1, True, "0.21", None, {}, float("nan")]),
    }
    for field in list(invoice):
        if rng.random() < 0.04:
            del invoice[field]
    return invoice


def _app_decision(invoice):
    required = {"invoice_id", "supplier", "currency", "net", "vat_rate"}
    try:
        if not required.issubset(invoice):
            raise ValueError("missing")
        net, vat_rate = br.validate_invoice(dict(invoice))
        return ("ok", net, br.money(net, vat_rate))
    except (ValueError, TypeError, OverflowError):
        return ("rejected",)


def _script_decision(invoice):
    try:
        net, vat_rate = invoice_verifier.validate_invoice(dict(invoice))
        return ("ok", net, invoice_verifier.money(net, vat_rate))
    except invoice_verifier.Block:
        return ("rejected",)


def test_the_standalone_verifier_and_the_app_decide_alike_on_random_invoices():
    rng = random.Random(20261006)
    accepted = rejected = 0
    for _ in range(1500):
        invoice = _random_invoice(rng)
        a, s = _app_decision(invoice), _script_decision(invoice)
        assert a == s, (invoice, a, s)
        accepted += a[0] == "ok"
        rejected += a[0] == "rejected"
    assert accepted > 100 and rejected > 100, (accepted, rejected)


def test_runs_of_random_valid_invoices_verify_exactly_when_the_vat_rate_is_the_controlled_one():
    rng = random.Random(77)
    tenant_id, _ = make_tenant()
    seen = {"approved": 0, "rejected": 0}
    for _ in range(25):
        invoice = {**GOOD, "invoice_id": "INV-" + uuid.uuid4().hex[:8], "net": rng.randrange(1, 10**7) / 100,
                   "vat_rate": rng.choice([0.21, 0.21, 0.06, 0.0, 0.12])}
        result = br.run_invoice_task(tenant_id, _task(invoice))
        if invoice["vat_rate"] == 0.21:
            proof = invoice_verifier.verify(DB_PATH, tenant_id, result["run_id"], invoice)
            assert proof["vat"] == result["final_result"]["vat"] and proof["gross"] == result["final_result"]["gross"]
            assert result["status"] == "VERIFIED"
            seen["approved"] += 1
        else:
            assert result["status"] == "BLOCK" and result["final_result"]["transfer_amount"] == 0.0
            with pytest.raises(invoice_verifier.Block, match="controlled policy"):
                invoice_verifier.verify(DB_PATH, tenant_id, result["run_id"], invoice)
            seen["rejected"] += 1
    assert seen["approved"] > 5 and seen["rejected"] > 3


# ================================================================== the invoice verifier is not weaker than the app
def _forge_run(tenant_id, invoice):
    """Six chain-valid agent records for an invoice the app would never have accepted (what writing to the evidence
    table directly, or an older version of the app, could leave behind)."""
    net = invoice["net"]
    vat = round(net * 0.21, 2)
    gross = round(net + vat, 2)
    run_id = str(uuid.uuid4())
    for out in br.run_invoice_task(tenant_id, _task(GOOD))["execution"]:
        out = json.loads(json.dumps(out))
        out.update(task=_task(invoice), agent_instance_id=str(uuid.uuid4()),
                   context_digest=hashlib.sha256(uuid.uuid4().bytes).hexdigest())
        if out["agent"] == "codeact":
            out["tool_output"] = {"net": net, "vat": vat, "gross": gross}
        if out["agent"] == "multi_agent":
            out["final_result"] = {"invoice_id": invoice["invoice_id"], "supplier": invoice["supplier"],
                                   "currency": invoice["currency"], "net": net, "vat": vat, "gross": gross,
                                   "payment_decision": "APPROVE_FOR_TEST_TRANSFER", "transfer_amount": gross,
                                   "transfer_status": "READY_NOT_SENT"}
        br._append(tenant_id, run_id, f"agent.{out['agent']}", out)
    return run_id


@pytest.mark.parametrize("over", [{"net": -5000.0}, {"net": 0.0}, {"net": 1e300}, {"net": 0.005}, {"currency": "eur"},
                                  {"currency": "EURO"}, {"invoice_id": ""}, {"supplier": "x" * 201}],
                         ids=lambda o: str(o)[:30])
def test_the_standalone_verifier_refuses_a_run_the_app_would_have_rejected(over):
    tenant_id, _ = make_tenant()
    invoice = {**GOOD, **over}
    run_id = _forge_run(tenant_id, invoice)
    with pytest.raises(invoice_verifier.Block):
        invoice_verifier.verify(DB_PATH, tenant_id, run_id, invoice)
    with pytest.raises(ValueError):
        br.validate_invoice(dict(invoice))


def test_a_tenant_with_several_runs_and_other_evidence_still_verifies_each_run():
    tenant_id, _ = make_tenant()
    runs = []
    for number in range(3):
        invoice = {**GOOD, "invoice_id": f"INV-MULTI-{number}", "net": 100.0 * (number + 1)}
        runs.append((invoice, br.run_invoice_task(tenant_id, _task(invoice))["run_id"]))
        main.append_record(tenant_id, "revenue.checkout_created", {"session_id": f"cs_{number}"})     # unrelated evidence between runs
    for invoice, run_id in runs:
        assert invoice_verifier.verify(DB_PATH, tenant_id, run_id, invoice)["status"] == "VERIFIED"
    with pytest.raises(invoice_verifier.Block, match="no agent evidence"):
        invoice_verifier.verify(DB_PATH, tenant_id, str(uuid.uuid4()), runs[0][0])
    with pytest.raises(invoice_verifier.Block):                              # another run's id with this run's invoice
        invoice_verifier.verify(DB_PATH, tenant_id, runs[1][1], runs[0][0])


def test_the_standalone_verifier_still_catches_a_tampered_chain(tmp_path):
    tenant_id, _ = make_tenant()
    result = br.run_invoice_task(tenant_id, _task(GOOD))
    other = br.run_invoice_task(tenant_id, _task({**GOOD, "invoice_id": "INV-OTHER"}))
    copy = str(tmp_path / "tampered.db")
    source, target = sqlite3.connect(DB_PATH), sqlite3.connect(copy)
    source.backup(target)
    source.close()
    assert invoice_verifier.verify(copy, tenant_id, result["run_id"], GOOD)["status"] == "VERIFIED"
    target.execute("DROP TRIGGER IF EXISTS evidence_no_update")
    target.execute("DROP TRIGGER IF EXISTS evidence_no_delete")
    # tamper with the OTHER run: the chain over the whole tenant breaks, so the untouched run no longer verifies either
    target.execute("UPDATE evidence_records SET payload_json = replace(payload_json, 'INV-OTHER', 'INV-EVIL') "
                   "WHERE tenant_id = ? AND payload_json LIKE ? ", (tenant_id, f'%{other["run_id"]}%'))
    target.commit()
    target.close()
    with pytest.raises(invoice_verifier.Block, match="hash-chain"):
        invoice_verifier.verify(copy, tenant_id, result["run_id"], GOOD)


def test_a_chain_re_based_at_a_later_sequence_is_not_accepted(tmp_path):
    """Someone who can write the database removes the head of a tenant's chain and recomputes every hash after it, so that
    all hash links are valid again. Only the sequence numbers (they start at 0 and have no gap) still tell."""
    from app.hashchain import GENESIS_HASH, compute_record_hash
    tenant_id, _ = make_tenant()
    main.append_record(tenant_id, "revenue.checkout_created", {"session_id": "cs_head"})      # the head that gets removed
    result = br.run_invoice_task(tenant_id, _task(GOOD))
    copy = str(tmp_path / "rebased.db")
    source, target = sqlite3.connect(DB_PATH), sqlite3.connect(copy)
    source.backup(target)
    source.close()
    assert invoice_verifier.verify(copy, tenant_id, result["run_id"], GOOD)["status"] == "VERIFIED"
    target.execute("DROP TRIGGER IF EXISTS evidence_no_update")
    target.execute("DROP TRIGGER IF EXISTS evidence_no_delete")
    rows = target.execute("SELECT id, seq, record_type, payload_json FROM evidence_records WHERE tenant_id = ? "
                          "ORDER BY seq", (tenant_id,)).fetchall()
    assert rows[0][1] == 0 and rows[0][2] == "revenue.checkout_created"
    target.execute("DELETE FROM evidence_records WHERE id = ?", (rows[0][0],))
    prev = GENESIS_HASH
    for row_id, seq, record_type, payload_json in rows[1:]:
        record_hash = compute_record_hash(tenant_id, seq, prev, payload_json, record_type)
        target.execute("UPDATE evidence_records SET prev_hash = ?, record_hash = ? WHERE id = ?", (prev, record_hash, row_id))
        prev = record_hash
    target.commit()
    target.close()
    with pytest.raises(invoice_verifier.Block, match="sequence"):
        invoice_verifier.verify(copy, tenant_id, result["run_id"], GOOD)


@pytest.mark.parametrize("bad", ["{", "[]", "null", "1", '"x"', "{}", '{"invoice_id": "x"}',
                                 '{"invoice_id":"x","supplier":"s","currency":"EUR","net":"1000","vat_rate":0.21}',
                                 '{"invoice_id":"x","supplier":"s","currency":"EUR","net":' + "9" * 500 + ',"vat_rate":0.21}',
                                 "[" * 100000], ids=lambda s: s[:25])
def test_the_invoice_cli_answers_malformed_input_with_a_clean_block_not_a_traceback(bad):
    cli = subprocess.run([sys.executable, "scripts/verify_business_invoice.py", "--db", DB_PATH, "--tenant-id", "t",
                          "--run-id", "r", "--invoice-json", bad], capture_output=True, text=True)
    assert cli.returncode == 1 and cli.stdout == "", (cli.returncode, cli.stdout[:200])
    assert "Traceback" not in cli.stderr, cli.stderr[:300]
    assert json.loads(cli.stderr)["status"] == "BLOCK"


def test_the_invoice_cli_does_not_create_a_database_for_a_mistyped_path(tmp_path):
    missing = tmp_path / "nope" / "typo.db"
    cli = subprocess.run([sys.executable, "scripts/verify_business_invoice.py", "--db", str(missing), "--tenant-id", "t",
                          "--run-id", "r", "--invoice-json", json.dumps(GOOD)], capture_output=True, text=True)
    assert cli.returncode == 1 and "Traceback" not in cli.stderr and json.loads(cli.stderr)["status"] == "BLOCK"
    assert not missing.exists() and not missing.parent.exists()
    empty = tmp_path / "empty.db"
    sqlite3.connect(empty).close()                                           # a database without the evidence table
    cli = subprocess.run([sys.executable, "scripts/verify_business_invoice.py", "--db", str(empty), "--tenant-id", "t",
                          "--run-id", "r", "--invoice-json", json.dumps(GOOD)], capture_output=True, text=True)
    assert cli.returncode == 1 and "Traceback" not in cli.stderr and json.loads(cli.stderr)["status"] == "BLOCK"


def test_the_invoice_cli_still_verifies_a_good_run_and_blocks_a_policy_mismatch():
    tenant_id, _ = make_tenant()
    good = br.run_invoice_task(tenant_id, _task(GOOD))
    cli = subprocess.run([sys.executable, "scripts/verify_business_invoice.py", "--db", DB_PATH, "--tenant-id", tenant_id,
                          "--run-id", good["run_id"], "--invoice-json", json.dumps(GOOD)], capture_output=True, text=True)
    proof = json.loads(cli.stdout)
    assert cli.returncode == 0 and proof["status"] == "VERIFIED" and proof["gross"] == 1210.0 and proof["evidence_count"] == 6
    mismatch = {**GOOD, "vat_rate": 0.06}
    bad = br.run_invoice_task(tenant_id, _task(mismatch))
    cli = subprocess.run([sys.executable, "scripts/verify_business_invoice.py", "--db", DB_PATH, "--tenant-id", tenant_id,
                          "--run-id", bad["run_id"], "--invoice-json", json.dumps(mismatch)], capture_output=True, text=True)
    assert cli.returncode == 1 and "controlled policy" in json.loads(cli.stderr)["reason"]


# ================================================================== a broken chain must not look like an approval
def test_a_failed_chain_check_returns_no_approval(monkeypatch):
    tenant_id, _ = make_tenant()
    monkeypatch.setattr(br, "verify_chain", lambda chain: (False, "hash chain broken"))
    result = br.run_invoice_task(tenant_id, _task(GOOD))
    assert result["status"] == "BLOCK" and result["reason"] == "hash chain broken"
    final = result["final_result"]
    assert final["payment_decision"] == "NOT_APPROVED" and final["transfer_status"] == "NOT_SENT" and final["transfer_amount"] == 0.0
    assert result["execution"][-1]["final_result"] == final and "BLOCKED" in result["execution"][-1]["result"]
    assert final["gross"] == 1210.0, "the computed amounts stay visible; only the decision changes"


def test_a_good_chain_keeps_the_approval():
    tenant_id, _ = make_tenant()
    result = br.run_invoice_task(tenant_id, _task(GOOD))
    assert result["status"] == "VERIFIED" and result["final_result"]["payment_decision"] == "APPROVE_FOR_TEST_TRANSFER"
