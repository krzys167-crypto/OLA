"""Paid Stripe webhooks: one checkout -> one run, with durable fail-closed claims.

These tests use real SQLite and hash-chain writes, but mock Stripe's signed
network source and the agent runtime. No external money is moved.
"""
import hashlib
import hmac
import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app import stripe_webhook as wh
from app.database import SessionLocal
from app.hashchain import verify_chain
from app.models import EvidenceRecord, StripeEvent, Tenant


def _seed(monkeypatch):
    tenant_id = str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="stripe_lock_" + tenant_id))
        db.commit()
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test_only_"+uuid.uuid4().hex)
    monkeypatch.setenv("OLA_STRIPE_MODE", "test")
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_fake_only")
    return tenant_id


def _event(tenant, session, event_id):
    body = json.dumps({
        "id": event_id,
        "type": "checkout.session.completed",
        "livemode": False,
        "data": {"object": {
            "id": session,
            "livemode": False,
            "metadata": {"tenant_id": tenant, "task": "safe audit",
                         "offer": "ola-execution-audit",
                         "product": "OLA Execution Audit"},
            "status": "complete", "payment_status": "paid",
            "currency": "eur", "amount_total": 9900,
        }},
    }).encode()
    stamp = str(int(time.time()))
    secret = wh.os.getenv("STRIPE_WEBHOOK_SECRET")
    signature = hmac.new(secret.encode(), stamp.encode()+b"."+body, hashlib.sha256).hexdigest()
    return body, f"t={stamp},v1={signature}"


def _rows(tenant):
    with SessionLocal() as db:
        records = db.scalars(
            select(EvidenceRecord).where(EvidenceRecord.tenant_id == tenant)
            .order_by(EvidenceRecord.seq)
        ).all()
    return [{
        "id": r.id, "tenant_id": r.tenant_id, "seq": r.seq,
        "record_type": r.record_type, "hash_version": r.hash_version,
        "prev_hash": r.prev_hash, "record_hash": r.record_hash,
        "payload_json": r.payload_json,
    } for r in records]


def test_two_distinct_events_for_same_paid_session_run_only_once(monkeypatch):
    tenant = _seed(monkeypatch)
    session = "cs_test_" + uuid.uuid4().hex
    calls = []
    def execute(tenant_id, task, *, allowed_tools):
        assert set(allowed_tools) == {"safe_expression", "local_mcp_tool_registry.sha256"}
        calls.append((tenant_id, task))
        return {"status": "VERIFIED", "run_id": "run-a", "final_result": "ok",
                "evidence_ids": []}
    monkeypatch.setattr(wh, "run_agent_task", execute)
    first = wh.process_checkout_event(*_event(tenant, session, "evt_"+uuid.uuid4().hex))
    second = wh.process_checkout_event(*_event(tenant, session, "evt_"+uuid.uuid4().hex))
    assert first == second
    assert first["status"] == "COMPLETED"
    assert calls == [(tenant, "safe audit")]
    rows = _rows(tenant)
    assert len(rows) == 2
    assert verify_chain(rows)[0] is True


def test_failed_first_evidence_write_stays_failed_and_retries_block(monkeypatch):
    tenant = _seed(monkeypatch)
    event_id = "evt_"+uuid.uuid4().hex
    event = _event(tenant, "cs_test_"+uuid.uuid4().hex, event_id)
    def broken(*args):
        raise RuntimeError("temporary storage failure")
    monkeypatch.setattr(wh, "_append_evidence", broken)
    monkeypatch.setattr(wh, "run_agent_task", lambda *args, **kwargs: pytest.fail("must not run"))
    with pytest.raises(RuntimeError):
        wh.process_checkout_event(*event)
    with SessionLocal() as db:
        row = db.scalar(select(StripeEvent).where(StripeEvent.event_id == event_id))
        assert row.status == "FAILED"
        assert json.loads(row.result_json)["checkout_session_id"].startswith("cs_test_")
    with pytest.raises(HTTPException) as caught:
        wh.process_checkout_event(*event)
    assert caught.value.status_code == 409


def test_blocked_agent_run_never_delivered_as_completed(monkeypatch):
    tenant = _seed(monkeypatch)
    monkeypatch.setattr(wh, "run_agent_task",
                        lambda *args, **kwargs: {"status": "BLOCK", "run_id": "run-b",
                                       "final_result": None, "evidence_ids": []})
    result = wh.process_checkout_event(*_event(tenant, "cs_test_"+uuid.uuid4().hex,
                                              "evt_"+uuid.uuid4().hex))
    assert result["status"] == "EXECUTION_BLOCKED"
    assert result["ola_status"] == "BLOCK"
    with SessionLocal() as db:
        row = db.scalar(select(StripeEvent).where(StripeEvent.event_id == result["event_id"]))
        assert row.status == "EXECUTION_BLOCKED"


def test_concurrent_event_claims_cannot_double_execute(monkeypatch):
    tenant = _seed(monkeypatch)
    session = "cs_test_" + uuid.uuid4().hex
    calls = []
    def execute(*args, allowed_tools):
        assert set(allowed_tools) == {"safe_expression", "local_mcp_tool_registry.sha256"}
        calls.append(args)
        return {"status": "VERIFIED", "run_id": "run-c", "final_result": "ok", "evidence_ids": []}
    monkeypatch.setattr(wh, "run_agent_task", execute)
    events = [
        _event(tenant, session, "evt_"+uuid.uuid4().hex)
        for _ in range(4)
    ]
    def call(event):
        return wh.process_checkout_event(*event)
    def attempt(event):
        try:
            return call(event)
        except HTTPException as exc:
            return {"http": exc.status_code}
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(attempt, events))
    assert len(calls) == 1
    assert sum(r.get("status") == "COMPLETED" for r in results) >= 1
    assert all(r.get("status") == "COMPLETED" or r.get("http") == 409 for r in results)
    assert verify_chain(_rows(tenant))[0] is True


def test_stripe_session_claim_rejects_cross_tenant_signed_replay(monkeypatch):
    first_tenant = _seed(monkeypatch)
    second_tenant = _seed(monkeypatch)
    session = "cs_test_" + uuid.uuid4().hex
    executions = []
    def execute(tenant_id, task, *, allowed_tools):
        assert set(allowed_tools) == {"safe_expression", "local_mcp_tool_registry.sha256"}
        executions.append(tenant_id)
        return {"status": "VERIFIED", "run_id": "run-safe",
                "final_result": "ok", "evidence_ids": []}
    monkeypatch.setattr(wh, "run_agent_task", execute)
    first = wh.process_checkout_event(*_event(
        first_tenant, session, "evt_"+uuid.uuid4().hex
    ))
    assert first["tenant_id"] == first_tenant
    with pytest.raises(HTTPException) as result:
        wh.process_checkout_event(*_event(
            second_tenant, session, "evt_"+uuid.uuid4().hex
        ))
    assert result.value.status_code == 409
    assert executions == [first_tenant]
