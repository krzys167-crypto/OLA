import hashlib
import hmac

import pytest
from sqlalchemy import select

from app.stripe_webhook import _validate_checkout, verify_stripe_signature


SECRET = "whsec_test_ola"
TIMESTAMP = 1_800_000_000


def _signature(payload: bytes) -> str:
    signed = f"{TIMESTAMP}.".encode() + payload
    digest = hmac.new(SECRET.encode(), signed, hashlib.sha256).hexdigest()
    return f"t={TIMESTAMP},v1={digest}"


def _paid_session():
    return {
        "metadata": {
            "offer": "ola-execution-audit",
            "product": "OLA Execution Audit",
            "task": "Audit this company workflow for evidence gaps.",
            "tenant_id": "tenant-test",
        },
        "payment_status": "paid",
        "status": "complete",
        "amount_total": 9900,
        "currency": "eur",
        "line_items": {"data": [{"price": {"id": "price_ola_test"}, "quantity": 1}]},
    }


def test_stripe_signature_accepts_valid_signature():
    payload = b'{"id":"evt_test","type":"checkout.session.completed"}'
    assert verify_stripe_signature(payload, _signature(payload), SECRET, now=TIMESTAMP)


def test_stripe_signature_rejects_tampered_payload():
    payload = b'{"id":"evt_test","type":"checkout.session.completed"}'
    signature = _signature(payload)
    tampered = b'{"id":"evt_test","type":"checkout.session.completed","x":"tampered"}'
    assert not verify_stripe_signature(tampered, signature, SECRET, now=TIMESTAMP)


def test_stripe_signature_rejects_old_timestamp():
    payload = b'{"id":"evt_test","type":"checkout.session.completed"}'
    signature = _signature(payload)
    assert not verify_stripe_signature(payload, signature, SECRET, now=TIMESTAMP + 301)


def test_paid_ola_checkout_extracts_audit_task(monkeypatch):
    monkeypatch.setenv("OLA_STRIPE_PRICE_ID", "price_ola_test")
    assert _validate_checkout(_paid_session()) == "Audit this company workflow for evidence gaps."


@pytest.mark.parametrize(
    "override",
    [
        {"payment_status": "unpaid"},
        {"amount_total": 9800},
        {"currency": "usd"},
        {"line_items": {"data": []}},
        {"metadata": {"offer": "other-offer", "product": "OLA Execution Audit", "task": "x"}},
    ],
)
def test_invalid_checkout_is_rejected(override, monkeypatch):
    monkeypatch.setenv("OLA_STRIPE_PRICE_ID", "price_ola_test")
    session = _paid_session()
    session.update(override)
    with pytest.raises(Exception):
        _validate_checkout(session)


def test_paid_checkout_uses_metadata_task_without_custom_fields(monkeypatch):
    monkeypatch.setenv("OLA_STRIPE_PRICE_ID", "price_ola_test")
    session = _paid_session()
    assert "custom_fields" not in session
    assert _validate_checkout(session) == "Audit this company workflow for evidence gaps."


def test_paid_webhook_only_queues_human_review_and_uses_fresh_stripe_session(monkeypatch):
    import json
    import uuid

    from app import stripe_webhook
    from app.database import SessionLocal
    from app.models import StripeEvent

    event_id = "evt_human_gate_" + str(uuid.uuid4())
    session_id = "cs_test_" + str(uuid.uuid4())
    price_id = "price_ola_test"
    task = "Review evidence gaps for this customer."
    fresh_session = {
        "id": session_id,
        "payment_status": "paid",
        "status": "complete",
        "amount_total": 9900,
        "currency": "eur",
        "metadata": {
            "offer": "ola-execution-audit",
            "product": "OLA Execution Audit",
            "tenant_id": "tenant-human-gate-test",
            "task": task,
        },
        "line_items": {"data": [{"price": {"id": price_id}, "quantity": 1}]},
    }
    event_payload = json.dumps({
        "id": event_id,
        "type": "checkout.session.completed",
        "data": {"object": {"id": session_id, "metadata": {"task": "UNTRUSTED"}}},
    }).encode()

    retrieved = []
    executed = []
    monkeypatch.setenv("OLA_STRIPE_PRICE_ID", price_id)
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test")
    monkeypatch.setattr(stripe_webhook, "verify_stripe_signature", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        stripe_webhook, "retrieve_checkout",
        lambda sid: retrieved.append(sid) or fresh_session,
        raising=False,
    )
    monkeypatch.setattr(
        stripe_webhook, "run_agent_task",
        lambda *args, **kwargs: executed.append(args) or {"status": "COMPLETED"},
        raising=False,
    )

    result = stripe_webhook.process_checkout_event(event_payload, "test-signature")

    assert retrieved == [session_id], "webhook must retrieve the authoritative Stripe session"
    assert result["status"] == "PAID_PENDING_HUMAN_GATE"
    assert result["checkout_session_id"] == session_id
    assert executed == [], "payment webhook must never execute an agent"

    with SessionLocal() as db:
        stored = db.scalar(select(StripeEvent).where(StripeEvent.event_id == event_id))
        assert stored is not None
        assert stored.status == "PAID_PENDING_HUMAN_GATE"
        assert stored.run_id is None
