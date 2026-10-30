"""Regression: a paid Checkout Session must not reuse another session's OLA result."""
import json
import uuid

from app import main
from app.api_key_hashing import api_key_fingerprint
from app.database import SessionLocal
from app.models import ApiKey, StripeEvent, Tenant

# /payment-success authenticates the caller and binds the session to its
# tenant (see test_payment_success_authz.py); these tests act as the owner.
UNIT_TENANT = "sandbox-unit-tenant"
UNIT_KEY = "payment-binding-unit-key"


def owner_key():
    with SessionLocal() as db:
        if db.get(Tenant, UNIT_TENANT) is None:
            db.add(Tenant(id=UNIT_TENANT, name="payment-binding-test"))
            db.flush()
            db.add(ApiKey(id=str(uuid.uuid4()), tenant_id=UNIT_TENANT,
                          key_hash=api_key_fingerprint(UNIT_KEY)))
            db.commit()
    return UNIT_KEY


def record_completed_checkout(task, checkout_id, run_id):
    with SessionLocal() as db:
        db.add(StripeEvent(
            id=str(uuid.uuid4()),
            event_id="evt_" + str(uuid.uuid4()),
            status="COMPLETED",
            task=task,
            run_id=run_id,
            result_json=json.dumps({
                "status": "COMPLETED", "checkout_session_id": checkout_id,
                "event_id": "test-event", "ola_run_id": run_id,
            }),
        ))
        db.commit()


def paid_session(checkout_id, task):
    return {
        "id": checkout_id, "payment_status": "paid", "status": "complete",
        "metadata": {
            "product": "OLA Execution Audit", "offer": "ola-execution-audit",
            "tenant_id": UNIT_TENANT, "task": task,
        },
    }


def test_payment_success_binds_result_to_exact_checkout_session(monkeypatch):
    task = "same audit request " + str(uuid.uuid4())
    record_completed_checkout(task, "cs_test_first", "run_first")
    record_completed_checkout(task, "cs_test_second", "run_second")
    monkeypatch.setattr(main, "retrieve_checkout",
                        lambda sid: paid_session(sid, task))
    result = main.payment_success("cs_test_second", x_api_key=owner_key())
    assert result["status"] == "COMPLETED"
    assert result["run_id"] == "run_second"
    assert result["result"]["checkout_session_id"] == "cs_test_second"


def test_payment_success_does_not_disclose_other_session_result(monkeypatch):
    task = "same audit request " + str(uuid.uuid4())
    record_completed_checkout(task, "cs_test_another", "run_other")
    monkeypatch.setattr(main, "retrieve_checkout",
                        lambda sid: paid_session(sid, task))
    result = main.payment_success("cs_test_brand_new", x_api_key=owner_key())
    assert result["status"] == "PAYMENT_CONFIRMED_EXECUTION_PENDING"
    assert "result" not in result
    assert "run_id" not in result
