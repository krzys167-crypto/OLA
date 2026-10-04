import json
import uuid

from app import main
from app.database import SessionLocal
from app.models import StripeEvent, Tenant


def _completed(tenant_id, session_id, task, *, result_session=None):
    event_id = "evt-" + uuid.uuid4().hex
    run_id = str(uuid.uuid4())
    result = {"status": "COMPLETED", "event_id": event_id, "checkout_session_id": result_session or session_id, "ola_run_id": run_id}
    with SessionLocal() as db:
        if db.get(Tenant, tenant_id) is None:
            db.add(Tenant(id=tenant_id, name="payment-isolation-test"))
        db.add(StripeEvent(id=str(uuid.uuid4()), event_id=event_id, status="COMPLETED", task=task, run_id=run_id, result_json=json.dumps(result)))
        db.commit()
    main.append_record(tenant_id, "stripe.ola_execution_completed", {"stripe_event_id": event_id, "checkout_session_id": session_id, "ola_run_id": run_id})
    return run_id


def _lookup(monkeypatch, tenant_id, session_id, task):
    monkeypatch.setattr(main, "retrieve_checkout", lambda requested: {
        "id": session_id, "payment_status": "paid", "status": "complete",
        "metadata": {"tenant_id": tenant_id, "task": task, "product": "OLA Execution Audit", "offer": "ola-execution-audit"},
    })
    return main.payment_success(session_id)


def test_identical_tasks_for_two_tenants_return_only_own_session(monkeypatch):
    tenant_a, tenant_b = str(uuid.uuid4()), str(uuid.uuid4())
    task = "same-task-" + uuid.uuid4().hex
    session_a, session_b = "cs-" + uuid.uuid4().hex, "cs-" + uuid.uuid4().hex
    foreign_run = _completed(tenant_b, session_b, task)
    own_run = _completed(tenant_a, session_a, task)
    response = _lookup(monkeypatch, tenant_a, session_a, task)
    assert response["status"] == "COMPLETED"
    assert response["run_id"] == own_run
    assert response["run_id"] != foreign_run
    assert response["result"]["checkout_session_id"] == session_a


def test_same_tenant_identical_tasks_do_not_mix_sessions(monkeypatch):
    tenant = str(uuid.uuid4())
    task = "same-task-" + uuid.uuid4().hex
    _completed(tenant, "cs-old-" + uuid.uuid4().hex, task)
    session = "cs-new-" + uuid.uuid4().hex
    own_run = _completed(tenant, session, task)
    assert _lookup(monkeypatch, tenant, session, task)["run_id"] == own_run


def test_other_tenant_evidence_cannot_complete_paid_session(monkeypatch):
    tenant_a, tenant_b = str(uuid.uuid4()), str(uuid.uuid4())
    session = "cs-" + uuid.uuid4().hex
    task = "same-task-" + uuid.uuid4().hex
    _completed(tenant_b, session, task)
    response = _lookup(monkeypatch, tenant_a, session, task)
    assert response["status"] == "PAYMENT_CONFIRMED_EXECUTION_PENDING"
    assert "result" not in response


def test_foreign_session_in_stored_result_is_not_disclosed(monkeypatch):
    tenant, session = str(uuid.uuid4()), "cs-" + uuid.uuid4().hex
    task = "same-task-" + uuid.uuid4().hex
    _completed(tenant, session, task, result_session="cs-foreign")
    response = _lookup(monkeypatch, tenant, session, task)
    assert response["status"] == "PAYMENT_CONFIRMED_EXECUTION_PENDING"
    assert "result" not in response
