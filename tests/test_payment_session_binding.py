"""Payment success must bind returned execution to the exact Stripe checkout session."""
import importlib
import json
import uuid

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.models import StripeEvent

main = importlib.import_module("app.main")

TASK = "Audit this company workflow for evidence gaps."


def paid_checkout(session_id: str, tenant_id: str) -> dict:
    return {
        "id": session_id,
        "metadata": {
            "tenant_id": tenant_id, "task": TASK, "offer": "ola-execution-audit",
            "product": "OLA Execution Audit",
        },
        "payment_status": "paid", "status": "complete",
    }


def record_completed(session_id: str, run_id: str):
    with SessionLocal() as db:
        db.add(StripeEvent(
            id=str(uuid.uuid4()),
            event_id="evt_" + uuid.uuid4().hex,
            status="COMPLETED",
            task=TASK,
            run_id=run_id,
            result_json=json.dumps({
                "status": "COMPLETED",
                "checkout_session_id": session_id,
                "ola_run_id": run_id,
                "ola_final_result": run_id,
            }),
        ))
        db.commit()


def test_paid_session_cannot_read_other_tenant_completed_task(monkeypatch):
    victim = "cs_test_victim_" + uuid.uuid4().hex
    requester = "cs_test_requester_" + uuid.uuid4().hex
    record_completed(victim, "victim-private-run")
    monkeypatch.setattr(main, "retrieve_checkout", lambda sid: paid_checkout(sid, "tenant-b"))
    response = TestClient(main.app).get("/payment-success", params={"session_id": requester})
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["status"] == "PAYMENT_CONFIRMED_EXECUTION_PENDING", payload
    assert "victim-private-run" not in response.text


def test_same_task_uses_exact_checkout_session(monkeypatch):
    first = "cs_test_first_" + uuid.uuid4().hex
    second = "cs_test_second_" + uuid.uuid4().hex
    record_completed(first, "run-first")
    record_completed(second, "run-second")
    monkeypatch.setattr(main, "retrieve_checkout", lambda sid: paid_checkout(sid, "tenant-a"))
    response = TestClient(main.app).get("/payment-success", params={"session_id": second})
    assert response.status_code == 200
    assert response.json()["status"] == "COMPLETED"
    assert response.json()["run_id"] == "run-second", response.json()


def test_missing_legacy_session_binding_never_promotes(monkeypatch):
    requested = "cs_test_unbound_" + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(StripeEvent(
            id=str(uuid.uuid4()),
            event_id="evt_" + uuid.uuid4().hex,
            status="COMPLETED",
            task=TASK,
            run_id="unbound-legacy-run",
            result_json=json.dumps({"status": "COMPLETED", "ola_run_id": "unbound-legacy-run"}),
        ))
        db.commit()
    monkeypatch.setattr(main, "retrieve_checkout", lambda sid: paid_checkout(sid, "tenant-x"))
    result = TestClient(main.app).get("/payment-success", params={"session_id": requested})
    assert result.status_code == 200
    assert result.json()["status"] == "PAYMENT_CONFIRMED_EXECUTION_PENDING", result.json()
