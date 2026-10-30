"""Security regression: /payment-success must authenticate the caller and bind
the Checkout Session to the caller's tenant.

A Checkout Session ID is not a credential: it travels in the Stripe redirect
URL, browser history, proxy logs and Referer headers. Before this fix any
caller holding a leaked session ID received another tenant's task text and
paid result, and could write evidence into that tenant's chain.
"""
import io
import json
import urllib.error
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

import app.main as main
from app.api_key_hashing import api_key_fingerprint
from app.database import SessionLocal
from app.models import ApiKey, EvidenceRecord, StripeEvent, Tenant


def _tenant():
    tenant_id = str(uuid.uuid4())
    key = "pay-authz-" + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="payment-authz-test"))
        db.flush()
        db.add(ApiKey(id=str(uuid.uuid4()), tenant_id=tenant_id,
                      key_hash=api_key_fingerprint(key)))
        db.commit()
    return tenant_id, key


def _evidence_count(tenant_id):
    with SessionLocal() as db:
        return db.scalar(select(func.count()).select_from(EvidenceRecord).where(
            EvidenceRecord.tenant_id == tenant_id))


def _completed_run(task, checkout_id, run_id):
    with SessionLocal() as db:
        db.add(StripeEvent(
            id=str(uuid.uuid4()), event_id="evt_" + uuid.uuid4().hex,
            status="COMPLETED", task=task, run_id=run_id,
            result_json=json.dumps({"status": "COMPLETED",
                                    "checkout_session_id": checkout_id,
                                    "ola_run_id": run_id,
                                    "report": "CONFIDENTIAL-" + run_id}),
        ))
        db.commit()


def _session(checkout_id, tenant_id, task, paid=True):
    return {
        "id": checkout_id,
        "payment_status": "paid" if paid else "unpaid",
        "status": "complete" if paid else "open",
        "metadata": {"product": "OLA Execution Audit",
                     "offer": "ola-execution-audit",
                     "tenant_id": tenant_id, "task": task},
    }


@pytest.fixture
def victim(monkeypatch):
    """Tenant A owns a paid, completed Checkout Session; Stripe is mocked."""
    tenant_id, key = _tenant()
    checkout_id = "cs_test_" + uuid.uuid4().hex
    task = "confidential audit of " + tenant_id
    run_id = "run_" + uuid.uuid4().hex[:12]
    _completed_run(task, checkout_id, run_id)
    sessions = {checkout_id: _session(checkout_id, tenant_id, task)}
    calls = []

    def fake_retrieve(sid):
        calls.append(sid)
        if sid == "cs_test_stripe_down":
            raise urllib.error.URLError("connection refused")
        if sid not in sessions:
            # What urllib raises for Stripe's resource_missing response.
            raise urllib.error.HTTPError(
                "https://api.stripe.com/v1/checkout/sessions/" + sid, 404,
                "Not Found", None, io.BytesIO(b"{}"))
        return sessions[sid]

    monkeypatch.setattr(main, "retrieve_checkout", fake_retrieve)
    return {"tenant_id": tenant_id, "key": key, "checkout_id": checkout_id,
            "task": task, "run_id": run_id, "sessions": sessions,
            "calls": calls}


def _get(checkout_id, key=None):
    headers = {"X-API-Key": key} if key is not None else {}
    return TestClient(main.app).get("/payment-success",
                                    params={"session_id": checkout_id},
                                    headers=headers)


def _assert_no_disclosure(response, victim):
    body = response.text
    assert victim["task"] not in body
    assert victim["run_id"] not in body
    assert "CONFIDENTIAL" not in body


def test_leaked_session_id_without_api_key_is_rejected(victim):
    before = _evidence_count(victim["tenant_id"])
    response = _get(victim["checkout_id"])
    assert response.status_code == 401
    _assert_no_disclosure(response, victim)
    # Anonymous callers never reach Stripe and never touch the tenant chain.
    assert victim["calls"] == []
    assert _evidence_count(victim["tenant_id"]) == before


def test_invalid_api_key_is_rejected(victim):
    response = _get(victim["checkout_id"], key="not-a-real-key")
    assert response.status_code == 401
    _assert_no_disclosure(response, victim)
    assert victim["calls"] == []


def test_other_tenant_cannot_read_session_and_gets_no_existence_oracle(victim):
    _, attacker_key = _tenant()
    cross = _get(victim["checkout_id"], key=attacker_key)
    missing = _get("cs_test_does_not_exist", key=attacker_key)
    assert cross.status_code == 404
    _assert_no_disclosure(cross, victim)
    # A foreign session and a non-existent one are indistinguishable.
    assert missing.status_code == 404
    assert cross.json() == missing.json()


def test_stripe_outage_is_502_not_a_disclosure(victim):
    response = _get("cs_test_stripe_down", key=victim["key"])
    assert response.status_code == 502
    _assert_no_disclosure(response, victim)


def test_other_tenant_cannot_write_into_victim_evidence_chain(victim):
    _, attacker_key = _tenant()
    unpaid_id = "cs_test_unpaid_" + uuid.uuid4().hex
    victim["sessions"][unpaid_id] = _session(
        unpaid_id, victim["tenant_id"], victim["task"], paid=False)
    before = _evidence_count(victim["tenant_id"])
    response = _get(unpaid_id, key=attacker_key)
    assert response.status_code == 404
    assert _evidence_count(victim["tenant_id"]) == before


def test_owner_tenant_still_receives_its_own_result(victim):
    response = _get(victim["checkout_id"], key=victim["key"])
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "COMPLETED"
    assert body["run_id"] == victim["run_id"]
    assert body["result"]["checkout_session_id"] == victim["checkout_id"]


def test_session_without_tenant_provenance_is_not_found(victim):
    tenant_id, key = _tenant()
    orphan = "cs_test_orphan_" + uuid.uuid4().hex
    session = _session(orphan, tenant_id, "orphan task")
    del session["metadata"]["tenant_id"]
    victim["sessions"][orphan] = session
    assert _get(orphan, key=key).status_code == 404


def test_stripe_object_for_a_different_id_is_not_trusted(victim):
    swapped = "cs_test_swapped_" + uuid.uuid4().hex
    # Lookup returns the victim's own session object under another ID.
    victim["sessions"][swapped] = victim["sessions"][victim["checkout_id"]]
    response = _get(swapped, key=victim["key"])
    assert response.status_code == 404


def test_owner_unpaid_session_is_blocked_and_logged_to_owner_chain(victim):
    unpaid_id = "cs_test_unpaid_" + uuid.uuid4().hex
    victim["sessions"][unpaid_id] = _session(
        unpaid_id, victim["tenant_id"], victim["task"], paid=False)
    before = _evidence_count(victim["tenant_id"])
    response = _get(unpaid_id, key=victim["key"])
    assert response.status_code == 200
    assert response.json()["status"] == "BLOCK"
    assert _evidence_count(victim["tenant_id"]) == before + 1
