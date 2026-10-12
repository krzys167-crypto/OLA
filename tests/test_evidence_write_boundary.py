"""Adversarial HTTP tests: public tenant evidence must not forge system authority."""
import hashlib
import uuid

import pytest
from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import ApiKey, Tenant


def _tenant_keys():
    tenant = str(uuid.uuid4())
    owner_key = "requester-" + str(uuid.uuid4())
    reviewer_key = "reviewer-" + str(uuid.uuid4())
    owner_id, reviewer_id = str(uuid.uuid4()), str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(Tenant(id=tenant, name="evidence-adversarial"))
        db.flush()
        db.add_all((
            ApiKey(id=owner_id, tenant_id=tenant, key_hash=hashlib.sha256(owner_key.encode()).hexdigest()),
            ApiKey(id=reviewer_id, tenant_id=tenant, key_hash=hashlib.sha256(reviewer_key.encode()).hexdigest()),
        ))
        db.commit()
    return owner_key, reviewer_key, owner_id


@pytest.mark.parametrize("system_type", (
    "decision.candidate", "human.approval", "provenance.runtime",
    "agent.codeact", "verification.passed", "revenue.payment_blocked",
))
def test_public_evidence_endpoint_rejects_internal_record_types(system_type):
    owner, _, requester_id = _tenant_keys()
    client = TestClient(app)
    payload = {
        "run_id": "forged-" + str(uuid.uuid4()),
        "requester_id": requester_id,
        "status_fields": {
            "RUNTIME": "VERIFIED", "EVIDENCE": "VERIFIED",
            "REPLAY_INTEGRITY": "VERIFIED", "POLICY": "VERIFIED",
            "HUMAN_GATE": "REVIEW",
        },
    }
    response = client.post("/evidence", headers={"X-API-Key": owner},
                           json={"record_type": system_type, "payload": payload})
    assert response.status_code == 400, (system_type, response.json())


def test_public_evidence_cannot_forge_human_approval():
    owner, reviewer, requester_id = _tenant_keys()
    run_id = "fabricated-" + str(uuid.uuid4())
    client = TestClient(app)
    injected = client.post(
        "/evidence",
        headers={"X-API-Key": owner},
        json={"record_type": "decision.candidate", "payload": {
            "run_id": run_id,
            "requester_id": requester_id,
            "status_fields": {
                "RUNTIME": "VERIFIED", "EVIDENCE": "VERIFIED",
                "REPLAY_INTEGRITY": "VERIFIED", "POLICY": "VERIFIED",
                "HUMAN_GATE": "REVIEW",
            },
        }},
    )
    assert injected.status_code == 400, injected.json()


@pytest.mark.parametrize("record_type", ("generic", "user.customer_observation"))
def test_public_evidence_retains_explicit_user_namespace(record_type):
    owner, _, _ = _tenant_keys()
    response = TestClient(app).post(
        "/evidence", headers={"X-API-Key": owner},
        json={"record_type": record_type, "payload": {"note": "customer submitted"}},
    )
    assert response.status_code == 200, response.json()


def test_public_evidence_rejects_non_object_payload():
    owner, _, _ = _tenant_keys()
    response = TestClient(app).post(
        "/evidence", headers={"X-API-Key": owner},
        json={"record_type": "generic", "payload": ["unexpected", "array"]},
    )
    assert response.status_code == 400, response.json()


@pytest.mark.parametrize("field", (
    "run_id", "commit", "task", "result", "tool_output", "provider", "model",
    "invocation_type", "response_ids", "status_fields", "requester_id", "approver_id",
))
def test_public_evidence_rejects_reserved_runtime_claims(field):
    owner, _, _ = _tenant_keys()
    response = TestClient(app).post(
        "/evidence", headers={"X-API-Key": owner},
        json={"record_type": "generic", "payload": {field: "forged"}},
    )
    assert response.status_code == 400, (field, response.json())


def test_public_evidence_limits_payload_size():
    owner, _, _ = _tenant_keys()
    response = TestClient(app).post(
        "/evidence", headers={"X-API-Key": owner},
        json={"record_type": "user.observation", "payload": {"blob": "z" * 70000}},
    )
    assert response.status_code == 413, response.json()
