"""Red-phase regression tests for human approval evidence integrity."""
import hashlib
import json
import uuid

from fastapi.testclient import TestClient

from app.api_key_crypto import hash_api_key
from app.database import SessionLocal
from app.hashchain import GENESIS_HASH
from app.main import app, append_record
from app.models import ApiKey, EvidenceRecord, Tenant


def setup_review():
    tenant_id = str(uuid.uuid4())
    requester_id = str(uuid.uuid4())
    approver_id = str(uuid.uuid4())
    requester_key = "requester-" + str(uuid.uuid4())
    approver_key = "approver-" + str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="human-gate-security"))
        db.flush()
        db.add_all([
            ApiKey(id=requester_id, tenant_id=tenant_id, key_hash=hash_api_key(requester_key)),
            ApiKey(id=approver_id, tenant_id=tenant_id, key_hash=hash_api_key(approver_key)),
        ])
        db.commit()
    return tenant_id, requester_id, approver_key


def candidate(tenant_id, requester_id, run_id, policy="VERIFIED"):
    return append_record(tenant_id, "decision.candidate", {
        "run_id": run_id, "requester_id": requester_id,
        "status_fields": {
            "RUNTIME": "VERIFIED", "EVIDENCE": "VERIFIED",
            "REPLAY_INTEGRITY": "VERIFIED", "POLICY": policy,
            "HUMAN_GATE": "REVIEW",
            "EXECUTION_ALLOWED": "REVIEW",
        },
        "candidate_status": "REVIEW",
    })


def approve(approver_key, run_id, tip_hash):
    return TestClient(app).post(
        f"/nina-run/{run_id}/approve",
        headers={"Authorization": f"Bearer {approver_key}"},
        json={"tip_hash": tip_hash},
    )


def test_human_approval_rejects_tampered_chain_even_at_current_tip():
    tenant, requester_id, approver_key = setup_review()
    run_id = "run-" + str(uuid.uuid4())
    first = candidate(tenant, requester_id, run_id)
    with SessionLocal() as db:
        db.add(EvidenceRecord(
            id=str(uuid.uuid4()), tenant_id=tenant, seq=1,
            record_type="generic", payload_json=json.dumps({"note": "inserted"}),
            prev_hash=first["record_hash"], record_hash="f"*64,
        ))
        db.commit()
    outcome = approve(approver_key, run_id, "f"*64)
    assert outcome.status_code == 409, outcome.json()


def test_human_approval_rejects_old_candidate_superseded_by_blocked_one():
    tenant, requester_id, approver_key = setup_review()
    run_id = "run-" + str(uuid.uuid4())
    candidate(tenant, requester_id, run_id)
    newer = candidate(tenant, requester_id, run_id, policy="BLOCK")
    outcome = approve(approver_key, run_id, newer["record_hash"])
    assert outcome.status_code == 409, outcome.json()


def test_human_approval_is_single_use_even_with_fresh_tip():
    tenant, requester_id, approver_key = setup_review()
    run_id = "run-" + str(uuid.uuid4())
    current = candidate(tenant, requester_id, run_id)
    first = approve(approver_key, run_id, current["record_hash"])
    assert first.status_code == 200, first.json()
    repeated = approve(approver_key, run_id, first.json()["tip_hash"])
    assert repeated.status_code == 409, repeated.json()


def test_human_approval_accepts_clean_current_chain():
    tenant, requester_id, approver_key = setup_review()
    run_id = "run-" + str(uuid.uuid4())
    current = candidate(tenant, requester_id, run_id)
    outcome = approve(approver_key, run_id, current["record_hash"])
    assert outcome.status_code == 200, outcome.json()
