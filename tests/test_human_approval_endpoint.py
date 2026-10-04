import hashlib
import uuid

from fastapi.testclient import TestClient
from app import main
from app.database import SessionLocal
from app.models import ApiKey, Tenant


def _candidate(*, runtime_status="VERIFIED", aggregate="REVIEW"):
    tenant_id, requester_id, approver_id, run_id = (str(uuid.uuid4()) for _ in range(4))
    requester_key, approver_key = "request-" + uuid.uuid4().hex, "approve-" + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="approval-regression"))
        for key_id, raw_key in ((requester_id, requester_key), (approver_id, approver_key)):
            db.add(ApiKey(id=key_id, tenant_id=tenant_id, key_hash=hashlib.sha256(raw_key.encode()).hexdigest()))
        db.commit()
    fields = {"RUNTIME": runtime_status, "EVIDENCE": "VERIFIED", "REPLAY_INTEGRITY": "VERIFIED", "POLICY": "VERIFIED", "HUMAN_GATE": "REVIEW", "EXECUTION_ALLOWED": aggregate}
    record = main.append_record(tenant_id, "decision.candidate", {"run_id": run_id, "requester_id": requester_id, "status_fields": fields, "candidate_status": aggregate})
    return run_id, record["record_hash"], requester_key, approver_key


def _approve(run_id, tip_hash, key):
    return TestClient(main.app).post(f"/nina-run/{run_id}/approve", headers={"Authorization": f"Bearer {key}"}, json={"tip_hash": tip_hash, "reason": "explicit test approver"})


def test_separate_approver_can_approve_eligible_candidate():
    run_id, tip_hash, _, approver_key = _candidate()
    response = _approve(run_id, tip_hash, approver_key)
    assert response.status_code == 200, response.text
    assert response.json()["record_type"] == "human.approval"
    assert response.json()["status"] == "VERIFIED"
    assert _approve(run_id, tip_hash, approver_key).status_code == 409


def test_requester_cannot_self_approve():
    run_id, tip_hash, requester_key, _ = _candidate()
    assert _approve(run_id, tip_hash, requester_key).status_code == 403


def test_approver_cannot_promote_blocked_runtime():
    run_id, tip_hash, _, approver_key = _candidate(runtime_status="BLOCK", aggregate="BLOCK")
    assert _approve(run_id, tip_hash, approver_key).status_code == 409


def test_inconsistent_candidate_aggregate_is_rejected():
    run_id, tip_hash, _, approver_key = _candidate(runtime_status="BLOCK", aggregate="REVIEW")
    assert _approve(run_id, tip_hash, approver_key).status_code == 409
