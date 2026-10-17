import hashlib
import uuid

from fastapi.testclient import TestClient
from app.database import SessionLocal
from app.main import app, append_record, read_tenant_evidence
from app.models import Tenant, ApiKey
from app.nina_workflow import run_nina_workflow
from app.workflow_engine import validate_plan


def setup_workflow(monkeypatch):
    monkeypatch.setenv("OLA_RUNTIME_COMMIT", "verified-unit-commit")
    tenant = str(uuid.uuid4())
    keys = [f"review-key-{uuid.uuid4()}" for _ in range(2)]
    identities = [str(uuid.uuid4()) for _ in range(2)]
    with SessionLocal() as db:
        db.add(Tenant(id=tenant, name="review-gate-test"))
        db.commit()
        for key, identity in zip(keys, identities):
            db.add(ApiKey(id=identity, tenant_id=tenant,
                          key_hash=hashlib.sha256(key.encode()).hexdigest()))
        db.commit()
    nodes = validate_plan({"nodes": [
        {"id": "task", "tool": "safe_expression", "task": "2+2", "needs": []},
    ]}, allowed_tools={"safe_expression"})
    result = run_nina_workflow(
        tenant_id=tenant, requester_id=identities[0], goal="2+2",
        allowed_tools=["safe_expression"], append=append_record,
        fetch_records=read_tenant_evidence,
        planner=lambda g, tools: (nodes, {"provider": "test", "model": "test", "response_id": "plan1"}),
        executor=lambda node, deps: "4",
    )
    assert result["igor"]["status"] == "VERIFIED", result
    return keys, identities, result


def approval_request(key, run_id, tip, digest, reason="I independently reviewed"):
    return TestClient(app).post(f"/nina-workflow/{run_id}/approve",
        headers={"Authorization": f"Bearer {key}"},
        json={"tip_hash": tip, "report_digest": digest, "reason": reason})


def test_human_gate_binds_tip_report_and_separate_identity(monkeypatch):
    keys, identities, result = setup_workflow(monkeypatch)
    report = result["igor"]
    refused = approval_request(keys[0], result["run_id"],
                               report["chain_tip"], report["report_digest"])
    assert refused.status_code == 403, refused.text
    approved = approval_request(keys[1], result["run_id"],
                                report["chain_tip"], report["report_digest"])
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "APPROVED_FOR_REVIEW_ONLY"
    assert approved.json()["production_authorized"] is False
    repeated = approval_request(keys[1], result["run_id"],
                                report["chain_tip"], report["report_digest"])
    assert repeated.status_code == 409


def test_human_gate_rejects_wrong_report_digest(monkeypatch):
    keys, _, result = setup_workflow(monkeypatch)
    report = result["igor"]
    res = approval_request(keys[1], result["run_id"], report["chain_tip"], "unbound-digest")
    assert res.status_code == 409


def test_independent_report_can_reverify_after_human_approval(monkeypatch):
    from sqlalchemy import select
    from app.models import ApiKey
    from app.igor_workflow import verify_dag_records
    keys, _, result = setup_workflow(monkeypatch)
    report = result["igor"]
    decision = approval_request(keys[1], result["run_id"], report["chain_tip"], report["report_digest"])
    assert decision.status_code == 200, decision.text
    key_hash = hashlib.sha256(keys[0].encode()).hexdigest()
    with SessionLocal() as db:
        row = db.scalar(select(ApiKey).where(ApiKey.key_hash == key_hash))
        tenant_id = row.tenant_id
    evidence = read_tenant_evidence(tenant_id)
    repeated_report = verify_dag_records(evidence, tenant_id=tenant_id,
                                         run_id=result["run_id"], expected_commit="verified-unit-commit")
    assert repeated_report["status"] == "VERIFIED", repeated_report
