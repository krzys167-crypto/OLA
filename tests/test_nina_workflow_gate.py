from app.api_key_hashing import api_key_fingerprint
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
                          key_hash=api_key_fingerprint(key)))
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
    key_hash = api_key_fingerprint(keys[0])
    with SessionLocal() as db:
        row = db.scalar(select(ApiKey).where(ApiKey.key_hash == key_hash))
        tenant_id = row.tenant_id
    evidence = read_tenant_evidence(tenant_id)
    repeated_report = verify_dag_records(evidence, tenant_id=tenant_id,
                                         run_id=result["run_id"], expected_commit="verified-unit-commit")
    assert repeated_report["status"] == "VERIFIED", repeated_report


def test_refresh_recovers_from_concurrent_tenant_evidence_without_mutation(monkeypatch):
    from sqlalchemy import select
    keys, identities, result = setup_workflow(monkeypatch)
    report = result["igor"]
    with SessionLocal() as db:
        tenant = db.scalar(select(ApiKey.tenant_id).where(
            ApiKey.key_hash == api_key_fingerprint(keys[0])))
    append_record(tenant, "customer.proof", {"event": "external-note"})
    stale = approval_request(keys[1], result["run_id"],
                             report["chain_tip"], report["report_digest"])
    assert stale.status_code == 409
    before = len(read_tenant_evidence(tenant))
    response = TestClient(app).get(
        f"/nina-workflow/{result['run_id']}/report",
        headers={"Authorization": f"Bearer {keys[1]}"})
    assert response.status_code == 200, response.text
    new = response.json()
    assert new["tip_hash"] != report["chain_tip"]
    assert new["report_digest"] != report["report_digest"]
    assert new["production_authorized"] is False
    assert len(read_tenant_evidence(tenant)) == before
    approved = approval_request(keys[1], result["run_id"],
                                new["tip_hash"], new["report_digest"])
    assert approved.status_code == 200, approved.text
    assert approved.json()["production_authorized"] is False


def test_approval_verification_does_not_hold_database_writer_lock(monkeypatch):
    import sqlite3
    import app.nina_workflow_gate as workflow_gate
    from app.database import DB_PATH
    keys, identities, result = setup_workflow(monkeypatch)
    original = workflow_gate.verify_dag_records
    observed = []
    def checked(*args, **kwargs):
        with sqlite3.connect(DB_PATH, timeout=0.05) as other_connection:
            other_connection.execute("BEGIN IMMEDIATE")
            other_connection.rollback()
        observed.append("independent read completed without writer lock")
        return original(*args, **kwargs)
    monkeypatch.setattr(workflow_gate, "verify_dag_records", checked)
    response = approval_request(keys[1], result["run_id"],
        result["igor"]["chain_tip"], result["igor"]["report_digest"])
    assert response.status_code == 200, response.text
    assert observed == ["independent read completed without writer lock"]


def test_refresh_report_requires_tenant_authentication(monkeypatch):
    _, _, result = setup_workflow(monkeypatch)
    r = TestClient(app).get(f"/nina-workflow/{result['run_id']}/report")
    assert r.status_code == 401
