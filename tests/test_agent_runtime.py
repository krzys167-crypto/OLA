from app.api_key_hashing import api_key_fingerprint
import uuid

from fastapi.testclient import TestClient

from app.main import app
from app.database import SessionLocal
from app.models import ApiKey, Tenant
from app.agent_runtime import AGENT_ROLES, run_agent_task, verify_agent_run

TEST_SOURCE_COMMIT = "d" * 40
WRONG_SOURCE_COMMIT = "e" * 40


def _seed_tenant(api_key="agent-key"):
    tenant_id = str(uuid.uuid4())
    db = SessionLocal()
    db.add(Tenant(id=tenant_id, name="agent-runtime-test"))
    db.commit()
    db.add(ApiKey(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        key_hash=api_key_fingerprint(api_key),
    ))
    db.commit()
    db.close()
    return tenant_id


def test_six_agent_runtime_is_ordered_and_verified(monkeypatch):
    monkeypatch.setenv("OLA_RUNTIME_COMMIT", TEST_SOURCE_COMMIT)
    tenant_id = _seed_tenant("agent-key-1")
    result = run_agent_task(tenant_id, "verify an evidence-backed task")

    assert result["status"] == "VERIFIED"
    assert result["agents"] == AGENT_ROLES
    assert result["evidence_count"] == 6
    assert verify_agent_run(tenant_id, result["run_id"])["status"] == "VERIFIED"


def test_six_agents_have_independent_execution_identity_and_context(monkeypatch):
    monkeypatch.setenv("OLA_RUNTIME_COMMIT", TEST_SOURCE_COMMIT)
    tenant_id = _seed_tenant("agent-key-independence")
    result = run_agent_task(tenant_id, "prove independent agent execution")

    executions = result["execution"]
    assert len(executions) == 6
    assert [item["agent"] for item in executions] == AGENT_ROLES
    assert len({item["agent_instance_id"] for item in executions}) == 6
    assert len({item["context_digest"] for item in executions}) == 6
    assert all(item["execution_boundary"] == "independent" for item in executions)
    assert all(item["invocation_type"] == "local_deterministic_model" for item in executions)


def test_internal_verifier_rejects_missing_runtime_commit(monkeypatch):
    monkeypatch.delenv("OLA_RUNTIME_COMMIT", raising=False)
    tenant_id = _seed_tenant("agent-key-missing-commit")
    result = run_agent_task(tenant_id, "task without a trusted source identity")

    assert result["status"] == "BLOCK", result
    assert result["evidence_count"] == 0
    assert result["execution"] == []
    assert "runtime source commit" in result.get("reason", "").lower()


def test_internal_verifier_rejects_invalid_runtime_commit(monkeypatch):
    monkeypatch.setenv("OLA_RUNTIME_COMMIT", "not-a-commit")
    tenant_id = _seed_tenant("agent-key-invalid-commit")
    result = run_agent_task(tenant_id, "task with malformed source identity")

    assert result["status"] == "BLOCK", result
    assert result["evidence_count"] == 0
    assert "runtime source commit" in result.get("reason", "").lower()


def test_internal_verifier_rejects_runtime_commit_mismatch(monkeypatch):
    monkeypatch.setenv("OLA_RUNTIME_COMMIT", TEST_SOURCE_COMMIT)
    tenant_id = _seed_tenant("agent-key-mismatched-commit")
    result = run_agent_task(tenant_id, "task with a changed source identity")
    assert result["status"] == "VERIFIED", result

    monkeypatch.setenv("OLA_RUNTIME_COMMIT", WRONG_SOURCE_COMMIT)
    proof = verify_agent_run(tenant_id, result["run_id"])
    assert proof["status"] == "BLOCK", proof
    assert "commit" in proof["reason"].lower()


def test_independent_verifier_rejects_missing_agent_evidence(monkeypatch):
    monkeypatch.setenv("OLA_RUNTIME_COMMIT", TEST_SOURCE_COMMIT)
    tenant_id = _seed_tenant("agent-key-2")
    result = run_agent_task(tenant_id, "task with complete evidence")

    assert verify_agent_run(tenant_id, str(uuid.uuid4()))["status"] in {"UNKNOWN", "BLOCK"}
    assert result["status"] == "VERIFIED"


def test_agent_runtime_http_endpoint(monkeypatch):
    monkeypatch.setenv("OLA_RUNTIME_COMMIT", TEST_SOURCE_COMMIT)
    _seed_tenant("agent-key")
    client = TestClient(app)
    response = client.post(
        "/agent-run",
        headers={"X-API-Key": "agent-key"},
        json={"task": "runtime agent verification"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "VERIFIED"


def test_agent_runtime_http_endpoint_blocks_unknown_commit(monkeypatch):
    monkeypatch.delenv("OLA_RUNTIME_COMMIT", raising=False)
    _seed_tenant("agent-key-no-commit")
    client = TestClient(app)
    response = client.post(
        "/agent-run",
        headers={"X-API-Key": "agent-key-no-commit"},
        json={"task": "runtime without source identity"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "BLOCK"
