import hashlib
import uuid

from fastapi.testclient import TestClient

from app.main import app
from app.database import SessionLocal
from app.models import Tenant, ApiKey
import app.agent_runtime as agent_runtime


def _tenant(key):
    with SessionLocal() as db:
        tenant_id = str(uuid.uuid4())
        db.add(Tenant(id=tenant_id, name="parallel-workflow-test"))
        db.commit()
        db.add(ApiKey(id=str(uuid.uuid4()), tenant_id=tenant_id,
                      key_hash=hashlib.sha256(key.encode()).hexdigest()))
        db.commit()


def test_workflow_endpoint_is_disabled_by_default(monkeypatch):
    key = f"workflow-gate-{uuid.uuid4()}"
    _tenant(key)
    monkeypatch.delenv("OLA_PARALLEL_WORKFLOWS_ENABLED", raising=False)
    response = TestClient(app).post("/nina-workflow",
        headers={"X-API-Key": key}, json={"task": "analyse the goal"})
    assert response.status_code == 503
    assert "disabled" in response.json()["detail"]


def test_workflow_endpoint_runs_real_route_with_mocked_external_model(monkeypatch):
    key = f"workflow-enabled-{uuid.uuid4()}"
    _tenant(key)
    monkeypatch.setenv("OLA_PARALLEL_WORKFLOWS_ENABLED", "1")
    calls = []

    def fake_provider(agent, task, context):
        calls.append(agent)
        if agent == "nina_dag_planner":
            return {
                "invocation_type": "real_llm", "response_id": "plan-response-id",
                "provider": "ollama", "model": "mock-model",
                "output": '{"nodes":[{"id":"analyst","tool":"llm_agent","task":"analyse","needs":[]},'
                          '{"id":"reviewer","tool":"llm_agent","task":"review","needs":["analyst"]}]}',
            }
        return {
            "invocation_type": "real_llm", "response_id": f"agent-{agent}",
            "provider": "ollama", "model": "mock-model", "output": f"result:{agent}",
        }

    monkeypatch.setattr(agent_runtime, "_invoke_llm", fake_provider)
    response = TestClient(app).post("/nina-workflow",
        headers={"X-API-Key": key}, json={"task": "analyse, review and report"})
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "COMPLETED_UNVERIFIED"
    assert body["verified"] is False
    assert body["human_gate"] == "NOT_APPROVED"
    assert len(body["evidence_ids"]) == 6
    assert calls == ["nina_dag_planner", "analyst", "reviewer"]
