import hashlib
import uuid

from fastapi.testclient import TestClient

from app.main import app
from app.database import SessionLocal
from app.models import ApiKey, Tenant
from app.agent_runtime import AGENT_ROLES, run_agent_task, verify_agent_run


def _seed_tenant(api_key="agent-key"):
    tenant_id = str(uuid.uuid4())
    db = SessionLocal()
    db.add(Tenant(id=tenant_id, name="agent-runtime-test"))
    db.commit()
    db.add(ApiKey(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        key_hash=hashlib.sha256(api_key.encode()).hexdigest(),
    ))
    db.commit()
    db.close()
    return tenant_id


def test_six_agent_runtime_is_ordered_and_verified():
    tenant_id = _seed_tenant("agent-key-1")
    result = run_agent_task(tenant_id, "calculate 6 * 7")

    assert result["status"] == "VERIFIED" and result["computation"] == "PERFORMED"
    assert result["agents"] == AGENT_ROLES
    assert result["evidence_count"] == 6
    assert verify_agent_run(tenant_id, result["run_id"])["status"] == "VERIFIED"


def test_six_agents_have_independent_execution_identity_and_context():
    tenant_id = _seed_tenant("agent-key-independence")
    result = run_agent_task(tenant_id, "prove independent agent execution")

    executions = result["execution"]
    assert len(executions) == 6
    assert [item["agent"] for item in executions] == AGENT_ROLES
    assert len({item["agent_instance_id"] for item in executions}) == 6
    assert len({item["context_digest"] for item in executions}) == 6
    assert all(item["execution_boundary"] == "independent" for item in executions)
    assert all(item["invocation_type"] == "local_deterministic_model" for item in executions)


def test_independent_verifier_rejects_missing_agent_evidence():
    tenant_id = _seed_tenant("agent-key-2")
    result = run_agent_task(tenant_id, "calculate 1 + 1")

    assert verify_agent_run(tenant_id, str(uuid.uuid4()))["status"] in {"UNKNOWN", "BLOCK"}
    assert result["status"] == "VERIFIED"


def test_a_task_with_nothing_to_compute_is_unknown_not_verified():
    """The chain is intact, but no work was done: reporting VERIFIED would be theater."""
    tenant_id = _seed_tenant("agent-key-noop")
    result = run_agent_task(tenant_id, "task with complete evidence")
    assert result["status"] == "UNKNOWN" and result["computation"] == "NOT_PERFORMED"
    assert verify_agent_run(tenant_id, result["run_id"])["status"] == "VERIFIED"   # integrity is a separate fact


def test_agent_runtime_http_endpoint():
    _seed_tenant("agent-key")
    client = TestClient(app)
    response = client.post(
        "/agent-run",
        headers={"X-API-Key": "agent-key"},
        json={"task": "calculate 2 + 2"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "VERIFIED"
