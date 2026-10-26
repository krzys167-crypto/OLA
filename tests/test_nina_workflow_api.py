from app.api_key_hashing import api_key_fingerprint
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
                      key_hash=api_key_fingerprint(key)))
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


def test_external_api_cannot_forge_dag_runtime_provenance():
    """Untrusted callers must never create trusted workflow/approval events."""
    from sqlalchemy import select
    from app.models import EvidenceRecord

    key = f"workflow-spoof-{uuid.uuid4()}"
    _tenant(key)
    client = TestClient(app)
    for record_type in (
        "workflow.planned", "task.started", "task.completed",
        "workflow.completed", "human.workflow_approval",
    ):
        result = client.post("/evidence", headers={"X-API-Key": key},
                             json={"record_type": record_type, "payload": {
                                 "event": record_type, "requester_id": "faked-other-user",
                             }})
        assert result.status_code == 403, (record_type, result.text)

    with SessionLocal() as db:
        tenant_id = db.scalar(
            select(ApiKey.tenant_id).where(
                ApiKey.key_hash == api_key_fingerprint(key)
            )
        )
        assert db.scalars(
            select(EvidenceRecord).where(
                EvidenceRecord.tenant_id == tenant_id,
                EvidenceRecord.record_type.in_((
                    "workflow.planned", "task.started", "task.completed",
                    "workflow.completed", "human.workflow_approval",
                ))
            )
        ).first() is None


def test_external_api_still_accepts_unreserved_evidence():
    key = f"workflow-evidence-{uuid.uuid4()}"
    _tenant(key)
    result = TestClient(app).post(
        "/evidence", headers={"X-API-Key": key},
        json={"record_type": "customer.proof", "payload": {"kind": "customer"}},
    )
    assert result.status_code == 200, result.text
    assert result.json()["record_hash"]


def test_nina_parallel_gate_checks_out_exact_head_on_pr_and_runs_on_main_push():
    from pathlib import Path
    source = (Path(__file__).resolve().parents[1]
              / ".github/workflows/nina-parallel-dag.yml").read_text()
    assert "\n  push:\n    branches: [main]\n" in source
    assert "\n  pull_request:\n    branches: [main]\n" in source
    assert "    paths:" not in source  # required gate cannot be skipped by path filters
    assert "ref: ${{ github.event.pull_request.head.sha || github.sha }}" in source
    assert "git rev-parse HEAD" in source


def test_final_production_gate_attests_actual_checked_out_commit():
    from pathlib import Path
    source = (Path(__file__).resolve().parents[1]
              / ".github/workflows/final-production-gate.yml").read_text()
    assert "ref: ${{ steps.target.outputs.sha }}" in source
    assert "git rev-parse HEAD" in source

def test_workflow_runtime_error_does_not_expose_internal_exception(monkeypatch):
    import app.main as main_module
    key = f"workflow-redact-{uuid.uuid4()}"
    _tenant(key)
    monkeypatch.setenv("OLA_PARALLEL_WORKFLOWS_ENABLED", "1")
    def broken_runtime(**kwargs):
        raise RuntimeError("secret-internal-connector-details")
    monkeypatch.setattr(main_module, "run_nina_workflow", broken_runtime)
    response = TestClient(app).post(
        "/nina-workflow", headers={"X-API-Key": key}, json={"task": "analyse"})
    assert response.status_code == 503
    assert response.json()["detail"] == "workflow runtime unavailable"
    assert "secret" not in response.text

def test_parallel_workflow_blocks_duplicate_or_unbounded_tools_before_planner(monkeypatch):
    import app.main as main_module

    key = f"workflow-bounded-{uuid.uuid4()}"
    _tenant(key)
    monkeypatch.setenv("OLA_PARALLEL_WORKFLOWS_ENABLED", "1")
    invoked = []
    monkeypatch.setattr(main_module, "run_nina_workflow",
                        lambda **kwargs: invoked.append(kwargs) or {"status": "SHOULD_NOT_EXECUTE"})
    client = TestClient(app)
    for bad_tools in (["llm_agent", "llm_agent"],
                      ["llm_agent"] * 30, [""]):
        response = client.post(
            "/nina-workflow", headers={"X-API-Key": key},
            json={"task": "review", "requested_tools": bad_tools},
        )
        assert response.status_code == 400, (bad_tools, response.text)
    assert invoked == []


def test_real_ollama_gate_installs_checksum_verified_release():
    from pathlib import Path
    source = (Path(__file__).resolve().parents[1] /
              ".github/workflows/nina-parallel-dag.yml").read_text()
    assert 'ollama_version="v0.40.6"' in source
    assert "c164ab8b1b28e2a247c29719b8e404c423c5b83ae64c3ab4e59d50c7ff7fc5e0" in source
    assert "sha256sum --check -" in source
    assert "https://ollama.com/install.sh" not in source


def test_workstation_requires_signed_source_pin_and_hashing_module():
    from pathlib import Path
    source = (Path(__file__).resolve().parents[1] /
              "workstation/OLA-Workstation.ps1").read_text()
    assert "426e781ba6e8bc2c17f6ed3bf1150372d673bc07" not in source
    assert "OLA_WORKSTATION_SOURCE_SHA" in source
    assert "OLA_SIGNER_FINGERPRINT" in source
    assert "git verify-commit $SourceCommit" in source
    assert "app/api_key_hashing.py" in source
    assert source.index("git verify-commit") < source.index("docker build")


def test_public_evidence_rejects_non_object_payload_without_poisoning_tenant():
    key = f"evidence-schema-{uuid.uuid4()}"
    _tenant(key)
    client = TestClient(app)
    for payload in (None, [], ["not-an-event"], "scalar", 42):
        res = client.post("/evidence", headers={"X-API-Key": key},
            json={"record_type": "customer.proof", "payload": payload})
        assert res.status_code == 400, (payload, res.text)
    valid = client.post("/evidence", headers={"X-API-Key": key},
        json={"record_type": "customer.proof", "payload": {"kind": "valid"}})
    assert valid.status_code == 200, valid.text
