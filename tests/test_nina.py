import pytest

from app.nina import NinaOrchestrator, NinaTask


def test_nina_creates_deterministic_task_contract():
    task = NinaTask.create("tenant-1", "Calculate 17 * 23", ["safe_expression"])
    assert task.tenant_id == "tenant-1"
    assert task.task == "Calculate 17 * 23"
    assert task.requested_tools == ("safe_expression",)
    assert task.task_id


def test_nina_rejects_empty_task():
    with pytest.raises(ValueError, match="task is required"):
        NinaTask.create("tenant-1", "", [])


def test_nina_denies_unknown_tool():
    orchestrator = NinaOrchestrator()
    task = NinaTask.create("tenant-1", "Calculate 17 * 23", ["shell"])
    decision = orchestrator.plan(task)
    assert decision.status == "BLOCK"
    assert decision.allowed_tools == ()
    assert "unknown tool" in decision.reason


def test_nina_allows_registered_tool():
    orchestrator = NinaOrchestrator()
    task = NinaTask.create("tenant-1", "Calculate 17 * 23", ["safe_expression"])
    decision = orchestrator.plan(task)
    assert decision.status == "ALLOW"
    assert decision.allowed_tools == ("safe_expression",)


from app.agent_runtime import _invoke_llm, run_agent_task
from app.database import SessionLocal
from app.models import EvidenceRecord, Tenant
from scripts.verify_agent_runtime import verify


def _seed_runtime_tenant():
    tenant_id = f"semantic-{uuid.uuid4()}"
    db = SessionLocal()
    db.add(Tenant(id=tenant_id, name="semantic-closure-test"))
    db.commit()
    db.close()
    return tenant_id


def test_real_llm_output_is_causal(monkeypatch):
    tenant_id = _seed_runtime_tenant()
    monkeypatch.setenv("OLA_LLM_MODE", "required")
    monkeypatch.setenv("OLA_LLM_PROVIDER", "openai")

    def fake_llm(*args, **kwargs):
        return {
            "provider": "openai",
            "model": "test-model",
            "invocation_type": "real_llm",
            "prompt_digest": "p",
            "output": '{"action":"safe_expression","result":"392"}',
            "response_id": "resp-test",
        }

    monkeypatch.setattr("app.agent_runtime._invoke_llm", fake_llm)

    with pytest.raises(RuntimeError, match="LLM proposed result"):
        run_agent_task(tenant_id, "Calculate 17 * 23 and return the verified result.")


def test_runtime_evidence_contains_canonical_source_sha(monkeypatch):
    tenant_id = _seed_runtime_tenant()
    source_sha = "source-sha-test"
    monkeypatch.setenv("OLA_SOURCE_COMMIT", source_sha)

    result = run_agent_task(tenant_id, "verify source binding")

    db = SessionLocal()
    rows = db.query(EvidenceRecord).filter(EvidenceRecord.tenant_id == tenant_id).order_by(EvidenceRecord.seq.asc()).all()
    db.close()
    assert result["source_commit"] == source_sha
    assert len(rows) == 6
    assert all(json.loads(row.payload_json)["source_commit"] == source_sha for row in rows)


def test_independent_verifier_rejects_source_commit_mismatch(monkeypatch):
    tenant_id = _seed_runtime_tenant()
    monkeypatch.setenv("OLA_SOURCE_COMMIT", "source-sha-canonical")

    result = run_agent_task(tenant_id, "verify source binding")

    verified = verify(
        tenant_id,
        result["run_id"],
        expected_commit="source-sha-other",
        expected_task="verify source binding",
        expected_result=result["final_result"],
    )
    assert verified["status"] == "BLOCK"


def test_ollama_without_provider_id_keeps_response_digest(monkeypatch):
    monkeypatch.setenv("OLA_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("OLA_LLM_MODE", "required")
    monkeypatch.setenv("OLA_LLM_MODEL", "qwen2.5:0.5b-instruct")

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "model": "qwen2.5:0.5b-instruct",
                "message": {"content": '{"action":"safe_expression","result":"391"}'},
            }

    import httpx
    monkeypatch.setattr(httpx, "post", lambda *args, **kwargs: FakeResponse())

    evidence = _invoke_llm("codeact", "Calculate 17 * 23", {})
    assert evidence["response_id"] is None
    assert evidence["response_digest"]
