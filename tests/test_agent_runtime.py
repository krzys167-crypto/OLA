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
    assert "tenant_evidence_hash_chain_integrity" in result["verification_scope"]
    assert "isolated_or_independent_agent_processes" in result["not_established"]


def test_six_agents_have_unique_in_process_identity_and_context(monkeypatch):
    monkeypatch.setenv("OLA_RUNTIME_COMMIT", TEST_SOURCE_COMMIT)
    tenant_id = _seed_tenant("agent-key-independence")
    result = run_agent_task(tenant_id, "prove independent agent execution")

    executions = result["execution"]
    assert len(executions) == 6
    assert [item["agent"] for item in executions] == AGENT_ROLES
    assert len({item["agent_instance_id"] for item in executions}) == 6
    assert len({item["context_digest"] for item in executions}) == 6
    assert all(item["execution_boundary"] == "in_process" for item in executions)
    assert all(item["status"] == "RECORDED" for item in executions)
    assert all(item["model_output_role"] == "advisory_only" for item in executions)
    assert all(item["action_result_source"] == "registered_capability" for item in executions)
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


def test_safe_expression_blocks_arithmetic_and_complexity_failures():
    from app.agent_runtime import _safe_expression

    assert "outside safe execution policy" in _safe_expression("calculate 1/0")
    assert "complexity limit" in _safe_expression("1+" + "+".join(["1"] * 100))
    assert "safe execution policy" in _safe_expression("1+" + "+".join(["1"] * 39))


def test_deterministic_mode_never_calls_external_provider(monkeypatch):
    import httpx
    from app.agent_runtime import _invoke_llm

    monkeypatch.setenv("OLA_LLM_MODE", "deterministic")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OLA_LLM_PROVIDER", "openai")

    def forbidden(*args, **kwargs):
        raise AssertionError("deterministic mode must not make network requests")

    monkeypatch.setattr(httpx, "post", forbidden)
    assert _invoke_llm("codeact", "calculate 1+1", {}) is None


def test_agent_run_rejects_oversized_task_before_writing_evidence(monkeypatch):
    monkeypatch.setenv("OLA_RUNTIME_COMMIT", TEST_SOURCE_COMMIT)
    tenant_id = _seed_tenant("agent-key-oversized")
    result = run_agent_task(tenant_id, "x" * 4097)

    assert result["status"] == "BLOCK"
    assert result["evidence_count"] == 0
    assert result["run_id"] is None


def test_agent_failure_writes_terminal_run_evidence(monkeypatch):
    from app.agent_runtime import AGENT_ROLES
    from app.igor_evidence_verifier import verify_chain
    from app.models import EvidenceRecord
    from sqlalchemy import select
    import json

    monkeypatch.setenv("OLA_RUNTIME_COMMIT", TEST_SOURCE_COMMIT)
    tenant_id = _seed_tenant("agent-key-failure-terminal")

    from app import agent_runtime
    original = agent_runtime._append_agent_evidence
    calls = {"count": 0}

    def fail_on_second(tenant, run_id, agent, task, previous_output, execution):
        calls["count"] += 1
        if calls["count"] == 2:
            raise RuntimeError("synthetic failure")
        return original(tenant, run_id, agent, task, previous_output, execution)

    monkeypatch.setattr(agent_runtime, "_append_agent_evidence", fail_on_second)
    result = run_agent_task(tenant_id, "safe synthetic task")

    assert result["status"] == "FAILED"
    with SessionLocal() as db:
        rows = db.scalars(select(EvidenceRecord).where(EvidenceRecord.tenant_id == tenant_id).order_by(EvidenceRecord.seq)).all()
    types = [row.record_type for row in rows]
    assert "execution.run.start" in types
    assert "execution.run.error" in types
    assert "execution.run.end" in types
    assert not any("safe synthetic task" in row.payload_json for row in rows)


def test_required_llm_mode_rejects_unapproved_openai_base_url(monkeypatch):
    import pytest
    from app.agent_runtime import _invoke_llm

    monkeypatch.setenv("OLA_LLM_MODE", "required")
    monkeypatch.setenv("OLA_LLM_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OLA_LLM_MODEL", "explicit-test-model")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://attacker.example/v1")

    with pytest.raises(RuntimeError, match="approved HTTPS"):
        _invoke_llm("codeact", "calculate 1+1", {})


def test_required_llm_mode_requires_explicit_model(monkeypatch):
    import pytest
    from app.agent_runtime import _invoke_llm

    monkeypatch.setenv("OLA_LLM_MODE", "required")
    monkeypatch.setenv("OLA_LLM_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.delenv("OLA_LLM_MODEL", raising=False)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)

    with pytest.raises(RuntimeError, match="OLA_LLM_MODEL must be explicitly configured"):
        _invoke_llm("codeact", "calculate 1+1", {})


def test_successful_agent_run_has_start_end_and_committed_task_only(monkeypatch):
    from sqlalchemy import select
    from app.models import EvidenceRecord
    import json

    monkeypatch.setenv("OLA_RUNTIME_COMMIT", TEST_SOURCE_COMMIT)
    tenant_id = _seed_tenant("agent-key-lifecycle")
    task = "synthetic private task text"
    result = run_agent_task(tenant_id, task)

    assert result["status"] == "VERIFIED"
    assert all(len(item["model_output_digest"]) == 64 for item in result["execution"])
    with SessionLocal() as db:
        rows = db.scalars(select(EvidenceRecord).where(EvidenceRecord.tenant_id == tenant_id).order_by(EvidenceRecord.seq)).all()
    payloads = [json.loads(row.payload_json) for row in rows]
    assert payloads[0]["task_digest"]
    assert payloads[-1]["status"] == "COMPLETED"
    assert any(row.record_type == "execution.run.start" for row in rows)
    assert any(row.record_type == "execution.run.end" for row in rows)
    assert not any(task in row.payload_json for row in rows)



def test_openai_multipart_output_uses_real_newline_separator(monkeypatch):
    import httpx
    from app.agent_runtime import _invoke_llm

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "id": "resp-test",
                "output": [
                    {"content": [{"type": "output_text", "text": "part one"}]},
                    {"content": [{"type": "output_text", "text": "part two"}]},
                ],
            }

    monkeypatch.setenv("OLA_LLM_MODE", "required")
    monkeypatch.setenv("OLA_LLM_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OLA_LLM_MODEL", "test-model")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    monkeypatch.setattr(httpx, "post", lambda *args, **kwargs: Response())

    result = _invoke_llm("codeact", "calculate 1+1", {})
    assert result["output"] == "part one\npart two"


def test_ollama_rejects_non_loopback_http_endpoint(monkeypatch):
    import pytest
    from app.agent_runtime import _invoke_llm

    monkeypatch.setenv("OLA_LLM_MODE", "required")
    monkeypatch.setenv("OLA_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("OLA_LLM_MODEL", "test-model")
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://attacker.example:11434")
    monkeypatch.delenv("OLA_OLLAMA_ALLOWED_HOSTS", raising=False)

    with pytest.raises(RuntimeError, match="loopback HTTP or an allowlisted HTTPS host"):
        _invoke_llm("codeact", "calculate 1+1", {})


def test_ollama_remote_https_requires_explicit_host_allowlist(monkeypatch):
    import pytest
    from app.agent_runtime import _invoke_llm

    monkeypatch.setenv("OLA_LLM_MODE", "required")
    monkeypatch.setenv("OLA_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("OLA_LLM_MODEL", "test-model")
    monkeypatch.setenv("OLLAMA_BASE_URL", "https://ollama.internal.example")
    monkeypatch.delenv("OLA_OLLAMA_ALLOWED_HOSTS", raising=False)

    with pytest.raises(RuntimeError, match="allowlisted HTTPS"):
        _invoke_llm("codeact", "calculate 1+1", {})


def test_ollama_remote_https_uses_explicitly_allowlisted_host(monkeypatch):
    import httpx
    from app.agent_runtime import _invoke_llm

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"message": {"content": "advisory output"}}

    calls = []
    def fake_post(url, **kwargs):
        calls.append(url)
        return Response()

    monkeypatch.setenv("OLA_LLM_MODE", "required")
    monkeypatch.setenv("OLA_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("OLA_LLM_MODEL", "test-model")
    monkeypatch.setenv("OLLAMA_BASE_URL", "https://ollama.internal.example")
    monkeypatch.setenv("OLA_OLLAMA_ALLOWED_HOSTS", "ollama.internal.example")
    monkeypatch.setattr(httpx, "post", fake_post)

    result = _invoke_llm("codeact", "calculate 1+1", {})
    assert calls == ["https://ollama.internal.example/api/chat"]
    assert result["output"] == "advisory output"
