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


def test_nina_explicit_llm_never_verifies_deterministic_fallback(monkeypatch):
    import app.nina as nina_module
    monkeypatch.setattr(nina_module, "run_agent_task", lambda tenant, task: {
        "status": "VERIFIED", "run_id": "fallback",
        "execution": [{"invocation_type": "local_deterministic_model",
                       "provider": "local", "model": "deterministic-runtime-v1"}],
    })
    task = NinaTask.create("tenant-1", "review evidence", ["llm_agent"])
    result = NinaOrchestrator().execute(task)
    assert result["status"] == "BLOCK"
    assert result["runtime"]["status"] == "VERIFIED"  # captured chain != requested real LLM


def test_nina_explicit_llm_requires_real_response_ids(monkeypatch):
    import app.nina as nina_module
    monkeypatch.setattr(nina_module, "run_agent_task", lambda tenant, task: {
        "status": "VERIFIED", "run_id": "missing-response",
        "execution": [{"invocation_type": "real_llm", "provider": "ollama",
                       "model": "qwen", "response_id": None}],
    })
    task = NinaTask.create("tenant-1", "review evidence", ["llm_agent"])
    assert NinaOrchestrator().execute(task)["status"] == "BLOCK"


def test_nina_explicit_llm_accepts_complete_real_trace(monkeypatch):
    import app.nina as nina_module
    monkeypatch.setattr(nina_module, "run_agent_task", lambda tenant, task: {
        "status": "VERIFIED", "run_id": "real-response",
        "execution": [{"invocation_type": "real_llm", "provider": "ollama",
                       "model": "qwen", "response_id": "r-123"}],
    })
    task = NinaTask.create("tenant-1", "review evidence", ["llm_agent"])
    assert NinaOrchestrator().execute(task)["status"] == "VERIFIED"


def test_nina_non_llm_task_keeps_existing_deterministic_contract(monkeypatch):
    import app.nina as nina_module
    monkeypatch.setattr(nina_module, "run_agent_task", lambda tenant, task: {
        "status": "VERIFIED", "run_id": "deterministic",
        "execution": [{"invocation_type": "local_deterministic_model"}],
    })
    task = NinaTask.create("tenant-1", "2+2", ["safe_expression"])
    assert NinaOrchestrator().execute(task)["status"] == "VERIFIED"
