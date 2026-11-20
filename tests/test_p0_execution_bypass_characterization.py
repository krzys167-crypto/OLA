"""P0 red-team characterization: authorization is currently decoupled from effect.

These tests intentionally characterize the observed main-branch behavior. They are
not a passing security regression suite: they demonstrate that a no-op gate
decision can be followed by a protected runtime call. Replace these tests with
zero-effect denial tests after broker integration.
"""
from fastapi.testclient import TestClient
import app.main as main


def test_agent_run_gate_noop_is_followed_by_actual_runtime_call(monkeypatch):
    gate_effects = []
    runtime_effects = []

    class AllowGate:
        def execute(self, **kwargs):
            gate_effects.append(kwargs.get("effect")())
            return main.ExecutionDecision(status="ALLOW", reason="test")

    monkeypatch.setattr(main, "REGISTERED_AGENT_IDS", frozenset({"agent-001"}))
    monkeypatch.setattr(main, "AGENT_RUN_GATE", AllowGate())
    monkeypatch.setattr(main, "tenant_from_key", lambda key: "tenant-test")
    monkeypatch.setattr(main, "append_record", lambda *args, **kwargs: {"id": "evidence"})
    monkeypatch.setattr(main, "run_agent_task", lambda tenant, task: runtime_effects.append((tenant, task)) or {"status": "test"})
    client = TestClient(main.app)

    response = client.post("/agent-run", json={"task": "characterization", "risk": "LOW"})

    assert response.status_code == 200
    assert gate_effects == [None]
    assert runtime_effects == [("tenant-test", "characterization")]


def test_nina_run_route_dispatches_to_nina_execution_service(monkeypatch):
    dispatches = []

    monkeypatch.setattr(main, "identity_from_key", lambda key: ("tenant-test", "principal-test"))
    monkeypatch.setattr(
        "app.nina_execution.run_nina_task",
        lambda tenant, principal, task, tools: dispatches.append((tenant, principal, task, tools)) or {"status": "test"},
    )
    client = TestClient(main.app)

    response = client.post("/nina-run", json={"task": "characterization"})

    assert response.status_code == 200
    assert dispatches == [("tenant-test", "principal-test", "characterization", ["safe_expression"])]
