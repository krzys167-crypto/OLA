"""P0 endpoint characterization: protected execution must fail closed.

These tests assert zero runtime dispatch when a request lacks valid authorization.
They do not claim the broker is integrated or prove production enforcement.
"""
from fastapi.testclient import TestClient
import app.main as main


def test_agent_run_denies_unauthorized_request_without_runtime_effect(monkeypatch):
    runtime_effects = []

    monkeypatch.setattr(main, "REGISTERED_AGENT_IDS", frozenset({"agent-001"}))
    monkeypatch.setattr(main, "tenant_from_key", lambda key: "tenant-test")
    monkeypatch.setattr(main, "append_record", lambda *args, **kwargs: {"id": "evidence"})
    monkeypatch.setattr(main, "run_agent_task", lambda tenant, task: runtime_effects.append((tenant, task)))
    client = TestClient(main.app)

    response = client.post("/agent-run", json={"task": "characterization", "risk": "LOW"})

    assert response.status_code == 403
    assert runtime_effects == []


def test_nina_run_route_dispatches_only_when_authorized_identity_is_supplied(monkeypatch):
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
