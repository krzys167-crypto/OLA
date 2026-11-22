"""Endpoint characterization; these tests do not claim voucher/Human Gate integration."""
from fastapi import HTTPException
from fastapi.testclient import TestClient
import app.main as main


def _tenant(key):
    if key != "test-key":
        raise HTTPException(status_code=401, detail="invalid API key")
    return "tenant-test"


def _identity(key):
    if key != "test-key":
        raise HTTPException(status_code=401, detail="invalid API key")
    return "tenant-test", "principal-test"


def test_agent_run_denies_high_risk_without_human_approval(monkeypatch):
    runtime_effects = []

    monkeypatch.setattr(main, "REGISTERED_AGENT_IDS", frozenset({"agent-001"}))
    monkeypatch.setattr(main, "tenant_from_key", _tenant)
    monkeypatch.setattr(main, "identity_from_key", _identity)
    monkeypatch.setattr(main, "append_record", lambda *args, **kwargs: {"id": "evidence"})
    monkeypatch.setattr(main, "run_agent_task", lambda tenant, task, principal: runtime_effects.append((tenant, task, principal)))
    client = TestClient(main.app)

    response = client.post(
        "/agent-run",
        headers={"X-API-Key": "test-key"},
        json={"task": "characterization", "risk": "HIGH"},
    )

    assert response.status_code == 403
    assert runtime_effects == []


def test_nina_run_requires_api_key_identity_but_is_not_voucher_gated(monkeypatch):
    dispatches = []

    monkeypatch.setattr(main, "identity_from_key", _identity)
    monkeypatch.setattr(
        "app.nina_execution.run_nina_task",
        lambda tenant, principal, task, tools: dispatches.append((tenant, principal, task, tools)) or {"status": "test"},
    )
    client = TestClient(main.app)

    denied = client.post("/nina-run", json={"task": "characterization"})
    assert denied.status_code == 401
    assert dispatches == []

    response = client.post(
        "/nina-run",
        headers={"X-API-Key": "test-key"},
        json={"task": "characterization"},
    )

    assert response.status_code == 200
    assert dispatches == [("tenant-test", "principal-test", "characterization", ["safe_expression"])]
