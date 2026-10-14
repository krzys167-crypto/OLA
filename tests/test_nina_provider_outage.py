"""Provider outages do not turn a partially executed NINA run into HTTP 500 or VERIFIED."""
import uuid
import httpx

from fastapi.testclient import TestClient
from app.api_key_crypto import hash_api_key
from app.database import SessionLocal
from app.main import app
from app.models import ApiKey, Tenant


def test_real_llm_connection_failure_returns_block_with_recorded_evidence(monkeypatch):
    tenant_id, key = str(uuid.uuid4()), "test-run-" + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="provider_" + tenant_id))
        db.add(ApiKey(id=str(uuid.uuid4()), tenant_id=tenant_id, key_hash=hash_api_key(key)))
        db.commit()
    monkeypatch.setenv("OLA_LLM_MODE", "required")
    monkeypatch.setenv("OLA_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("OLA_LLM_MODEL", "missing-model-test")
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")

    def down(*args, **kwargs):
        raise httpx.ConnectError("provider down; should not be in response")

    monkeypatch.setattr(httpx, "post", down)
    client = TestClient(app)
    result = client.post("/nina-run", headers={"X-API-Key": key},
                         json={"task": "17 * 23", "requested_tools": ["safe_expression"]})
    assert result.status_code == 200
    body = result.json()
    assert body["status"] == "BLOCK"
    assert body["nina"]["status"] == "BLOCK"
    assert body["igor"]["status"] != "VERIFIED"
    assert body["human_gate"]["status"] == "BLOCK"
    assert body["run_id"]
    assert "provider down;" not in result.text
    proof = client.get("/control/overview", headers={"X-API-Key": key})
    assert proof.status_code == 200
    view = proof.json()
    assert view["evidence"]["status"] == "VERIFIED"
    assert any(e["type"] == "runtime.blocked" for e in view["recent_events"])
    assert view["production"]["status"] == "NO-GO"
