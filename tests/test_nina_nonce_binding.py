import hashlib
import uuid

from fastapi.testclient import TestClient
from app.database import SessionLocal
from app.main import app
from app.models import ApiKey, Tenant


def test_nina_provenance_exports_runtime_nonce_and_igor_checks_it(monkeypatch):
    monkeypatch.setenv("OLA_SOURCE_COMMIT", "test-nonce-source")
    monkeypatch.setenv("OLA_RUNTIME_COMMIT", "test-nonce-source")
    monkeypatch.setenv("OLA_REPLAY_NONCE", "cd" * 32)
    monkeypatch.setenv("OLA_LLM_PROVIDER", "deterministic")
    monkeypatch.setenv("OLA_LLM_MODE", "deterministic")
    tenant_id, key = str(uuid.uuid4()), "nonce-test-" + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="nonce-binding-test"))
        db.add(ApiKey(id=str(uuid.uuid4()), tenant_id=tenant_id, key_hash=hashlib.sha256(key.encode()).hexdigest()))
        db.commit()
    response = TestClient(app).post("/nina-run", headers={"X-API-Key": key}, json={"task": "Calculate 17 * 23", "requested_tools": ["safe_expression"]})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["provenance"]["replay_nonce"] == "cd" * 32
    assert body["igor"]["checks"]["replay_nonce"] is True
    assert body["human_gate"]["status"] == "BLOCK"
