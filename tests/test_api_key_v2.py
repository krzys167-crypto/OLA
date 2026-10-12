"""API key v2 cryptographic contract and strict legacy rejection."""
import uuid

import pytest
from fastapi.testclient import TestClient

from app.api_key_crypto import KeyConfigurationError, hash_api_key
from app.database import SessionLocal
from app.main import app
from app.models import ApiKey, Tenant


def test_kdf_is_stable_and_tenant_secret_dependent(monkeypatch):
    token = "key-v2-" + uuid.uuid4().hex
    monkeypatch.setenv("OLA_API_KEY_PEPPER", "a" * 64)
    first = hash_api_key(token)
    assert first == hash_api_key(token)
    assert len(first) == 64
    monkeypatch.setenv("OLA_API_KEY_PEPPER", "b" * 64)
    assert hash_api_key(token) != first


def test_missing_pepper_is_not_a_legacy_fallback(monkeypatch):
    monkeypatch.delenv("OLA_API_KEY_PEPPER", raising=False)
    with pytest.raises(KeyConfigurationError):
        hash_api_key("not-a-real-key")


def test_short_pepper_is_rejected(monkeypatch):
    monkeypatch.setenv("OLA_API_KEY_PEPPER", "unsafe")
    with pytest.raises(KeyConfigurationError):
        hash_api_key("not-a-real-key")


def test_existing_legacy_hash_not_accepted_by_v2_auth(monkeypatch):
    monkeypatch.setenv("OLA_API_KEY_PEPPER", "a" * 64)
    tenant_id = str(uuid.uuid4())
    raw = "legacy-key-" + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="legacy-migration-test"))
        db.flush()
        db.add(ApiKey(id=str(uuid.uuid4()), tenant_id=tenant_id,
                      key_hash="0" * 64))
        db.commit()
    response = TestClient(app).post(
        "/evidence",
        headers={"X-API-Key": raw},
        json={"record_type": "generic", "payload": {"v": 2}},
    )
    assert response.status_code == 401


def test_v2_key_is_accepted(monkeypatch):
    monkeypatch.setenv("OLA_API_KEY_PEPPER", "a" * 64)
    tenant_id = str(uuid.uuid4())
    raw = "v2-key-" + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="v2-migration-test"))
        db.flush()
        db.add(ApiKey(id=str(uuid.uuid4()), tenant_id=tenant_id,
                      key_hash=hash_api_key(raw)))
        db.commit()
    response = TestClient(app).post(
        "/evidence",
        headers={"X-API-Key": raw},
        json={"record_type": "generic", "payload": {"v": 2}},
    )
    assert response.status_code == 200, response.json()
