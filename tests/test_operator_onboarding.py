"""OLA operator onboarding: actual API authentication, not just input presence."""
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.database import SessionLocal
from app.main import app
from app.models import ApiKey, Tenant
from scripts.provision_local_operator import issue_operator_key


def test_authenticated_operator_session_and_credential_never_echoed():
    name = "operator_" + uuid.uuid4().hex
    tenant_id, raw = issue_operator_key(name)
    assert raw.startswith("ola2_") and len(raw) >= 50
    client = TestClient(app)
    response = client.get("/auth/session", headers={"X-API-Key": raw})
    assert response.status_code == 200
    body = response.json()
    assert body["authenticated"] is True
    assert body["tenant_id"] == tenant_id
    assert body["scope"] == "OLA_CORE"
    assert body["credential_id"]
    assert raw not in response.text
    with SessionLocal() as db:
        stored = db.scalar(select(ApiKey).where(ApiKey.tenant_id == tenant_id))
        assert stored is not None
        assert stored.key_hash != raw
        assert len(stored.key_hash) == 64


def test_missing_or_invalid_key_is_blocked():
    client = TestClient(app)
    assert client.get("/auth/session").status_code == 401
    assert client.get("/auth/session", headers={"X-API-Key": "invalid"}).status_code == 401


def test_missing_pepper_returns_controlled_503_not_internal_exception(monkeypatch):
    monkeypatch.delenv("OLA_API_KEY_PEPPER", raising=False)
    client = TestClient(app)
    resp = client.get("/auth/session", headers={"X-API-Key": "ola2_fake"})
    assert resp.status_code == 503
    assert "not configured" in resp.json()["detail"]
    with pytest.raises(RuntimeError):
        issue_operator_key("no_pepper_" + uuid.uuid4().hex)


def test_provision_is_fail_closed_against_duplicate_tenant():
    name = "operator_" + uuid.uuid4().hex
    tenant_id, raw = issue_operator_key(name)
    assert tenant_id and raw
    with pytest.raises(ValueError, match="already exists"):
        issue_operator_key(name)
    for wrong in ("../escape", "space here", "", "x" * 81):
        with pytest.raises(ValueError):
            issue_operator_key(wrong)
    with SessionLocal() as db:
        assert len(db.scalars(select(Tenant).where(Tenant.name == name)).all()) == 1
        assert len(db.scalars(select(ApiKey).where(ApiKey.tenant_id == tenant_id)).all()) == 1
