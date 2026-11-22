"""Capability voucher integration tests through real HTTP execution boundaries."""
import uuid

from fastapi.testclient import TestClient

from app.api_key_hashing import api_key_fingerprint
from app.database import SessionLocal
from app.main import app
from app.models import ApiKey, Tenant


def _tenant_with_key():
    tenant_id = str(uuid.uuid4())
    api_key = f"capability-test-{tenant_id}"
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="capability-voucher-boundary"))
        db.commit()
        db.add(ApiKey(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            key_hash=api_key_fingerprint(api_key),
        ))
        db.commit()
    return tenant_id, api_key


def test_agent_run_fails_closed_before_any_agent_when_voucher_key_is_missing(monkeypatch):
    tenant_id, api_key = _tenant_with_key()
    monkeypatch.setenv("OLA_RUNTIME_COMMIT", "a" * 40)
    monkeypatch.setenv("OLA_LLM_MODE", "deterministic")
    monkeypatch.delenv("OLA_CAPABILITY_VOUCHER_KEY_HEX", raising=False)

    from app import agent_runtime
    original = agent_runtime._execute_agent
    effects = []

    def observe_effect(*args, **kwargs):
        effects.append(args[0])
        return original(*args, **kwargs)

    monkeypatch.setattr(agent_runtime, "_execute_agent", observe_effect)

    response = TestClient(app).post(
        "/agent-run",
        headers={"X-API-Key": api_key},
        json={"task": "calculate 2+2", "risk": "LOW"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "BLOCK"
    assert effects == [], "agent execution must not begin without a configured voucher key"


def test_agent_run_binds_capability_authorization_to_authenticated_api_key(monkeypatch):
    tenant_id, api_key = _tenant_with_key()
    monkeypatch.setenv("OLA_RUNTIME_COMMIT", "b" * 40)
    monkeypatch.setenv("OLA_LLM_MODE", "deterministic")
    monkeypatch.setenv("OLA_CAPABILITY_VOUCHER_KEY_HEX", "11" * 32)
    monkeypatch.setenv("OLA_ENVIRONMENT", "test")

    response = TestClient(app).post(
        "/agent-run",
        headers={"X-API-Key": api_key},
        json={"task": "calculate 2+2", "risk": "LOW"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "VERIFIED"
    from app.database import SessionLocal
    from app.models import EvidenceRecord
    from sqlalchemy import select
    import json

    with SessionLocal() as db:
        rows = db.scalars(
            select(EvidenceRecord)
            .where(EvidenceRecord.tenant_id == tenant_id)
            .order_by(EvidenceRecord.seq.asc())
        ).all()
    authorizations = [
        json.loads(row.payload_json)
        for row in rows
        if row.record_type == "execution.capability.authorized"
    ]
    assert len(authorizations) == 6
    assert all(item["principal_id"] for item in authorizations)
    assert all(item["voucher_id"] for item in authorizations)
    assert all(item["arguments_digest"] for item in authorizations)
    assert all(item["policy_version"] for item in authorizations)
