import hashlib
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.database import SessionLocal
from app.models import ApiKey, Tenant
from app.main import app


def _seed_tenant():
    db = SessionLocal()
    tenant = Tenant(id=str(uuid.uuid4()), name="nina-chat-e2e")
    db.add(tenant)
    db.commit()
    db.add(
        ApiKey(
            id=str(uuid.uuid4()),
            tenant_id=tenant.id,
            key_hash=hashlib.sha256(f"product-key-{tenant.id}".encode()).hexdigest(),
        )
    )
    db.commit()
    tenant_id = tenant.id
    db.close()
    return tenant_id


def test_nina_home_is_served():
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert "NINA" in response.text


def test_nina_chat_requires_authenticated_tenant():
    client = TestClient(app)
    response = client.post(
        "/chat",
        json={"messages": [{"role": "user", "content": "hello"}]},
    )
    assert response.status_code == 401


def test_nina_chat_route_reaches_runtime(monkeypatch):
    tenant_id = _seed_tenant()

    def fake_chat(received_tenant_id, messages):
        assert received_tenant_id == tenant_id
        assert messages == [{"role": "user", "content": "hello"}]
        return {"status": "VERIFIED", "message": "hello from test"}

    monkeypatch.setattr("app.main.chat", fake_chat)

    client = TestClient(app)
    response = client.post(
        "/chat",
        headers={"X-API-Key": f"product-key-{tenant_id}"},
        json={"messages": [{"role": "user", "content": "hello"}]},
    )

    assert response.status_code == 200
    # the model answered, but no independent judge accepted it: the surface must say UNKNOWN, not VERIFIED
    assert response.json()["status"] == "UNKNOWN"
    assert response.json()["verification"] == "NOT_JUDGED"
    assert response.json()["message"] == "hello from test"
