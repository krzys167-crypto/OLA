import hashlib
import uuid

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.models import ApiKey, Tenant
from app.main import app


CLIENT = TestClient(app)


def _seed_tenant(api_key):
    tenant_id = str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name=f"evidence-list-{tenant_id}"))
        db.add(
            ApiKey(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                key_hash=hashlib.sha256(api_key.encode()).hexdigest(),
            )
        )
        db.commit()
    return tenant_id


def _create_evidence(api_key, record_type, payload):
    response = CLIENT.post(
        "/evidence",
        headers={"X-API-Key": api_key},
        json={"record_type": record_type, "payload": payload},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_evidence_list_is_read_only_and_tenant_scoped():
    tenant_a = _seed_tenant("evidence-list-a")
    tenant_b = _seed_tenant("evidence-list-b")

    first = _create_evidence("evidence-list-a", "test.first", {"value": 1})
    second = _create_evidence("evidence-list-a", "test.second", {"value": 2})
    _create_evidence("evidence-list-b", "test.other", {"value": 99})

    before_count = None
    with SessionLocal() as db:
        before_count = sum(1 for row in db.query(__import__("app.models", fromlist=["EvidenceRecord"]).EvidenceRecord).filter_by(tenant_id=tenant_a))

    response = CLIENT.get(
        "/evidence",
        headers={"X-API-Key": "evidence-list-a"},
        params={"limit": 20},
    )
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["count"] == 2
    assert [record["seq"] for record in body["records"]] == [second["seq"], first["seq"]]
    assert all(record["tenant_id"] == tenant_a for record in body["records"])

    with SessionLocal() as db:
        after_count = sum(1 for row in db.query(__import__("app.models", fromlist=["EvidenceRecord"]).EvidenceRecord).filter_by(tenant_id=tenant_a))
    assert after_count == before_count


def test_evidence_list_cursor_and_bounds():
    api_key = "evidence-list-cursor"
    _seed_tenant(api_key)
    rows = [
        _create_evidence(api_key, f"test.{index}", {"index": index})
        for index in range(3)
    ]

    response = CLIENT.get(
        "/evidence",
        headers={"X-API-Key": api_key},
        params={"limit": 2},
    )
    assert response.status_code == 200
    assert response.json()["count"] == 2
    assert [record["seq"] for record in response.json()["records"]] == [
        rows[2]["seq"],
        rows[1]["seq"],
    ]

    oldest_seq = rows[1]["seq"]
    cursor_response = CLIENT.get(
        "/evidence",
        headers={"X-API-Key": api_key},
        params={"limit": 20, "before_seq": oldest_seq},
    )
    assert cursor_response.status_code == 200
    assert [record["seq"] for record in cursor_response.json()["records"]] == [rows[0]["seq"]]

    assert CLIENT.get("/evidence", headers={"X-API-Key": api_key}, params={"limit": 0}).status_code == 400
    assert CLIENT.get("/evidence", headers={"X-API-Key": api_key}, params={"limit": 101}).status_code == 400
    assert CLIENT.get("/evidence", headers={"X-API-Key": api_key}, params={"before_seq": -1}).status_code == 400
    assert CLIENT.get("/evidence").status_code == 401
