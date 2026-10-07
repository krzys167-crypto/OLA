import hashlib
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.main import app
from app.database import SessionLocal
from app.models import ApiKey, EvidenceRecord, Tenant
from app.hashchain import verify_chain


def _seed_tenant():
    db = SessionLocal()
    tenant = Tenant(id=str(uuid.uuid4()), name="product-e2e")
    tenant_id = tenant.id
    db.add(tenant)
    db.commit()
    db.add(
        ApiKey(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            key_hash=hashlib.sha256(f"product-key-{tenant_id}".encode()).hexdigest(),
        )
    )
    db.commit()
    db.close()
    return tenant_id


def test_product_e2e_task_fault_recovery_verification():
    tenant_id = _seed_tenant()
    client = TestClient(app)

    response = client.post(
        "/audit",
        headers={"X-API-Key": f"product-key-{tenant_id}"},
        json={
            "task": "controlled incident verification",
            "scenario": "fault_then_recovery",
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "VERIFIED"
    assert result["outcome"] == "recovered_and_verified"
    assert result["evidence_count"] == 5

    db = SessionLocal()
    rows = db.scalars(
        select(EvidenceRecord)
        .where(EvidenceRecord.tenant_id == tenant_id)
        .order_by(EvidenceRecord.seq.asc())
    ).all()
    db.close()

    assert [row.record_type for row in rows] == [
        "task.received",
        "execution.started",
        "fault.detected",
        "recovery.applied",
        "verification.passed",
    ]
    chain = [
        {
            "tenant_id": row.tenant_id,
            "seq": row.seq,
            "prev_hash": row.prev_hash,
            "record_hash": row.record_hash,
            "record_type": row.record_type,
            "payload_json": row.payload_json,
        }
        for row in rows
    ]
    assert verify_chain(chain)[0]
    assert result["evidence_ids"] == [row.id for row in rows]
