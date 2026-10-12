"""Two valid simultaneous approvers may produce at most one Human Gate approval."""
import concurrent.futures
import hashlib
import importlib
import json
import threading
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.api_key_crypto import hash_api_key
from app.database import SessionLocal
from app.models import ApiKey, EvidenceRecord, Tenant

main = importlib.import_module("app.main")


def _prepare():
    tenant = str(uuid.uuid4())
    requester = str(uuid.uuid4())
    key_one = "reviewer1-" + uuid.uuid4().hex
    key_two = "reviewer2-" + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(Tenant(id=tenant, name="atomic-human-gate"))
        db.flush()
        db.add_all([
            ApiKey(id=requester, tenant_id=tenant,
                   key_hash=hash_api_key("requester-" + uuid.uuid4().hex)),
            ApiKey(id=str(uuid.uuid4()), tenant_id=tenant,
                   key_hash=hash_api_key(key_one)),
            ApiKey(id=str(uuid.uuid4()), tenant_id=tenant,
                   key_hash=hash_api_key(key_two)),
        ])
        db.commit()
    run = "atomic-" + uuid.uuid4().hex
    tip = main.append_record(tenant, "decision.candidate", {
        "run_id": run, "requester_id": requester,
        "status_fields": {
            "RUNTIME": "VERIFIED", "EVIDENCE": "VERIFIED",
            "REPLAY_INTEGRITY": "VERIFIED", "POLICY": "VERIFIED",
            "HUMAN_GATE": "REVIEW",
            "EXECUTION_ALLOWED": "REVIEW",
        }, "candidate_status": "REVIEW",
    })["record_hash"]
    return tenant, run, tip, (key_one, key_two)


def test_simultaneous_approvals_are_atomic_and_never_duplicate(monkeypatch):
    tenant, run, tip, keys = _prepare()
    original_append = main.append_record
    arrival = threading.Barrier(2)

    # Force the original read/verify/append race after both requests
    # pass eligibility. The fixed approval flow commits under one SQLite
    # write transaction and does not use the non-atomic append helper.
    def force_overlap(tenant_id, record_type, payload):
        if record_type == "human.approval":
            arrival.wait(timeout=10)
        return original_append(tenant_id, record_type, payload)

    monkeypatch.setattr(main, "append_record", force_overlap)

    def approve(key):
        client = TestClient(main.app, raise_server_exceptions=False)
        return client.post(
            f"/nina-run/{run}/approve",
            headers={"Authorization": f"Bearer {key}"},
            json={"tip_hash": tip},
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(approve, key) for key in keys]
        responses = [future.result(timeout=25) for future in futures]
    assert sorted(r.status_code for r in responses) == [200, 409], [
        (r.status_code, r.text) for r in responses
    ]
    with SessionLocal() as db:
        rows = db.scalars(
            select(EvidenceRecord).where(
                EvidenceRecord.tenant_id == tenant,
                EvidenceRecord.record_type == "human.approval",
            )
        ).all()
    approvals = [
        row for row in rows
        if json.loads(row.payload_json).get("run_id") == run
    ]
    assert len(approvals) == 1, approvals
