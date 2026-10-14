"""Forward-only v2 evidence migration: no historical hash rewriting."""
import os
import sqlite3
import tempfile
import uuid

from sqlalchemy import create_engine, select

from app import database
from app.control_plane import get_overview
from app.database import SessionLocal
from app.hashchain import GENESIS_HASH, canonical_json, compute_record_hash, verify_chain
from app.main import append_record
from app.models import EvidenceRecord, Tenant


def test_mixed_legacy_chain_remains_valid_and_new_metadata_is_bound():
    tenant = str(uuid.uuid4())
    legacy_id = str(uuid.uuid4())
    payload_json = canonical_json({"legacy": "original"})
    v1 = compute_record_hash(tenant, 0, GENESIS_HASH, payload_json)
    with SessionLocal() as db:
        db.add(Tenant(id=tenant, name="mixed-v1-v2"))
        db.add(EvidenceRecord(
            id=legacy_id, tenant_id=tenant, seq=0,
            record_type="legacy.test", payload_json=payload_json,
            prev_hash=GENESIS_HASH, record_hash=v1, hash_version=1,
        ))
        db.commit()
    next_record = append_record(tenant, "user.test", {"modern": True})
    assert next_record["seq"] == 1
    assert next_record["hash_version"] == 2
    with SessionLocal() as db:
        rows = db.scalars(
            select(EvidenceRecord).where(EvidenceRecord.tenant_id == tenant)
            .order_by(EvidenceRecord.seq)
        ).all()
        records = [{
            "id": row.id, "tenant_id": row.tenant_id,
            "record_type": row.record_type, "hash_version": row.hash_version,
            "seq": row.seq, "payload_json": row.payload_json,
            "prev_hash": row.prev_hash, "record_hash": row.record_hash,
        } for row in rows]
    assert verify_chain(records) == (True, "ok")
    assert get_overview(tenant)["evidence"]["status"] == "VERIFIED"

    mutated = [dict(r) for r in records]
    mutated[1]["record_type"] = "human.approval"
    assert verify_chain(mutated)[0] is False
    mutated = [dict(r) for r in records]
    mutated[1]["id"] = "forged"
    assert verify_chain(mutated)[0] is False
    mutated = [dict(r) for r in records]
    mutated[1]["hash_version"] = 1
    assert verify_chain(mutated)[0] is False
    mutated = [dict(r) for r in records]
    mutated[1].pop("id")
    assert verify_chain(mutated)[0] is False
    mutated = [dict(r) for r in records]
    mutated[1]["hash_version"] = 3
    assert verify_chain(mutated)[0] is False

    # Historical v1 id/type were never hash-bound; no claim they are now.
    assert records[0]["hash_version"] == 1


def test_additive_schema_migration_preserves_preexisting_legacy_bytes(monkeypatch):
    with tempfile.TemporaryDirectory() as folder:
        path = os.path.join(folder, "legacy.sqlite")
        with sqlite3.connect(path) as raw:
            raw.execute(
                "CREATE TABLE evidence_records ("
                "id TEXT PRIMARY KEY, tenant_id TEXT, seq INTEGER, "
                "record_type TEXT, payload_json TEXT, prev_hash TEXT, record_hash TEXT)"
            )
            raw.execute(
                "INSERT INTO evidence_records VALUES (?,?,?,?,?,?,?)",
                ("legacy-1", "tenant-old", 0, "user.old", "{}",
                 GENESIS_HASH, compute_record_hash("tenant-old", 0, GENESIS_HASH, "{}"))
            )
        migrated_engine = create_engine("sqlite:///" + path)
        monkeypatch.setattr(database, "engine", migrated_engine)
        database.ensure_evidence_hash_schema()
        database.ensure_evidence_hash_schema()  # idempotent
        with migrated_engine.begin() as conn:
            row = conn.exec_driver_sql(
                "SELECT id,record_type,payload_json,record_hash,hash_version "
                "FROM evidence_records WHERE id='legacy-1'"
            ).one()
        assert tuple(row) == (
            "legacy-1", "user.old", "{}",
            compute_record_hash("tenant-old", 0, GENESIS_HASH, "{}"), 1,
        )
        migrated_engine.dispose()
