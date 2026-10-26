import os
import uuid

from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import declarative_base, sessionmaker

DB_PATH = os.getenv("OLA_EG_DB_PATH", "ola.db")
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False, "timeout": 30})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()


def install_append_only_triggers():
    with engine.begin() as conn:
        conn.exec_driver_sql("""
        CREATE TRIGGER IF NOT EXISTS evidence_no_update
        BEFORE UPDATE ON evidence_records
        BEGIN SELECT RAISE(ABORT, 'evidence_records is append-only'); END;
        """)
        conn.exec_driver_sql("""
        CREATE TRIGGER IF NOT EXISTS evidence_no_delete
        BEFORE DELETE ON evidence_records
        BEGIN SELECT RAISE(ABORT, 'evidence_records is append-only'); END;
        """)


def append_evidence_atomic(tenant_id, record_type, payload, *, producer_id="ola_runtime"):
    """Serialize all evidence writers before reading a tenant tip.

    SQLite BEGIN IMMEDIATE acquires the database writer reservation before
    selecting seq/prev_hash. It works across threads *and processes*, unlike
    a Python lock. Unique(tenant_id, seq) remains a final fail-closed guard.
    SQLite is still a single-writer backend; use a separately audited
    PostgreSQL implementation for high write throughput.
    """
    from .hashchain import GENESIS_HASH, sealed_payload_json, compute_record_hash_v2
    from .models import EvidenceRecord

    if not isinstance(tenant_id, str) or not tenant_id:
        raise ValueError("tenant_id required for evidence append")
    if not isinstance(record_type, str) or not record_type:
        raise ValueError("record_type required for evidence append")
    payload_json = sealed_payload_json(record_type, payload, producer=producer_id)
    with SessionLocal() as db:
        if db.bind.dialect.name != "sqlite":
            raise RuntimeError("no atomic append policy for non-SQLite backend")
        db.connection().exec_driver_sql("BEGIN IMMEDIATE")
        last = db.scalar(select(EvidenceRecord)
                         .where(EvidenceRecord.tenant_id == tenant_id)
                         .order_by(EvidenceRecord.seq.desc()))
        seq = last.seq + 1 if last is not None else 0
        previous = last.record_hash if last is not None else GENESIS_HASH
        record_id = str(uuid.uuid4())
        digest = compute_record_hash_v2(tenant_id, seq, previous, record_type,
                                        producer_id, payload_json)
        db.add(EvidenceRecord(
            id=record_id, tenant_id=tenant_id, seq=seq, record_type=record_type,
            payload_json=payload_json, prev_hash=previous, record_hash=digest,
        ))
        db.commit()
        return {"id": record_id, "tenant_id": tenant_id, "seq": seq,
                "record_hash": digest}
