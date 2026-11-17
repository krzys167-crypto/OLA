import base64
import json

from sqlalchemy import select

from app.database import SessionLocal, begin_write_transaction
from app.evidence_v4 import Keyring
from app.evidence_writer import append_evidence_v4_locked
from app.igor_evidence_verifier import verify_chain
from app.models import EvidenceRecord


KEY_A = b"writer-v4-test-key-a-material-32bytes"
KEY_B = b"writer-v4-test-key-b-material-32bytes"


def _configure_keyring(monkeypatch):
    keys = {"writer-k1": KEY_A, "writer-k2": KEY_B}
    monkeypatch.setenv(
        "OLA_EVIDENCE_V4_KEYRING_JSON",
        json.dumps({key_id: base64.b64encode(value).decode() for key_id, value in keys.items()}),
    )
    monkeypatch.setenv("OLA_EVIDENCE_V4_ACTIVE_KEY_ID", "writer-k1")
    return keys


def test_locked_v4_writer_preserves_rotation_safe_dedup_and_chain_integrity(monkeypatch):
    keys = _configure_keyring(monkeypatch)
    tenant_id = "writer-v4-rotation-dedup"
    old_ring = Keyring(keys=keys, active_key_id="writer-k1")
    new_ring = Keyring(keys=keys, active_key_id="writer-k2")

    with SessionLocal() as db:
        begin_write_transaction(db, tenant_id=tenant_id)
        first = append_evidence_v4_locked(
            db, tenant_id, "provenance.runtime",
            {"run_id": "r1", "result": "391"},
            keyring=old_ring,
        )
        db.commit()

    monkeypatch.setenv("OLA_EVIDENCE_V4_ACTIVE_KEY_ID", "writer-k2")
    with SessionLocal() as db:
        begin_write_transaction(db, tenant_id=tenant_id)
        duplicate = append_evidence_v4_locked(
            db, tenant_id, "provenance.runtime",
            {"result": "391", "run_id": "r1"},
            keyring=new_ring,
            deduplicate=True,
        )
        db.commit()

    assert duplicate["deduplicated"] is True
    assert duplicate["id"] == first["id"]
    assert duplicate["record_hash"] == first["record_hash"]

    with SessionLocal() as db:
        begin_write_transaction(db, tenant_id=tenant_id)
        second = append_evidence_v4_locked(
            db, tenant_id, "provenance.runtime",
            {"run_id": "r2", "result": "392"},
            keyring=new_ring,
        )
        db.commit()

    assert second["seq"] == 1
    with SessionLocal() as db:
        rows = db.scalars(
            select(EvidenceRecord).where(EvidenceRecord.tenant_id == tenant_id)
            .order_by(EvidenceRecord.seq.asc())
        ).all()
    records = [{
        "id": row.id, "tenant_id": row.tenant_id, "seq": row.seq,
        "record_type": row.record_type, "payload_json": row.payload_json,
        "prev_hash": row.prev_hash, "record_hash": row.record_hash,
    } for row in rows]
    assert verify_chain(records) == (True, "ok")
    assert json.loads(rows[0].payload_json)["__ola_evidence_v4__"]["key_id"] == "writer-k1"
    assert json.loads(rows[1].payload_json)["__ola_evidence_v4__"]["key_id"] == "writer-k2"


def test_locked_v4_writer_refuses_to_extend_invalid_existing_chain(monkeypatch):
    keys = _configure_keyring(monkeypatch)
    tenant_id = "writer-v4-corrupt-chain"
    with SessionLocal() as db:
        db.add(EvidenceRecord(
            id="corrupt-v4-row",
            tenant_id=tenant_id,
            seq=0,
            record_type="provenance.runtime",
            payload_json='{"tampered":true}',
            prev_hash="0" * 64,
            record_hash="f" * 64,
        ))
        db.commit()

    with SessionLocal() as db:
        begin_write_transaction(db, tenant_id=tenant_id)
        try:
            append_evidence_v4_locked(
                db, tenant_id, "provenance.runtime",
                {"run_id": "r1"},
                keyring=Keyring(keys=keys, active_key_id="writer-k1"),
            )
        except ValueError as exc:
            assert "existing tenant evidence chain is invalid" in str(exc)
            db.rollback()
        else:
            raise AssertionError("writer appended to an invalid evidence chain")
