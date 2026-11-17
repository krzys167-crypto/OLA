"""Transaction-aware V4 evidence append primitive.

Callers must acquire the tenant evidence-chain write lock and keep this
operation inside their existing SQLAlchemy transaction. This module never
opens, commits, rolls back, or nests a database session.
"""
from __future__ import annotations

import json
import uuid
from typing import Any, Mapping

from sqlalchemy import select

from .evidence_v4 import (
    Keyring,
    V4_META_KEY,
    canonical_json,
    load_keyring,
    seal_payload_v4,
    sign_record,
)
from .models import EvidenceRecord
from .igor_evidence_verifier import verify_chain as verify_existing_chain


def _logical_v4_payload(payload_json: str, *, record_type: str, producer: str) -> str | None:
    """Return canonical application payload for a valid V4 dedup candidate."""
    try:
        payload = json.loads(payload_json)
    except (TypeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    metadata = payload.get(V4_META_KEY)
    if not isinstance(metadata, dict):
        return None
    if set(metadata) != {"version", "key_id", "record_type", "producer"}:
        return None
    if (
        type(metadata.get("version")) is not int
        or metadata["version"] != 4
        or metadata.get("record_type") != record_type
        or metadata.get("producer") != producer
    ):
        return None
    application_payload = dict(payload)
    del application_payload[V4_META_KEY]
    try:
        return canonical_json(application_payload)
    except ValueError:
        return None


def append_evidence_v4_locked(
    db,
    tenant_id: str,
    record_type: str,
    payload: Mapping[str, Any],
    *,
    producer_id: str = "ola_runtime",
    keyring: Keyring | None = None,
    deduplicate: bool = False,
) -> dict:
    """Append one V4 row in the caller's already-locked transaction.

    The function deliberately does not commit. The caller owns the transaction,
    lock lifetime, and any coupled business-state mutations.

    Deduplication is V4-version-scoped and ignores key_id, so rotating the active
    key cannot turn an otherwise identical retry into a second evidence event.
    Legacy rows are not dedup candidates; they require a separate, explicit
    historical reconciliation policy.
    """
    if not isinstance(tenant_id, str) or not tenant_id:
        raise ValueError("tenant_id required for evidence append")
    if not isinstance(record_type, str) or not record_type.strip():
        raise ValueError("record_type required for evidence append")
    if not isinstance(payload, Mapping):
        raise ValueError("evidence payload must be an object")

    ring = keyring or load_keyring()
    logical_payload = canonical_json(dict(payload))

    existing_rows = db.scalars(
        select(EvidenceRecord).where(EvidenceRecord.tenant_id == tenant_id)
        .order_by(EvidenceRecord.seq.asc())
    ).all()
    if existing_rows:
        existing_records = [{
            "id": row.id, "tenant_id": row.tenant_id, "seq": row.seq,
            "record_type": row.record_type, "payload_json": row.payload_json,
            "prev_hash": row.prev_hash, "record_hash": row.record_hash,
        } for row in existing_rows]
        chain_ok, chain_reason = verify_existing_chain(existing_records)
        if not chain_ok:
            raise ValueError(f"existing tenant evidence chain is invalid: {chain_reason}")

    if deduplicate:
        candidates = db.scalars(
            select(EvidenceRecord).where(
                EvidenceRecord.tenant_id == tenant_id,
                EvidenceRecord.record_type == record_type,
            ).order_by(EvidenceRecord.seq.asc())
        ).all()
        for existing in candidates:
            candidate_payload = _logical_v4_payload(
                existing.payload_json,
                record_type=record_type,
                producer=producer_id,
            )
            if candidate_payload == logical_payload:
                return {
                    "id": existing.id,
                    "tenant_id": tenant_id,
                    "seq": existing.seq,
                    "record_hash": existing.record_hash,
                    "deduplicated": True,
                }

    latest = existing_rows[-1] if existing_rows else None
    seq = latest.seq + 1 if latest is not None else 0
    previous_hash = latest.record_hash if latest is not None else "0" * 64
    payload_json = seal_payload_v4(
        record_type, payload, ring, producer=producer_id
    )
    material = {
        "tenant_id": tenant_id,
        "seq": seq,
        "prev_hash": previous_hash,
        "record_type": record_type,
        "producer": producer_id,
        "payload_json": payload_json,
    }
    digest = sign_record(material, ring)
    record_id = str(uuid.uuid4())
    db.add(EvidenceRecord(
        id=record_id,
        tenant_id=tenant_id,
        seq=seq,
        record_type=record_type,
        payload_json=payload_json,
        prev_hash=previous_hash,
        record_hash=digest,
    ))
    db.flush()
    return {
        "id": record_id,
        "tenant_id": tenant_id,
        "seq": seq,
        "record_hash": digest,
        "deduplicated": False,
    }
