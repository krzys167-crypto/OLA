"""Read-only tenant-scoped Command Center projections from the canonical EvidenceRecord table.

This is NOT an independent cryptographic attestation: SQLite hash-chain checks
can prove internal consistency, not signed source identity or production GO.
"""
from __future__ import annotations

import json
import os
import re
from sqlalchemy import select

from .agent_runtime import AGENT_ROLES
from .database import SessionLocal
from .hashchain import verify_chain
from .models import EvidenceRecord
from .replay import verify_replay

MAX_RECORDS = 5000
MAX_ACTIVITY = 12
SOURCE_SHA = re.compile(r"^[a-f0-9]{40}$")
RUN_ID = re.compile(r"^[a-f0-9-]{36}$")


def load_tenant_records(tenant_id: str):
    """Read bounded *complete* tenant history. Never silently verify a truncated chain."""
    with SessionLocal() as db:
        rows = db.scalars(
            select(EvidenceRecord)
            .where(EvidenceRecord.tenant_id == tenant_id)
            .order_by(EvidenceRecord.seq.asc())
            .limit(MAX_RECORDS + 1)
        ).all()
    if len(rows) > MAX_RECORDS:
        return None
    return [
        {
            "id": row.id,
            "tenant_id": row.tenant_id,
            "seq": row.seq,
            "prev_hash": row.prev_hash,
            "record_hash": row.record_hash,
            "record_type": row.record_type,
            "payload_json": row.payload_json,
        }
        for row in rows
    ]


def _payload(record):
    try:
        value = json.loads(record["payload_json"])
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _integrity(records):
    if records is None:
        return "UNKNOWN", "evidence retention exceeds safe verification bound"
    if not records:
        return "UNKNOWN", "no evidence recorded for tenant"
    ok, reason = verify_chain(records)
    if not ok:
        return "BLOCK", reason
    if any(_payload(row) is None for row in records):
        return "BLOCK", "invalid or non-object evidence payload"
    return "VERIFIED", reason


def _runs(records):
    candidates = {}
    approvals = set()
    provenances = {}
    for row in records:
        payload = _payload(row)
        if payload is None or not isinstance(payload.get("run_id"), str):
            continue
        run_id = payload["run_id"]
        if row["record_type"] == "decision.candidate":
            candidates[run_id] = payload
        elif row["record_type"] == "human.approval":
            approvals.add(run_id)
        elif row["record_type"] == "provenance.runtime":
            provenances[run_id] = payload
    result = []
    for run_id, candidate in reversed(list(candidates.items())):
        fields = candidate.get("status_fields")
        fields = fields if isinstance(fields, dict) else {}
        prov = provenances.get(run_id, {})
        result.append({
            "run_id": run_id,
            "candidate_status_recorded": candidate.get("candidate_status", "UNKNOWN"),
            "nina_status_recorded": fields.get("RUNTIME", "UNKNOWN"),
            "replay_status_recorded": fields.get("REPLAY_INTEGRITY", "UNKNOWN"),
            "policy_status_recorded": fields.get("POLICY", "UNKNOWN"),
            "human_approval_recorded": run_id in approvals,
            "provider_recorded": prov.get("provider"),
            "model_recorded": prov.get("model"),
            "source_commit_recorded": prov.get("commit", "UNKNOWN"),
            "verified_from_source": False,
        })
    return result


def get_overview(tenant_id: str):
    records = load_tenant_records(tenant_id)
    integrity, reason = _integrity(records)
    source = os.environ.get("OLA_RUNTIME_COMMIT", "").strip()
    source_status = "DECLARED_SHA_NOT_SIGNED" if SOURCE_SHA.fullmatch(source) else "UNKNOWN"
    provider = os.environ.get("OLA_LLM_PROVIDER", "").strip().lower() or "UNKNOWN"
    model = os.environ.get("OLA_LLM_MODEL", "").strip() or "UNKNOWN"
    if records is None:
        activities = []
        runs = []
        count = None
        tip_hash = None
    else:
        activities = []
        if integrity == "VERIFIED":
            for row in records[-MAX_ACTIVITY:]:
                payload = _payload(row)
                activities.append({
                    "record_id": row["id"],
                    "seq": row["seq"],
                    "type": row["record_type"],
                    "run_id": payload.get("run_id") if payload else None,
                })
            runs = _runs(records)[:MAX_ACTIVITY]
        else:
            runs = []
        count = len(records)
        tip_hash = records[-1]["record_hash"] if integrity == "VERIFIED" else None
    return {
        "schema": "ola.command-center.v1",
        "tenant_id": tenant_id,
        "api": {"status": "AUTHENTICATED", "scope": "OLA_CORE"},
        "source": {"status": source_status, "commit": source if source_status != "UNKNOWN" else None},
        "evidence": {
            "status": integrity,
            "reason": reason,
            "record_count": count,
            "tip_hash": tip_hash,
        },
        "orchestrator": {
            "status": "REGISTERED_NOT_EXECUTED",
            "roles": list(AGENT_ROLES),
        },
        "llm": {"provider_configured": provider, "model_configured": model, "connectivity": "UNKNOWN"},
        "runs": runs,
        "recent_events": activities,
        "production": {"status": "NO-GO", "reason": "signed release and independent human gate not proven by read-only telemetry"},
        "evidence_trust": "LOCAL_SQLITE_HASH_CHAIN_NOT_EXTERNAL_ATTESTATION",
    }


def get_run_detail(tenant_id: str, run_id: str):
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        return None
    records = load_tenant_records(tenant_id)
    integrity, reason = _integrity(records)
    if records is None:
        return {"run_id": run_id, "status": "UNKNOWN", "reason": reason, "records": []}
    rows = []
    found = False
    for row in records:
        payload = _payload(row)
        if payload and payload.get("run_id") == run_id:
            found = True
            rows.append({
                "record_id": row["id"],
                "seq": row["seq"],
                "type": row["record_type"],
                "hash": row["record_hash"],
            })
    if not found:
        return None
    if integrity != "VERIFIED":
        return {"run_id": run_id, "status": "BLOCK", "reason": reason, "records": []}

    replay = verify_replay(
        records,
        expected_run_id=run_id,
        expected_tenant_id=tenant_id,
        expected_record_count=len(records),
        expected_tip_hash=records[-1]["record_hash"],
    )
    return {
        "run_id": run_id,
        "status": replay["status"],
        "reason": replay.get("reason"),
        "replay": replay,
        "records": rows,
        "scope": "LOCAL_HASH_AND_REPLAY_ONLY",
        "independent_release_verification": "UNKNOWN",
        "production": "NO-GO",
    }
