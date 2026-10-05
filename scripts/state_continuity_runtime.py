#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import uuid

os.environ.setdefault("OLA_LLM_MODE", "deterministic")

from app.agent_runtime import run_agent_task
from app.database import SessionLocal
from app.hashchain import verify_chain
from app.models import EvidenceRecord, Tenant


def chain_snapshot(tenant_id):
    with SessionLocal() as db:
        rows = db.query(EvidenceRecord).filter(EvidenceRecord.tenant_id == tenant_id).order_by(EvidenceRecord.seq.asc()).all()
        chain = [{
            "tenant_id": r.tenant_id,
            "seq": r.seq,
            "prev_hash": r.prev_hash,
            "record_hash": r.record_hash,
            "record_type": r.record_type,
            "payload_json": r.payload_json,
        } for r in rows]
    ok, reason = verify_chain(chain)
    if not ok:
        raise SystemExit(f"hash-chain verification failed: {reason}")
    return {"count": len(rows), "tip_hash": rows[-1].record_hash if rows else None, "next_seq": len(rows), "chain_status": "VERIFIED"}


def create_tenant():
    tenant_id = str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="state-continuity-runtime"))
        db.commit()
    return tenant_id


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant")
    parser.add_argument("--task", default="Calculate 17 * 23 and return the verified result.")
    parser.add_argument("--inspect", action="store_true")
    args = parser.parse_args()
    tenant = args.tenant or create_tenant()
    if args.inspect:
        print(json.dumps({"tenant_id": tenant, **chain_snapshot(tenant)}, sort_keys=True))
        return
    result = run_agent_task(tenant, args.task)
    if result.get("status") != "VERIFIED":
        raise SystemExit(json.dumps({"tenant_id": tenant, "result": result}, sort_keys=True))
    print(json.dumps({
        "tenant_id": tenant,
        "result_status": result["status"],
        "final_result": result["final_result"],
        "execution_count": len(result.get("execution", [])),
        **chain_snapshot(tenant),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
