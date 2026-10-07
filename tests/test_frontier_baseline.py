import hashlib
import json
import os
import uuid

from app.agent_runtime import run_agent_task
from app.database import SessionLocal
from app.models import Tenant
from app.hashchain import verify_chain
from sqlalchemy import select

def test_frontier_baseline_vector():
    os.environ["OLA_LLM_MODE"] = "deterministic"
    tenant_id = str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="frontier-baseline"))
        db.commit()

    result = run_agent_task(tenant_id, "Calculate 17 * 23 and return the verified result.")
    assert result["status"] == "VERIFIED"
    assert result["final_result"] == "391"
    assert len(result["execution"]) == 6
    assert len(set(item["agent_instance_id"] for item in result["execution"])) == 6
    assert len(set(item["context_digest"] for item in result["execution"])) == 6

    with SessionLocal() as db:
        rows = db.scalars(
            select(__import__("app.models", fromlist=["EvidenceRecord"]).EvidenceRecord)
            .where(__import__("app.models", fromlist=["EvidenceRecord"]).EvidenceRecord.tenant_id == tenant_id)
            .order_by(__import__("app.models", fromlist=["EvidenceRecord"]).EvidenceRecord.seq.asc())
        ).all()

    chain = [
        {"tenant_id": r.tenant_id, "seq": r.seq, "prev_hash": r.prev_hash,
         "record_hash": r.record_hash, "record_type": r.record_type, "payload_json": r.payload_json}
        for r in rows
    ]
    chain_ok, reason = verify_chain(chain)
    assert chain_ok, reason

    vector = {
        "benchmark": "OLA-Frontier-Baseline-v1",
        "task": "Calculate 17 * 23",
        "task_completion": 1,
        "correctness": 1 if result["final_result"] == "391" else 0,
        "evidence_completeness": len(rows) / 6,
        "hash_chain_integrity": 1 if chain_ok else 0,
        "independent_agent_instances": len(set(item["agent_instance_id"] for item in result["execution"])) / 6,
        "independent_contexts": len(set(item["context_digest"] for item in result["execution"])) / 6,
        "terminal_status": result["status"],
    }
    print(json.dumps(vector, sort_keys=True))
