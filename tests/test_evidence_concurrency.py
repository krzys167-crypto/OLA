"""Concurrency regression: all production writers must share one atomic SQLite append.

The test stresses independent DB sessions, never only a Python-local lock.
"""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import subprocess
import sys
import uuid

from sqlalchemy import select
from app.database import SessionLocal
from app.hashchain import verify_chain
from app.models import Tenant, EvidenceRecord
from app.main import append_record
import app.agent_runtime as agent_runtime
import app.business_runtime as business_runtime
import app.stripe_webhook as stripe_webhook


def new_tenant():
    tenant_id = str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="concurrent-evidence-test"))
        db.commit()
    return tenant_id


def get_chain(tenant_id):
    with SessionLocal() as db:
        records = db.scalars(select(EvidenceRecord)
                             .where(EvidenceRecord.tenant_id == tenant_id)
                             .order_by(EvidenceRecord.seq.asc())).all()
        return [{
            "tenant_id": row.tenant_id, "seq": row.seq, "prev_hash": row.prev_hash,
            "record_hash": row.record_hash, "record_type": row.record_type, "payload_json": row.payload_json,
        } for row in records]


def test_parallel_four_existing_writer_paths_keep_full_chain(monkeypatch):
    tenant = new_tenant()
    monkeypatch.setattr(agent_runtime, "_execute_agent",
                        lambda *args, **kw: {"result": "test-result"})

    def work(index):
        kind = index % 4
        if kind == 0:
            append_record(tenant, "parallel.api", {"i": index})
        elif kind == 1:
            business_runtime._append(tenant, f"run-{index}", "parallel.business", {"i": index})
        elif kind == 2:
            stripe_webhook._append_evidence(tenant, "parallel.stripe", {"i": index})
        else:
            agent_runtime._append_agent_evidence(
                tenant, f"run-{index}", "codeact", "2 + 2", {}, [])

    with ThreadPoolExecutor(max_workers=12) as pool:
        list(pool.map(work, range(96)))

    records = get_chain(tenant)
    assert len(records) == 96
    assert [row["seq"] for row in records] == list(range(96))
    assert verify_chain(records) == (True, "ok")


def test_multiple_processes_share_sqlite_write_lock():
    tenant = new_tenant()
    program = (
        "from app.main import append_record\n"
        "import sys\n"
        "tenant, owner = sys.argv[1:]\n"
        "for i in range(16):\n"
        "    append_record(tenant, 'parallel.multiprocess', {'owner':owner,'i':i})\n"
    )
    processes = [
        subprocess.Popen([sys.executable, "-c", program, tenant, str(i)])
        for i in range(4)
    ]
    try:
        for proc in processes:
            assert proc.wait(timeout=45) == 0
    finally:
        for proc in processes:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
    chain = get_chain(tenant)
    assert len(chain) == 64
    assert verify_chain(chain) == (True, "ok")


def test_legacy_integrity_readable_but_not_authenticated():
    from app.hashchain import (
        GENESIS_HASH, compute_record_hash, compute_record_hash_v2, canonical_json, sealed_payload_json,
        trusted_record, verify_chain,
    )
    raw = canonical_json({"event": "workflow.planned", "run_id": "old"})
    old = {"tenant_id": "tenant", "seq": 0, "prev_hash": GENESIS_HASH,
           "record_type": "workflow.planned", "payload_json": raw,
           "record_hash": compute_record_hash("tenant", 0, GENESIS_HASH, raw)}
    sealed = sealed_payload_json("workflow.planned", {"event": "workflow.planned", "run_id": "new"})
    new = {"tenant_id": "tenant", "seq": 1, "prev_hash": old["record_hash"],
           "record_type": "workflow.planned", "payload_json": sealed,
           "record_hash": compute_record_hash_v2("tenant", 1, old["record_hash"], "workflow.planned", "ola_runtime", sealed)}
    assert verify_chain([old, new]) == (True, "ok")
    assert trusted_record(old) is False
    assert trusted_record(new) is True


def test_public_evidence_cannot_mint_internal_provenance():
    import pytest
    from app.hashchain import EVIDENCE_META_KEY, sealed_payload_json
    with pytest.raises(ValueError, match="public producer"):
        sealed_payload_json("workflow.planned", {}, producer="tenant_api")
    with pytest.raises(ValueError, match="reserved metadata"):
        sealed_payload_json("customer.proof", {EVIDENCE_META_KEY: {"producer": "ola_runtime"}})


def test_old_hash_with_forged_v2_metadata_cannot_be_promoted():
    from app.hashchain import (
        GENESIS_HASH, canonical_json, compute_record_hash, verify_chain,
        EVIDENCE_META_KEY,
    )
    fake = canonical_json({
        "event": "workflow.planned", "run_id": "attacker",
        EVIDENCE_META_KEY: {
            "version": 2, "record_type": "workflow.planned", "producer": "ola_runtime",
        },
    })
    legacy_hash = compute_record_hash("tenant", 0, GENESIS_HASH, fake)
    old = {"tenant_id": "tenant", "seq": 0, "prev_hash": GENESIS_HASH,
           "record_type": "workflow.planned", "payload_json": fake,
           "record_hash": legacy_hash}
    assert verify_chain([old]) == (False, "record hash mismatch")
