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
            "record_hash": row.record_hash, "payload_json": row.payload_json,
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
