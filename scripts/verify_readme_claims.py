#!/usr/bin/env python3
"""
verify_readme_claims.py

Re-runs the 4 core guarantees claimed in README.md as standalone checks,
independent of the main test suite. Intended for CI and local pre-commit use.

Usage:
    python3 scripts/verify_readme_claims.py

Exit code 0 = all guarantees hold. Non-zero = at least one broke.
Each run gets a fresh temporary SQLite database so stale /tmp state cannot
contaminate the result.
"""
import atexit
import os
import secrets
import shutil
import sys
import tempfile
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app.api_key_hashing import api_key_fingerprint

TEST_DIR = tempfile.mkdtemp(prefix="ola_readme_claims_")
TEST_DB = os.path.join(TEST_DIR, "claims.db")
os.environ["OLA_EG_DB_PATH"] = TEST_DB
# Standalone test fixture; never use this ephemeral pepper for production.
os.environ["OLA_API_KEY_PEPPER"] = secrets.token_hex(32)

FAILURES = []


def _cleanup():
    try:
        from app import database
        database.engine.dispose()
    except Exception:
        pass
    shutil.rmtree(TEST_DIR, ignore_errors=True)


atexit.register(_cleanup)


def check(name):
    def decorator(fn):
        try:
            fn()
            print(f"[PASS] {name}")
        except AssertionError as e:
            print(f"[FAIL] {name}: {e}")
            FAILURES.append(name)
        except Exception as e:
            print(f"[ERROR] {name}: {type(e).__name__}: {e}")
            FAILURES.append(name)
        return fn
    return decorator


def _fresh_db():
    from app import database
    database.engine.dispose()
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)
    database.Base.metadata.create_all(bind=database.engine)
    database.install_append_only_triggers()


@check("Claim #1: append-only — UPDATE is blocked at DB level")
def _c1():
    from sqlalchemy import text
    from app.database import SessionLocal
    from app.models import EvidenceRecord

    _fresh_db()
    db = SessionLocal()
    rec = EvidenceRecord(id=str(uuid.uuid4()), tenant_id="t", seq=0,
                          record_type="generic", payload_json="{}",
                          prev_hash="0" * 64, record_hash="a" * 64)
    db.add(rec)
    db.commit()
    try:
        db.execute(text("UPDATE evidence_records SET payload_json=:p WHERE id=:id"),
                   {"p": '{"x":1}', "id": rec.id})
        db.commit()
        raise AssertionError("UPDATE succeeded — append-only trigger did not block it")
    except AssertionError:
        raise
    except Exception:
        db.rollback()


@check("Claim #2: hash-chain — tampered payload is detected by recompute")
def _c2():
    from app.hashchain import GENESIS_HASH, canonical_json, compute_record_hash, verify_chain

    pj = canonical_json({"a": 1})
    h = compute_record_hash("t", 0, GENESIS_HASH, pj)
    records = [{"tenant_id": "t", "seq": 0, "prev_hash": GENESIS_HASH,
                "record_hash": h, "payload_json": pj}]
    valid, _ = verify_chain(records)
    assert valid, "sanity: untampered chain should verify"

    records[0]["payload_json"] = canonical_json({"a": 999})
    valid, _ = verify_chain(records)
    assert not valid, "tampered payload was NOT detected"


@check("Claim #3: tenant isolation — cross-tenant record access is 404, not 403")
def _c3():
    from fastapi.testclient import TestClient
    from app.main import app
    from app.database import SessionLocal
    from app.models import Tenant, ApiKey
    import hashlib

    _fresh_db()
    db = SessionLocal()
    tA, tB = Tenant(id=str(uuid.uuid4()), name="a"), Tenant(id=str(uuid.uuid4()), name="b")
    db.add_all([tA, tB]); db.commit()
    kA_raw, kB_raw = "key-a", "key-b"
    db.add_all([
        ApiKey(id=str(uuid.uuid4()), tenant_id=tA.id, key_hash=api_key_fingerprint(kA_raw)),
        ApiKey(id=str(uuid.uuid4()), tenant_id=tB.id, key_hash=api_key_fingerprint(kB_raw)),
    ])
    db.commit()

    client = TestClient(app)
    created = client.post("/evidence", headers={"X-API-Key": kA_raw},
                          json={"record_type": "generic", "payload": {}}).json()
    r = client.get(f"/evidence/{created['id']}", headers={"X-API-Key": kB_raw})
    assert r.status_code == 404, f"expected 404, got {r.status_code}"


@check("Claim #4: UNKNOWN is never silently coerced to PASS")
def _c4():
    from app.rules import rule_core_hash_001, rule_cert_expiry_001, RuleStatus

    r1 = rule_core_hash_001([])
    assert r1.status == RuleStatus.UNKNOWN, f"expected UNKNOWN on no records, got {r1.status}"

    r2 = rule_cert_expiry_001(
        [{"tenant_id": "t", "seq": 0, "record_type": "certificate", "payload_json": "{}"}]
    )
    assert r2.status == RuleStatus.UNKNOWN, f"expected UNKNOWN on malformed cert, got {r2.status}"


if __name__ == "__main__":
    print()
    if FAILURES:
        print(f"{len(FAILURES)} claim(s) BROKEN: {', '.join(FAILURES)}")
        sys.exit(1)
    print("All README guarantees verified.")
    sys.exit(0)
