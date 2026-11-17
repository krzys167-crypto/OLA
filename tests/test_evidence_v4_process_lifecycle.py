import base64
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KEYS = {
    "process-k1": b"process-restart-key-one-material-32bytes",
    "process-k2": b"process-restart-key-two-material-32bytes",
}
TENANT = "v4-process-lifecycle-tenant"


def _keyring_json(keys):
    return json.dumps({key_id: base64.b64encode(value).decode() for key_id, value in keys.items()})


def _run(code, db_path, keys, active, *, expect_success=True):
    env = os.environ.copy()
    env.pop("OLA_DATABASE_URL", None)
    env.pop("DATABASE_URL", None)
    env["PYTHONPATH"] = str(ROOT)
    env["OLA_EG_DB_PATH"] = str(db_path)
    env["OLA_EVIDENCE_V4_KEYRING_JSON"] = _keyring_json(keys)
    env["OLA_EVIDENCE_V4_ACTIVE_KEY_ID"] = active
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if expect_success and result.returncode:
        raise AssertionError(f"child process failed: {result.stdout}\n{result.stderr}")
    if not expect_success:
        assert result.returncode != 0, result.stdout
    return result


WRITE_CODE = """
from app.database import Base, engine, SessionLocal, begin_write_transaction
from app.evidence_v4 import load_keyring
from app.evidence_writer import append_evidence_v4_locked
Base.metadata.create_all(bind=engine)
with SessionLocal() as db:
    begin_write_transaction(db, tenant_id=TENANT)
    append_evidence_v4_locked(
        db, TENANT, "provenance.runtime",
        {"run_id": RUN_ID, "result": RESULT},
        keyring=load_keyring(),
    )
    db.commit()
""".replace("TENANT", repr(TENANT))


VERIFY_CODE = """
from sqlalchemy import select
from app.database import SessionLocal
from app.igor_evidence_verifier import verify_chain
from app.models import EvidenceRecord
with SessionLocal() as db:
    rows = db.scalars(
        select(EvidenceRecord).where(EvidenceRecord.tenant_id == TENANT)
        .order_by(EvidenceRecord.seq.asc())
    ).all()
records = [{
    "tenant_id": row.tenant_id, "seq": row.seq, "record_type": row.record_type,
    "payload_json": row.payload_json, "prev_hash": row.prev_hash,
    "record_hash": row.record_hash,
} for row in rows]
ok, reason = verify_chain(records)
assert ok, reason
assert len(records) == 2, len(records)
print("V4_PROCESS_RESTART_VERIFIED")
""".replace("TENANT", repr(TENANT))


def test_real_process_restart_rotation_and_separate_backup_restore(tmp_path):
    source_db = tmp_path / "source.sqlite3"
    backup_db = tmp_path / "backup.sqlite3"
    restored_db = tmp_path / "restored.sqlite3"
    secret_backup = tmp_path / "v4-keyring-backup.json"

    first_write = WRITE_CODE.replace("RUN_ID", repr("run-before-restart")).replace("RESULT", repr("391"))
    _run(first_write, source_db, {"process-k1": KEYS["process-k1"]}, "process-k1")

    second_write = WRITE_CODE.replace("RUN_ID", repr("run-after-rotation")).replace("RESULT", repr("392"))
    _run(second_write, source_db, KEYS, "process-k2")

    _run(VERIFY_CODE, source_db, KEYS, "process-k2")

    # Evidence backup and secret backup are separate artifacts.
    with sqlite3.connect(source_db) as source, sqlite3.connect(backup_db) as backup:
        source.backup(backup)
    secret_backup.write_text(json.dumps({
        "keyring": json.loads(_keyring_json(KEYS)),
        "active_key_id": "process-k2",
    }), encoding="utf-8")
    shutil.copy2(backup_db, restored_db)

    restored_keys = json.loads(secret_backup.read_text(encoding="utf-8"))
    restored_env_keys = {
        key_id: base64.b64decode(encoded, validate=True)
        for key_id, encoded in restored_keys["keyring"].items()
    }
    restored_active_key_id = restored_keys["active_key_id"]
    _run(VERIFY_CODE, restored_db, restored_env_keys, restored_active_key_id)

    # Losing the old key blocks verification; no fallback key is tried.
    _run(VERIFY_CODE, restored_db, {"process-k2": KEYS["process-k2"]}, "process-k2", expect_success=False)

    database_bytes = source_db.read_bytes()
    for secret in KEYS.values():
        assert secret not in database_bytes
        assert base64.b64encode(secret) not in database_bytes
