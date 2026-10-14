import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import uuid

from app.agent_runtime import run_agent_task
from app.database import SessionLocal
from app.models import Tenant

TASK = "Calculate 17 * 23 and return the verified result."
RESULT = "391"


def test_standalone_verifier_blocks_tampered_evidence():
    tenant_id = str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="tamper-proof-test"))
        db.commit()

    runtime = run_agent_task(tenant_id, TASK, allowed_tools=("safe_expression", "local_mcp_tool_registry.sha256"))
    assert runtime["status"] == "VERIFIED", runtime

    source_db = os.environ["OLA_EG_DB_PATH"]
    with tempfile.TemporaryDirectory(prefix="ola_verifier_tamper_") as tmp:
        tampered_db = os.path.join(tmp, "tampered.db")
        shutil.copy2(source_db, tampered_db)
        db = sqlite3.connect(tampered_db)
        # Simulate an attacker who can alter a copied evidence store; the
        # standalone verifier must still reject the broken hash chain.
        db.execute("DROP TRIGGER IF EXISTS evidence_no_update")
        db.execute("DROP TRIGGER IF EXISTS evidence_no_delete")
        db.execute(
            "UPDATE evidence_records SET payload_json=? WHERE tenant_id=? AND seq=0",
            (json.dumps({"tampered": True}, sort_keys=True), tenant_id),
        )
        db.commit()
        db.close()

        verifier = subprocess.run(
            [
                sys.executable,
                "scripts/verify_agent_runtime.py",
                "--db-path", tampered_db,
                "--tenant-id", tenant_id,
                "--run-id", runtime["run_id"],
                "--expected-commit", "TEST_COMMIT",
                "--expected-task", TASK,
                "--expected-result", RESULT,
            ],
            capture_output=True,
            text=True,
        )

    assert verifier.returncode != 0
    proof = json.loads(verifier.stdout.strip())
    assert proof["status"] == "BLOCK"
    assert "hash" in proof["reason"]
