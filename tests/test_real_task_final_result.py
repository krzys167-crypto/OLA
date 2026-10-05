import json
import os
import subprocess
import sys
import uuid

from app.agent_runtime import run_agent_task
from app.database import SessionLocal
from app.models import Tenant

REAL_TASK = "Calculate 17 * 23 and return the verified result."
EXPECTED_RESULT = "391"


def _tenant():
    tenant_id = str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="real-task-test"))
        db.commit()
    return tenant_id


def test_six_agents_produce_verified_final_result_with_external_verifier():
    tenant_id = _tenant()
    os.environ["OLA_SOURCE_COMMIT"] = "TEST_COMMIT"
    result = run_agent_task(tenant_id, REAL_TASK)

    assert result["status"] == "VERIFIED", result
    assert result["task"] == REAL_TASK
    assert result["final_result"] == EXPECTED_RESULT
    assert len(result["execution"]) == 6
    assert result["execution"][0]["tool_output"] == EXPECTED_RESULT
    assert result["execution"][-1]["final_result"] == EXPECTED_RESULT

    verifier = subprocess.run(
        [
            sys.executable,
            "scripts/verify_agent_runtime.py",
            "--tenant-id",
            tenant_id,
            "--run-id",
            result["run_id"],
            "--expected-commit",
            "TEST_COMMIT",
            "--expected-task",
            REAL_TASK,
            "--expected-result",
            EXPECTED_RESULT,
        ],
        capture_output=True,
        text=True,
    )
    assert verifier.returncode == 0, verifier.stdout + verifier.stderr
    proof = json.loads(verifier.stdout.strip())
    assert proof["status"] == "VERIFIED", proof
    assert proof["task"] == REAL_TASK
    assert proof["final_result"] == EXPECTED_RESULT
    assert proof["evidence_count"] == 6
    assert proof["independent_instance_count"] == 6
    assert proof["independent_context_count"] == 6
