import json
import os
import subprocess
import sys
import uuid

from app.business_runtime import run_invoice_task
from app.database import SessionLocal
from app.models import Tenant

INVOICE = {
    "invoice_id": "INV-TEST-2026-001",
    "supplier": "TEST-SUPPLIER",
    "currency": "EUR",
    "net": 1000.0,
    "vat_rate": 0.21,
}
TASK = "INVOICE_JSON:" + json.dumps(INVOICE, sort_keys=True, separators=(",", ":"))


def test_six_agents_produce_verified_invoice_result_and_external_verifier_passes():
    tenant_id = str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="business-invoice-test"))
        db.commit()

    result = run_invoice_task(tenant_id, TASK)
    assert result["status"] == "VERIFIED", result
    assert len(result["execution"]) == 6
    assert result["final_result"]["gross"] == 1210.0
    assert result["final_result"]["transfer_amount"] == 1210.0
    assert result["final_result"]["transfer_status"] == "READY_NOT_SENT"
    assert result["lifecycle"]["status"] == "VERIFIED", result
    assert result["replay_verification"]["status"] == "VERIFIED", result
    assert result["replay_verification"]["execution_status"] == "SUCCEEDED", result
    assert result["replay_verification"]["run_event_count"] == 8, result

    verifier = subprocess.run(
        [sys.executable, "scripts/verify_business_invoice.py",
         "--db", os.environ["OLA_EG_DB_PATH"],
         "--tenant-id", tenant_id,
         "--run-id", result["run_id"],
         "--invoice-json", json.dumps(INVOICE, sort_keys=True, separators=(",", ":"))],
        capture_output=True,
        text=True,
    )
    assert verifier.returncode == 0, verifier.stdout + verifier.stderr
    proof = json.loads(verifier.stdout.strip())
    assert proof["status"] == "VERIFIED"
    assert proof["gross"] == 1210.0
    assert proof["evidence_count"] == 6
    assert proof["independent_instance_count"] == 6
    assert proof["independent_context_count"] == 6
    assert proof["lifecycle"]["status"] == "VERIFIED"
    assert proof["lifecycle"]["execution_status"] == "SUCCEEDED"
    assert proof["lifecycle"]["run_event_count"] == 8
    assert proof["transfer_status"] == "READY_NOT_SENT"


def test_business_policy_block_is_a_completed_audited_run():
    tenant_id = str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="business-invoice-block-test"))
        db.commit()

    invoice = dict(INVOICE, vat_rate=0.19)
    task = "INVOICE_JSON:" + json.dumps(invoice, sort_keys=True, separators=(",", ":"))
    result = run_invoice_task(tenant_id, task)

    assert result["status"] == "BLOCK", result
    assert result["final_result"]["payment_decision"] == "REJECT_POLICY_MISMATCH"
    assert result["final_result"]["transfer_amount"] == 0.0
    assert result["final_result"]["transfer_status"] == "NOT_SENT"
    assert result["lifecycle"]["status"] == "VERIFIED", result
    assert result["replay_verification"]["status"] == "VERIFIED", result
    assert result["replay_verification"]["execution_status"] == "BLOCKED", result
    assert result["replay_verification"]["blocked_agent_roles"] == ["self_reflection"], result
