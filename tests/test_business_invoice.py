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
    assert result["status"] == "RECORDED", result
    assert result["execution_boundary"] == "in_process"
    assert "tenant_evidence_hash_chain_integrity" in result["verification_scope"]
    assert "real_llm_invocation" in result["not_established"]
    assert len(result["execution"]) == 6
    assert result["final_result"]["gross"] == 1210.0
    assert result["final_result"]["transfer_amount"] == 1210.0
    assert result["final_result"]["transfer_status"] == "READY_NOT_SENT"

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
    assert proof["agent_instance_count"] == 6
    assert proof["unique_context_count"] == 6
    assert proof["execution_boundary"] == "in_process"
    assert proof["verifier_boundary"] == "separate_process"
    assert "isolated_or_independent_agent_processes" in proof["not_established"]
    assert proof["transfer_status"] == "READY_NOT_SENT"



def test_vat_policy_mismatch_blocks_transfer_and_independent_verifier():
    tenant_id = str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="business-invoice-vat-mismatch"))
        db.commit()

    invoice = {**INVOICE, "invoice_id": "INV-TEST-VAT-MISMATCH", "vat_rate": 0.25}
    task = "INVOICE_JSON:" + json.dumps(invoice, sort_keys=True, separators=(",", ":"))
    result = run_invoice_task(tenant_id, task)

    assert result["status"] == "BLOCK", result
    assert result["execution"][-2]["tool_output"] == "FAIL", result
    assert result["final_result"]["payment_decision"] == "BLOCK", result
    assert result["final_result"]["transfer_amount"] == 0, result
    assert result["final_result"]["transfer_status"] == "BLOCKED_POLICY_MISMATCH", result

    verifier = subprocess.run(
        [sys.executable, "scripts/verify_business_invoice.py",
         "--db", os.environ["OLA_EG_DB_PATH"],
         "--tenant-id", tenant_id,
         "--run-id", result["run_id"],
         "--invoice-json", json.dumps(invoice, sort_keys=True, separators=(",", ":"))],
        capture_output=True,
        text=True,
    )
    assert verifier.returncode != 0, verifier.stdout + verifier.stderr
    proof = json.loads(verifier.stderr.strip())
    assert proof["status"] == "BLOCK"
