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


def test_six_agents_produce_verified_invoice_result_and_external_verifier_passes(monkeypatch):
    tenant_id = str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="business-invoice-test"))
        db.commit()

    monkeypatch.setenv("OLA_SOURCE_COMMIT", "business-invoice-test-commit")
    monkeypatch.delenv("OLA_RUNTIME_COMMIT", raising=False)
    monkeypatch.delenv("OLA_REPLAY_NONCE", raising=False)
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


def test_business_policy_block_is_a_completed_audited_run(monkeypatch):
    tenant_id = str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="business-invoice-block-test"))
        db.commit()

    monkeypatch.setenv("OLA_SOURCE_COMMIT", "business-invoice-test-commit")
    monkeypatch.delenv("OLA_RUNTIME_COMMIT", raising=False)
    monkeypatch.delenv("OLA_REPLAY_NONCE", raising=False)
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



def test_business_agent_exception_is_persisted_and_run_is_closed(monkeypatch):
    import app.pipeline_bridge as pipeline_bridge
    from app.pipeline_bridge import load_chain

    tenant_id = str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="business-invoice-failure-test"))
        db.commit()

    monkeypatch.setenv("OLA_SOURCE_COMMIT", "business-invoice-test-commit")
    monkeypatch.delenv("OLA_RUNTIME_COMMIT", raising=False)
    monkeypatch.delenv("OLA_REPLAY_NONCE", raising=False)

    original_append = pipeline_bridge.append_evidence
    failed_once = {"value": False}

    def fail_react_once(tenant, record_type, payload, *, attempts=8):
        if record_type == "agent.react" and not failed_once["value"]:
            failed_once["value"] = True
            raise TimeoutError("provider timeout secret-marker")
        return original_append(tenant, record_type, payload, attempts=attempts)

    monkeypatch.setattr(pipeline_bridge, "append_evidence", fail_react_once)
    result = run_invoice_task(tenant_id, TASK)

    assert result["status"] == "BLOCK", result
    assert result["failed_agent"] == "react", result
    assert result["execution_status"] == "FAILED", result
    assert result["lifecycle"]["status"] == "VERIFIED", result
    assert result["replay_verification"]["status"] == "VERIFIED", result
    assert result["replay_verification"]["execution_status"] == "FAILED", result

    selected = [
        record for record in load_chain(tenant_id)
        if json.loads(record["payload_json"]).get("run_id") == result["run_id"]
        and record["record_type"].startswith("agent.")
    ]
    assert [record["record_type"] for record in selected] == ["agent.codeact", "agent.react"]
    failure = json.loads(selected[-1]["payload_json"])
    assert failure["status"] == "BLOCK"
    assert failure["execution_status"] == "FAILED"
    assert failure["error_type"] == "TimeoutError"
    assert len(failure["error_digest"]) == 64
    assert "secret-marker" not in json.dumps(failure)
    assert result["final_result"] is None
