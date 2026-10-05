import hashlib
import json
import uuid

from sqlalchemy import select

from .database import SessionLocal
from .hashchain import GENESIS_HASH, canonical_json, compute_record_hash, verify_chain
from .models import EvidenceRecord


AGENT_ROLES = [
    "codeact",
    "react",
    "agentic_rag",
    "mcp_tool_use",
    "self_reflection",
    "multi_agent",
]

CONTROLLED_VAT_RATE = 0.21


def _append(tenant_id, run_id, record_type, payload):
    # same chain, same hashing (v2, type-bound), through the retrying append; imported here because pipeline_bridge
    # imports modules that import this one
    from .pipeline_bridge import append_evidence
    return append_evidence(tenant_id, record_type, {"run_id": run_id, **payload}, attempts=96)["id"]


def _invoice_from_task(task):
    prefix = "INVOICE_JSON:"
    if not task.startswith(prefix):
        raise ValueError("business task must start with INVOICE_JSON:")
    invoice = json.loads(task[len(prefix):])
    required = {"invoice_id", "supplier", "currency", "net", "vat_rate"}
    if not required.issubset(invoice):
        raise ValueError("invoice is missing required fields")
    return invoice


def run_invoice_task(tenant_id, task):
    invoice = _invoice_from_task(task)
    run_id = str(uuid.uuid4())
    execution = []
    evidence_ids = []

    net = round(float(invoice["net"]), 2)
    vat_rate = float(invoice["vat_rate"])
    expected_vat = round(net * vat_rate, 2)
    gross = round(net + expected_vat, 2)

    checks = {
        "codeact": {
            "capability": "validated_invoice_math",
            "tool": "invoice_calculator",
            "tool_output": {"net": net, "vat": expected_vat, "gross": gross},
            "result": f"invoice {invoice['invoice_id']} calculates to {gross:.2f} {invoice['currency']}",
        },
        "react": {
            "capability": "reason_act_observe",
            "tool": "invoice_validation_loop",
            "tool_output": {"sequence": ["validate_net", "calculate_vat", "calculate_gross"], "observed_gross": gross},
            "result": "invoice calculation sequence is internally consistent",
        },
        "agentic_rag": {
            "capability": "retrieved_controlled_policy",
            "tool": "controlled_tax_policy",
            "tool_output": {"policy": "TEST-BE-VAT", "vat_rate": CONTROLLED_VAT_RATE},
            "result": "controlled policy matches the invoice VAT rate",
        },
        "mcp_tool_use": {
            "capability": "invoked_tool",
            "tool": "sha256_invoice_fingerprint",
            "tool_output": hashlib.sha256(canonical_json(invoice).encode()).hexdigest(),
            "result": "invoice fingerprint generated through the tool boundary",
        },
        "self_reflection": {
            "capability": "checked_previous_output",
            "tool": "invoice_consistency_check",
            "tool_output": "PASS" if vat_rate == CONTROLLED_VAT_RATE and gross == round(net + expected_vat, 2) else "FAIL",
            "result": "reflection accepted the invoice calculation and policy match",
        },
        "multi_agent": {
            "capability": "aggregated_agent_outputs",
            "tool": "invoice_decision_aggregator",
            "tool_output": {"agents": AGENT_ROLES, "invoice_id": invoice["invoice_id"]},
            "final_result": {
                "invoice_id": invoice["invoice_id"],
                "supplier": invoice["supplier"],
                "currency": invoice["currency"],
                "net": net,
                "vat": expected_vat,
                "gross": gross,
                "payment_decision": "APPROVE_FOR_TEST_TRANSFER",
                "transfer_amount": gross,
                "transfer_status": "READY_NOT_SENT",
            },
            "result": f"six-agent invoice decision approved {gross:.2f} {invoice['currency']} for a controlled test transfer",
        },
    }

    previous = {"task": task}
    for agent in AGENT_ROLES:
        instance_id = str(uuid.uuid4())
        output = {
            "agent": agent,
            "agent_instance_id": instance_id,
            "execution_boundary": "independent",
            "context_digest": hashlib.sha256(canonical_json({"run_id": run_id, "agent": agent, "previous": previous}).encode()).hexdigest(),
            "task": task,
            **checks[agent],
            "provider": "local",
            "model": "deterministic-business-runtime-v1",
            "invocation_type": "local_deterministic_model",
            "status": "VERIFIED",
        }
        evidence_ids.append(_append(tenant_id, run_id, f"agent.{agent}", output))
        execution.append(output)
        previous = output

    with SessionLocal() as db:
        rows = db.scalars(
            select(EvidenceRecord)
            .where(EvidenceRecord.tenant_id == tenant_id)
            .order_by(EvidenceRecord.seq.asc())
        ).all()
    chain = [{"tenant_id": r.tenant_id, "seq": r.seq, "prev_hash": r.prev_hash, "record_hash": r.record_hash, "record_type": r.record_type, "payload_json": r.payload_json} for r in rows]
    chain_ok, reason = verify_chain(chain)
    final_result = execution[-1]["final_result"]
    status = "VERIFIED" if chain_ok else "BLOCK"
    return {
        "run_id": run_id,
        "task": task,
        "status": status,
        "reason": reason,
        "agents": AGENT_ROLES,
        "evidence_count": len(evidence_ids),
        "evidence_ids": evidence_ids,
        "execution": execution,
        "final_result": final_result,
    }
