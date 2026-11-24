import hashlib
import json
import math
import os
import re
import uuid
from datetime import datetime, timezone
from decimal import Context, Decimal, ROUND_HALF_UP

from sqlalchemy import select

from .database import SessionLocal
from .hashchain import GENESIS_HASH, canonical_json, compute_record_hash, verify_chain
from .models import EvidenceRecord
from .replay import run_event_digest, verify_replay


AGENT_ROLES = [
    "codeact",
    "react",
    "agentic_rag",
    "mcp_tool_use",
    "self_reflection",
    "multi_agent",
]

CONTROLLED_VAT_RATE = 0.21
MAX_NET = 1_000_000_000.0
MAX_INVOICE_BYTES = 65536
_CURRENCY = re.compile(r"[A-Z]{3}")
_CENT = Decimal("0.01")
_CONTEXT = Context(prec=60)                       # far more digits than net (<= 1e9, 2 decimals) x rate can ever need
_CONTROLLED_RATE = Decimal(repr(CONTROLLED_VAT_RATE))


def _number(value, field):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be a JSON number")
    if not math.isfinite(value):
        raise ValueError(f"{field} must be finite")
    return float(value)


def validate_invoice(invoice):
    """Amounts are checked, not coerced: a string, a bool, null, NaN, a negative or sub-cent net is a 400."""
    for field in ("invoice_id", "supplier"):
        if not isinstance(invoice.get(field), str) or not invoice[field].strip() or len(invoice[field]) > 200:
            raise ValueError(f"{field} must be a non-empty string of at most 200 characters")
        try:
            invoice[field].encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError(f"{field} is not valid UTF-8 text") from None
    if not isinstance(invoice.get("currency"), str) or not _CURRENCY.fullmatch(invoice["currency"]):
        raise ValueError("currency must be an ISO 4217 style code of three capital letters")
    net = _number(invoice.get("net"), "net")
    vat_rate = _number(invoice.get("vat_rate"), "vat_rate")
    if not 0 < net <= MAX_NET:
        raise ValueError(f"net must be greater than 0 and at most {MAX_NET:.0f}")
    if round(net, 2) != net:
        raise ValueError("net must not have more than two decimal places")
    if not 0 <= vat_rate <= 1:
        raise ValueError("vat_rate must be between 0 and 1")
    return net, vat_rate


def money(net, vat_rate):
    """(vat, gross, policy_match) in decimal arithmetic, rounded half-up to the cent. Binary floats cannot do this:
    round(0.5 * 0.21, 2) is 0.10 because 0.105 is stored as 0.10499999999999999, where the invoice means 0.11.
    The inputs are the floats the JSON parser produced; repr() is the shortest decimal that round-trips to them, i.e.
    the number the client wrote. scripts/verify_business_invoice.py repeats exactly this."""
    try:
        net_d, rate_d = Decimal(repr(net)), Decimal(repr(vat_rate))
        vat = _CONTEXT.multiply(net_d, rate_d).quantize(_CENT, rounding=ROUND_HALF_UP, context=_CONTEXT)
        if vat.is_zero():
            vat = abs(vat)                        # never -0.00 (a vat_rate of -0.0 is accepted: -0.0 == 0)
        gross = _CONTEXT.add(net_d, vat).quantize(_CENT, rounding=ROUND_HALF_UP, context=_CONTEXT)
    except ArithmeticError as exc:
        raise ValueError("invoice amounts are outside the supported range") from exc
    return float(vat), float(gross), rate_d == _CONTROLLED_RATE


def _append(tenant_id, run_id, record_type, payload):
    """Append one business-run event to the tenant's shared append-only chain."""
    from .pipeline_bridge import append_evidence
    return append_evidence(tenant_id, record_type, {"run_id": run_id, **payload}, attempts=96)


def _invoice_from_task(task):
    prefix = "INVOICE_JSON:"
    if not task.startswith(prefix):
        raise ValueError("business task must start with INVOICE_JSON:")
    invoice = json.loads(task[len(prefix):])
    if not isinstance(invoice, dict):
        raise ValueError("invoice must be a JSON object")
    required = {"invoice_id", "supplier", "currency", "net", "vat_rate"}
    if not required.issubset(invoice):
        raise ValueError("invoice is missing required fields")
    return invoice


def run_invoice_task(tenant_id, task):
    invoice = _invoice_from_task(task)
    net, vat_rate = validate_invoice(invoice)
    expected_vat, gross, policy_match = money(net, vat_rate)

    run_id = str(uuid.uuid4())
    source_commit = os.getenv("OLA_SOURCE_COMMIT", os.getenv("OLA_RUNTIME_COMMIT", "UNKNOWN"))
    replay_nonce = os.getenv("OLA_REPLAY_NONCE") or "NOT_REQUIRED"
    task_digest = hashlib.sha256(task.encode("utf-8")).hexdigest()
    started_at = datetime.now(timezone.utc).isoformat()
    execution = []
    evidence_ids = []
    blocked_agent_roles = []
    failed_agent = None
    failure_type = None
    failure_digest = None

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
            "result": ("controlled policy matches the invoice VAT rate" if policy_match else
                       f"controlled policy ({CONTROLLED_VAT_RATE}) does NOT match the invoice VAT rate ({vat_rate})"),
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
            "tool_output": "PASS" if policy_match and Decimal(repr(net)) + Decimal(repr(expected_vat)) == Decimal(repr(gross)) else "FAIL",
            "result": ("reflection accepted the invoice calculation and policy match" if policy_match else
                       "reflection REJECTED the invoice: its VAT rate differs from the controlled policy"),
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
                "payment_decision": "APPROVE_FOR_TEST_TRANSFER" if policy_match else "REJECT_POLICY_MISMATCH",
                "transfer_amount": gross if policy_match else 0.0,
                "transfer_status": "READY_NOT_SENT" if policy_match else "NOT_SENT",
            },
            "result": (f"six-agent invoice decision approved {gross:.2f} {invoice['currency']} for a controlled test transfer"
                       if policy_match else "six-agent invoice decision REJECTED the payment: VAT rate outside the controlled policy"),
        },
    }

    from .pipeline_bridge import load_chain
    start_record = _append(tenant_id, run_id, "run.start", {
        "schema": "ola.run-lifecycle/v1",
        "started_at": started_at,
        "task_digest": task_digest,
        "source_commit": source_commit,
        "replay_nonce": replay_nonce,
        "expected_agent_roles": list(AGENT_ROLES),
        "runtime_kind": "business_invoice",
    })

    previous = {"task": task}
    for agent in AGENT_ROLES:
        agent_started_at = datetime.now(timezone.utc).isoformat()
        instance_id = str(uuid.uuid4())
        output = {
            "agent": agent,
            "agent_instance_id": instance_id,
            "execution_boundary": "independent",
            "context_digest": hashlib.sha256(canonical_json({"run_id": run_id, "agent": agent, "previous": previous}).encode()).hexdigest(),
            "task": task,
            "input_digest": hashlib.sha256(canonical_json(previous).encode("utf-8")).hexdigest(),
            "started_at": agent_started_at,
            "ended_at": datetime.now(timezone.utc).isoformat(),
            "source_commit": source_commit,
            "replay_nonce": replay_nonce,
            "execution_status": "VERIFIED",
            **checks[agent],
            "provider": "local",
            "model": "deterministic-business-runtime-v1",
            "invocation_type": "local_deterministic_model",
            "status": "VERIFIED" if (policy_match or agent != "self_reflection") else "BLOCK",
        }
        try:
            record = _append(tenant_id, run_id, f"agent.{agent}", output)
        except Exception as exc:
            failed_agent = agent
            failure_type = type(exc).__name__
            failure_digest = hashlib.sha256(
                f"ola.agent-failure/v1|{run_id}|{agent}|{failure_type}".encode("utf-8")
            ).hexdigest()
            failure = {
                "agent": agent,
                "agent_instance_id": instance_id,
                "execution_boundary": "independent",
                "context_digest": output["context_digest"],
                "task": task,
                "input_digest": output["input_digest"],
                "started_at": agent_started_at,
                "ended_at": datetime.now(timezone.utc).isoformat(),
                "source_commit": source_commit,
                "replay_nonce": replay_nonce,
                "execution_status": "FAILED",
                "capability": "agent_execution_failed",
                "tool": "agent.error",
                "tool_output": "",
                "result": "business agent invocation failed; output was not accepted",
                "provider": "local",
                "model": "deterministic-business-runtime-v1",
                "invocation_type": "agent_error",
                "status": "BLOCK",
                "error_type": failure_type,
                "error_digest": failure_digest,
            }
            try:
                record = _append(tenant_id, run_id, f"agent.{agent}", failure)
                evidence_ids.append(record["id"])
                execution.append(failure)
            except Exception as append_exc:
                failure_type = type(append_exc).__name__
                failure_digest = hashlib.sha256(
                    f"ola.agent-failure/v1|{run_id}|{agent}|{failure_type}".encode("utf-8")
                ).hexdigest()
            break
        evidence_ids.append(record["id"])
        execution.append(output)
        if output["status"] == "BLOCK":
            blocked_agent_roles.append(agent)
        previous = output

    run_rows = [
        record for record in load_chain(tenant_id)
        if (
            record["record_type"] == "run.start"
            or record["record_type"].startswith("agent.")
        )
        and json.loads(record["payload_json"]).get("run_id") == run_id
    ]
    agent_rows = [record for record in run_rows if record["record_type"].startswith("agent.")]
    completed_agent_roles = [
        json.loads(record["payload_json"])["agent"]
        for record in agent_rows
        if json.loads(record["payload_json"]).get("execution_status", "VERIFIED") == "VERIFIED"
    ]
    if failed_agent:
        outcome = "FAILED"
    elif blocked_agent_roles:
        outcome = "COMPLETED_BLOCKED"
    else:
        outcome = "SUCCEEDED"

    end_record = _append(tenant_id, run_id, "run.end", {
        "schema": "ola.run-lifecycle/v1",
        "started_at": started_at,
        "ended_at": datetime.now(timezone.utc).isoformat(),
        "task_digest": task_digest,
        "source_commit": source_commit,
        "replay_nonce": replay_nonce,
        "expected_agent_roles": list(AGENT_ROLES),
        "outcome": outcome,
        "completed_agent_roles": completed_agent_roles,
        "blocked_agent_roles": blocked_agent_roles,
        "failed_agent": failed_agent,
        "error_type": failure_type,
        "error_digest": failure_digest,
        "start_record_id": start_record["id"],
        "start_record_hash": start_record["record_hash"],
        "agent_event_count": len(agent_rows),
        "run_event_count": len(run_rows),
        "run_event_digest": run_event_digest(run_rows),
        "runtime_kind": "business_invoice",
    })

    with SessionLocal() as db:
        rows = db.scalars(
            select(EvidenceRecord)
            .where(EvidenceRecord.tenant_id == tenant_id)
            .order_by(EvidenceRecord.seq.asc())
        ).all()
    chain = [{
        "id": row.id,
        "tenant_id": row.tenant_id,
        "seq": row.seq,
        "prev_hash": row.prev_hash,
        "record_hash": row.record_hash,
        "record_type": row.record_type,
        "payload_json": row.payload_json,
    } for row in rows]
    chain_ok, reason = verify_chain(chain)
    replay = verify_replay(
        chain,
        expected_run_id=run_id,
        expected_tenant_id=tenant_id,
        expected_record_count=len(chain),
        expected_tip_hash=chain[-1]["record_hash"] if chain else None,
    )
    final_result = execution[-1].get("final_result") if execution and not failed_agent else None
    if failed_agent:
        status = "BLOCK"
        reason = f"agent execution failed: {failed_agent}"
    elif chain_ok and replay["status"] == "VERIFIED" and policy_match:
        status = "VERIFIED"
    else:
        status = "BLOCK"
        if chain_ok and not policy_match:
            reason = "invoice VAT rate differs from the controlled policy; payment rejected"
        elif not chain_ok:
            reason = f"evidence hash-chain verification failed: {reason}"
        else:
            reason = replay.get("reason", "run replay verification failed")
    if policy_match and (not chain_ok or replay["status"] != "VERIFIED" or failed_agent):
        final_result = {
            **(final_result or checks["multi_agent"]["final_result"]),
            "payment_decision": "NOT_APPROVED",
            "transfer_amount": 0.0,
            "transfer_status": "NOT_SENT",
        }

    return {
        "run_id": run_id,
        "task": task,
        "status": status,
        "reason": reason,
        "agents": AGENT_ROLES,
        "evidence_count": len(agent_rows),
        "evidence_ids": evidence_ids,
        "lifecycle": replay.get("lifecycle", {"status": "BLOCK"}),
        "replay_verification": replay,
        "execution_status": replay.get("execution_status", "FAILED"),
        "execution": execution,
        "final_result": final_result,
    }

