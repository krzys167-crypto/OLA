import argparse
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.igor_evidence_verifier import trusted_record, verify_chain as verify_evidence_chain

ROLES = ["codeact", "react", "agentic_rag", "mcp_tool_use", "self_reflection", "multi_agent"]
CAPABILITIES = {
    "codeact": "validated_invoice_math",
    "react": "reason_act_observe",
    "agentic_rag": "retrieved_controlled_policy",
    "mcp_tool_use": "invoked_tool",
    "self_reflection": "checked_previous_output",
    "multi_agent": "aggregated_agent_outputs",
}
EXPECTED_INVOCATION = {
    "provider": "local",
    "model": "deterministic-business-runtime-v1",
    "invocation_type": "local_deterministic_model",
}
CONTROLLED_VAT_RATE = 0.21


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def fail(reason):
    raise SystemExit(json.dumps({"status": "BLOCK", "reason": reason}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--invoice-json", required=True)
    args = parser.parse_args()

    invoice = json.loads(args.invoice_json)
    expected_net = round(float(invoice["net"]), 2)
    expected_vat = round(expected_net * float(invoice["vat_rate"]), 2)
    expected_gross = round(expected_net + expected_vat, 2)
    if float(invoice["vat_rate"]) != CONTROLLED_VAT_RATE:
        fail("controlled VAT policy mismatch; transfer authorization is blocked")

    db = sqlite3.connect(args.db)
    rows = db.execute(
        "SELECT tenant_id, seq, record_type, payload_json, prev_hash, record_hash "
        "FROM evidence_records WHERE tenant_id=? ORDER BY seq",
        (args.tenant_id,),
    ).fetchall()
    db.close()

    if len(rows) != 6:
        fail(f"expected 6 evidence records, got {len(rows)}")

    expected_types = [f"agent.{role}" for role in ROLES]
    if [row[2] for row in rows] != expected_types:
        fail("agent evidence order/type mismatch")

    records = [{
        "tenant_id": row[0], "seq": row[1], "record_type": row[2],
        "payload_json": row[3], "prev_hash": row[4], "record_hash": row[5],
    } for row in rows]
    chain_ok, chain_reason = verify_evidence_chain(records)
    if not chain_ok:
        fail(chain_reason)

    instances = set()
    contexts = set()
    payloads = []
    for expected_seq, row in enumerate(rows):
        tenant_id, seq, record_type, payload_json, prev_hash, record_hash = row
        if tenant_id != args.tenant_id or seq != expected_seq:
            fail("tenant or sequence mismatch")
        record = {
            "tenant_id": tenant_id, "seq": seq, "record_type": record_type,
            "payload_json": payload_json, "prev_hash": prev_hash, "record_hash": record_hash,
        }
        if not trusted_record(record):
            fail("legacy or unauthenticated agent evidence")
        payload = json.loads(payload_json)
        payloads.append(payload)
        agent = payload.get("agent")
        if agent != ROLES[expected_seq]:
            fail("agent identity/order mismatch")
        if payload.get("run_id") != args.run_id:
            fail("run_id mismatch")
        if payload.get("task") != "INVOICE_JSON:" + canonical(invoice):
            fail("task mismatch")
        if payload.get("status") != "RECORDED":
            fail("agent evidence is not producer-recorded")
        if payload.get("capability") != CAPABILITIES[agent]:
            fail(f"capability mismatch for {agent}")
        if payload.get("execution_boundary") != "in_process":
            fail("unexpected agent execution boundary")
        invocation = {
            "provider": payload.get("provider"),
            "model": payload.get("model"),
            "invocation_type": payload.get("invocation_type"),
        }
        if invocation != EXPECTED_INVOCATION:
            fail(f"invocation metadata mismatch for {agent}")
        instances.add(payload.get("agent_instance_id"))
        contexts.add(payload.get("context_digest"))

    if len(instances) != 6 or len(contexts) != 6:
        fail("agent identities or contexts are not unique")

    first = payloads[0]
    policy = payloads[2]
    reflection = payloads[4]
    last = payloads[-1]
    if first.get("tool_output") != {"net": expected_net, "vat": expected_vat, "gross": expected_gross}:
        fail("invoice calculation does not match independent recomputation")
    if policy.get("tool_output") != {"policy": "TEST-BE-VAT", "vat_rate": CONTROLLED_VAT_RATE}:
        fail("controlled VAT policy evidence mismatch")
    if reflection.get("tool_output") != "PASS":
        fail("self-reflection did not pass the controlled VAT policy check")
    final = last.get("final_result")
    expected_final = {
        "invoice_id": invoice["invoice_id"],
        "supplier": invoice["supplier"],
        "currency": invoice["currency"],
        "net": expected_net,
        "vat": expected_vat,
        "gross": expected_gross,
        "payment_decision": "APPROVE_FOR_TEST_TRANSFER",
        "transfer_amount": expected_gross,
        "transfer_status": "READY_NOT_SENT",
    }
    if final != expected_final:
        fail("final business result mismatch")

    print(json.dumps({
        "status": "VERIFIED",
        "run_id": args.run_id,
        "invoice_id": invoice["invoice_id"],
        "net": expected_net,
        "vat": expected_vat,
        "gross": expected_gross,
        "evidence_count": 6,
        "agent_instance_count": len(instances),
        "unique_context_count": len(contexts),
        "execution_boundary": "in_process",
        "verifier_boundary": "separate_process",
        "verification_scope": [
            "tenant_evidence_hash_chain_integrity",
            "record_producer_binding",
            "invoice_arithmetic_recomputed",
            "controlled_policy_match",
            "final_business_result_match",
            "unique_agent_instance_and_context_labels",
        ],
        "not_established": [
            "isolated_or_independent_agent_processes",
            "real_llm_invocation",
            "live_payment_or_transfer_execution",
        ],
        "payment_decision": final["payment_decision"],
        "transfer_status": final["transfer_status"],
        "reason": "separate-process verifier independently recomputed invoice arithmetic, policy, roles, capabilities, invocation metadata, result and hash chain; agent process isolation is not claimed",
    }, sort_keys=True))


if __name__ == "__main__":
    main()
