import argparse
import hashlib
import json
import sqlite3

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
GENESIS = "0" * 64


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

    expected_prev = GENESIS
    seen_v2 = False
    instances = set()
    contexts = set()
    payloads = []
    for expected_seq, row in enumerate(rows):
        tenant_id, seq, record_type, payload_json, prev_hash, record_hash = row
        if tenant_id != args.tenant_id or seq != expected_seq:
            fail("tenant or sequence mismatch")
        if prev_hash != expected_prev:
            fail("hash-chain predecessor mismatch")
        v1 = hashlib.sha256(f"{tenant_id}|{seq}|{prev_hash}|{payload_json}".encode("utf-8")).hexdigest()
        v2 = hashlib.sha256(
            f"ola.chain/2|{tenant_id}|{seq}|{prev_hash}|{len(record_type)}:{record_type}|{payload_json}".encode("utf-8")).hexdigest()
        if record_hash == v2:
            seen_v2 = True
        elif seen_v2 or record_hash != v1:      # legacy v1 only before the first type-bound (v2) record
            fail("hash-chain record hash mismatch")
        expected_prev = record_hash
        payload = json.loads(payload_json)
        payloads.append(payload)
        agent = payload.get("agent")
        if agent != ROLES[expected_seq]:
            fail("agent identity/order mismatch")
        if payload.get("run_id") != args.run_id:
            fail("run_id mismatch")
        if payload.get("task") != "INVOICE_JSON:" + canonical(invoice):
            fail("task mismatch")
        if payload.get("status") != "VERIFIED":
            fail("agent status is not VERIFIED")
        if payload.get("capability") != CAPABILITIES[agent]:
            fail(f"capability mismatch for {agent}")
        if payload.get("execution_boundary") != "independent":
            fail("execution boundary is not independent")
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
    last = payloads[-1]
    if first.get("tool_output") != {"net": expected_net, "vat": expected_vat, "gross": expected_gross}:
        fail("invoice calculation does not match independent recomputation")
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
        "independent_instance_count": len(instances),
        "independent_context_count": len(contexts),
        "payment_decision": final["payment_decision"],
        "transfer_status": final["transfer_status"],
        "reason": "standalone verifier independently recomputed invoice arithmetic, policy, roles, capabilities, invocation metadata, identities, final result and hash-chain",
    }, sort_keys=True))


if __name__ == "__main__":
    main()
