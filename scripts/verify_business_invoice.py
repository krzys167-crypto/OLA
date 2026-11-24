"""Standalone verifier for a six-agent business invoice run.

It deliberately imports nothing from `app`: the point is a second, independent implementation. That also means the
invoice rules (field validation, decimal maths, the controlled VAT policy) are repeated here and must stay identical to
app/business_runtime.py; tests/test_review6_money.py runs both on random invoices and fails on any disagreement.

Exit status: 0 and a JSON proof on stdout when VERIFIED; otherwise 1 and {"status": "BLOCK", "reason": ...} on stderr
(never a traceback, whatever the input)."""
import argparse
import hashlib
import json
import math
import re
import sqlite3
import sys
from decimal import Context, Decimal, ROUND_HALF_UP
from pathlib import Path

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
CONTROLLED_VAT_RATE = 0.21
MAX_NET = 1_000_000_000.0
REQUIRED_FIELDS = ("invoice_id", "supplier", "currency", "net", "vat_rate")
_CURRENCY = re.compile(r"[A-Z]{3}")
_CENT = Decimal("0.01")
_CONTEXT = Context(prec=60)
_CONTROLLED_RATE = Decimal(repr(CONTROLLED_VAT_RATE))


class Block(Exception):
    """The run is not verified; the message is the reason."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def fail(reason):
    raise Block(reason)


def _number(value, field):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        fail(f"invoice {field} must be a JSON number")
    try:
        if not math.isfinite(value):
            fail(f"invoice {field} must be finite")
        return float(value)
    except OverflowError:
        fail(f"invoice {field} is too large")


def validate_invoice(invoice):
    """The same rules as app.business_runtime.validate_invoice: amounts are checked, not coerced. Returns (net, vat_rate)."""
    if not isinstance(invoice, dict):
        fail("invoice must be a JSON object")
    if not set(REQUIRED_FIELDS).issubset(invoice):
        fail("invoice is missing required fields")
    for field in ("invoice_id", "supplier"):
        value = invoice[field]
        if not isinstance(value, str) or not value.strip() or len(value) > 200:
            fail(f"invoice {field} must be a non-empty string of at most 200 characters")
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            fail(f"invoice {field} is not valid UTF-8 text")
    if not isinstance(invoice["currency"], str) or not _CURRENCY.fullmatch(invoice["currency"]):
        fail("invoice currency must be an ISO 4217 style code of three capital letters")
    net = _number(invoice["net"], "net")
    vat_rate = _number(invoice["vat_rate"], "vat_rate")
    if not 0 < net <= MAX_NET:
        fail(f"invoice net must be greater than 0 and at most {MAX_NET:.0f}")
    if round(net, 2) != net:
        fail("invoice net must not have more than two decimal places")
    if not 0 <= vat_rate <= 1:
        fail("invoice vat_rate must be between 0 and 1")
    return net, vat_rate


def money(net, vat_rate):
    """(vat, gross, policy_match), decimal arithmetic rounded half-up to the cent, as the app does it (binary floats give
    round(0.5 * 0.21, 2) == 0.10 where the invoice means 0.11)."""
    try:
        net_d, rate_d = Decimal(repr(net)), Decimal(repr(vat_rate))
        vat = _CONTEXT.multiply(net_d, rate_d).quantize(_CENT, rounding=ROUND_HALF_UP, context=_CONTEXT)
        if vat.is_zero():
            vat = abs(vat)
        gross = _CONTEXT.add(net_d, vat).quantize(_CENT, rounding=ROUND_HALF_UP, context=_CONTEXT)
    except ArithmeticError:
        fail("invoice amounts are outside the supported range")
    return float(vat), float(gross), rate_d == _CONTROLLED_RATE


def _open_read_only(db_path):
    """Read-only, and never creating a file: a mistyped --db path must not leave an empty database behind."""
    try:
        return sqlite3.connect(Path(db_path).resolve().as_uri() + "?mode=ro", uri=True, timeout=30)
    except (sqlite3.Error, OSError, ValueError) as exc:
        fail(f"cannot open the evidence database: {exc}")


def _scan(db_path, tenant_id, run_id):
    """Verify the complete tenant chain, then return the selected run's agent and lifecycle evidence."""
    db = _open_read_only(db_path)
    agent_rows = []
    lifecycle_events = []
    try:
        cursor = db.execute(
            "SELECT id, tenant_id, seq, record_type, payload_json, prev_hash, record_hash "
            "FROM evidence_records WHERE tenant_id=? ORDER BY seq", (tenant_id,))
        expected_prev = GENESIS
        seen_v2 = False
        for expected_seq, row in enumerate(cursor):
            record_id, row_tenant, seq, record_type, payload_json, prev_hash, record_hash = row
            if row_tenant != tenant_id or seq != expected_seq:
                fail("tenant or sequence mismatch")
            if prev_hash != expected_prev:
                fail("hash-chain predecessor mismatch")
            v1 = hashlib.sha256(f"{row_tenant}|{seq}|{prev_hash}|{payload_json}".encode("utf-8")).hexdigest()
            v2 = hashlib.sha256(
                f"ola.chain/2|{row_tenant}|{seq}|{prev_hash}|{len(record_type)}:{record_type}|{payload_json}".encode("utf-8")).hexdigest()
            if record_hash == v2:
                seen_v2 = True
            elif seen_v2 or record_hash != v1:
                fail("hash-chain record hash mismatch")
            expected_prev = record_hash
            if not isinstance(record_type, str) or not (
                record_type in {"run.start", "run.end"} or record_type.startswith("agent.")
            ):
                continue
            try:
                payload = json.loads(payload_json)
            except (TypeError, ValueError, RecursionError):
                fail("run event payload is not valid JSON")
            if not isinstance(payload, dict):
                fail("run event payload must be a JSON object")
            if payload.get("run_id") == run_id:
                record = {
                    "id": record_id,
                    "tenant_id": row_tenant,
                    "seq": seq,
                    "record_type": record_type,
                    "payload_json": payload_json,
                    "prev_hash": prev_hash,
                    "record_hash": record_hash,
                }
                lifecycle_events.append((record, payload))
                if record_type.startswith("agent."):
                    agent_rows.append((record_type, payload))
    except (sqlite3.Error, UnicodeError) as exc:
        fail(f"cannot read the evidence database: {exc}")
    finally:
        db.close()
    return agent_rows, lifecycle_events


def _verify_lifecycle(lifecycle_events, tenant_id, run_id, task, source_commit, policy_match):
    starts = [(record, payload) for record, payload in lifecycle_events if record["record_type"] == "run.start"]
    ends = [(record, payload) for record, payload in lifecycle_events if record["record_type"] == "run.end"]
    if len(starts) != 1 or len(ends) != 1:
        fail("run lifecycle start/end missing or duplicated")
    start_record, start = starts[0]
    end_record, end = ends[0]
    if lifecycle_events[0][0]["record_type"] != "run.start" or lifecycle_events[-1][0]["record_type"] != "run.end":
        fail("run lifecycle ordering mismatch")
    if [record["record_type"] for record, _ in lifecycle_events] != [
        "run.start", *[f"agent.{role}" for role in ROLES], "run.end"
    ]:
        fail("run lifecycle event order mismatch")
    if start.get("schema") != "ola.run-lifecycle/v1" or end.get("schema") != "ola.run-lifecycle/v1":
        fail("run lifecycle schema mismatch")
    if start.get("run_id") != run_id or end.get("run_id") != run_id:
        fail("run lifecycle run id mismatch")
    if start.get("expected_agent_roles") != ROLES or end.get("expected_agent_roles") != ROLES:
        fail("run lifecycle agent roster mismatch")

    expected_outcome = "SUCCEEDED" if policy_match else "COMPLETED_BLOCKED"
    expected_blocked_roles = [] if policy_match else ["self_reflection"]
    if end.get("outcome") != expected_outcome:
        fail("run lifecycle outcome mismatch")
    if end.get("completed_agent_roles") != ROLES:
        fail("run lifecycle completed-agent roster mismatch")
    if end.get("blocked_agent_roles") != expected_blocked_roles or end.get("failed_agent") is not None:
        fail("run lifecycle blocked/failed-agent roster mismatch")
    if end.get("agent_event_count") != len(ROLES):
        fail("run lifecycle agent event count mismatch")
    if end.get("start_record_id") != start_record["id"] or end.get("start_record_hash") != start_record["record_hash"]:
        fail("run lifecycle start anchor mismatch")

    task_digest = hashlib.sha256(task.encode("utf-8")).hexdigest()
    if start.get("task_digest") != task_digest or end.get("task_digest") != task_digest:
        fail("run lifecycle task digest mismatch")
    if not isinstance(source_commit, str) or not source_commit:
        fail("run lifecycle source commit missing")
    nonce = start.get("replay_nonce")
    if not isinstance(nonce, str) or not nonce:
        fail("run lifecycle replay nonce missing")
    if end.get("source_commit") != source_commit or start.get("source_commit") != source_commit:
        fail("run lifecycle source commit mismatch")
    if end.get("replay_nonce") != nonce:
        fail("run lifecycle replay nonce mismatch")

    for index, (record, payload) in enumerate(lifecycle_events[1:-1]):
        role = ROLES[index]
        if payload.get("agent") != role or record["record_type"] != f"agent.{role}":
            fail("run lifecycle agent identity/order mismatch")
        if payload.get("task") != task:
            fail(f"run lifecycle task mismatch for {role}")
        if payload.get("task") is None or hashlib.sha256(payload["task"].encode("utf-8")).hexdigest() != task_digest:
            fail(f"run lifecycle task digest mismatch for {role}")
        if payload.get("source_commit") != source_commit or payload.get("replay_nonce") != nonce:
            fail(f"run lifecycle provenance mismatch for {role}")
        if payload.get("execution_status", "VERIFIED") != "VERIFIED":
            fail(f"run lifecycle invocation did not complete for {role}")

    pre_end = [record for record, _ in lifecycle_events[:-1]]
    if end.get("run_event_count") != len(pre_end):
        fail("run lifecycle event count mismatch")
    projection = [
        {
            "id": record["id"],
            "seq": record["seq"],
            "record_type": record["record_type"],
            "record_hash": record["record_hash"],
        }
        for record in pre_end
    ]
    expected_digest = hashlib.sha256(canonical(projection).encode("utf-8")).hexdigest()
    if end.get("run_event_digest") != expected_digest:
        fail("run lifecycle event digest mismatch")

    try:
        started_at = datetime.fromisoformat(str(start.get("started_at", "")).replace("Z", "+00:00"))
        ended_at = datetime.fromisoformat(str(end.get("ended_at", "")).replace("Z", "+00:00"))
    except ValueError:
        fail("run lifecycle timestamps invalid")
    if started_at.tzinfo is None or ended_at.tzinfo is None or ended_at < started_at:
        fail("run lifecycle timestamps invalid")
    if end.get("started_at") != start.get("started_at"):
        fail("run lifecycle start timestamp mismatch")

    return {
        "status": "VERIFIED",
        "execution_status": "SUCCEEDED" if policy_match else "BLOCKED",
        "outcome": expected_outcome,
        "run_event_count": len(lifecycle_events),
        "run_event_digest": expected_digest,
        "start_record_id": start_record["id"],
        "end_record_id": end_record["id"],
    }


def verify(db_path, tenant_id, run_id, invoice):
    """The proof dict, or Block(reason)."""
    net, vat_rate = validate_invoice(invoice)
    expected_net = net
    expected_vat, expected_gross, policy_match = money(net, vat_rate)     # policy_match False: the payment must be REJECTED
    run_rows, lifecycle_events = _scan(db_path, tenant_id, run_id)
    task = "INVOICE_JSON:" + canonical(invoice)
    lifecycle = _verify_lifecycle(
        lifecycle_events,
        tenant_id,
        run_id,
        task,
        "UNKNOWN" if not lifecycle_events else lifecycle_events[0][1].get("source_commit"),
        policy_match,
    )

    if not run_rows:
        fail("no agent evidence found for this run id")
    if len(run_rows) != len(ROLES):
        fail(f"expected {len(ROLES)} agent evidence records for this run, got {len(run_rows)}")
    if [record_type for record_type, _ in run_rows] != [f"agent.{role}" for role in ROLES]:
        fail("agent evidence order/type mismatch")

    instances = set()
    contexts = set()
    payloads = []
    for index, (_record_type, payload) in enumerate(run_rows):
        payloads.append(payload)
        agent = payload.get("agent")
        if agent != ROLES[index]:
            fail("agent identity/order mismatch")
        if payload.get("task") != task:
            fail("task mismatch")
        expected_status = "VERIFIED" if (policy_match or agent != "self_reflection") else "BLOCK"
        if payload.get("status") != expected_status:
            fail(f"agent status is not {expected_status}")
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

    if len(instances) != len(ROLES) or len(contexts) != len(ROLES):
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
        "payment_decision": "APPROVE_FOR_TEST_TRANSFER" if policy_match else "REJECT_POLICY_MISMATCH",
        "transfer_amount": expected_gross if policy_match else 0.0,
        "transfer_status": "READY_NOT_SENT" if policy_match else "NOT_SENT",
    }
    if final != expected_final:
        fail("final business result mismatch")
    if not policy_match:
        fail("invoice VAT rate differs from the controlled policy: the run correctly rejected the payment, "
             "so the invoice is NOT approved")

    return {
        "status": "VERIFIED",
        "run_id": run_id,
        "invoice_id": invoice["invoice_id"],
        "net": expected_net,
        "vat": expected_vat,
        "gross": expected_gross,
        "evidence_count": len(run_rows),
        "lifecycle": lifecycle,
        "independent_instance_count": len(instances),
        "independent_context_count": len(contexts),
        "payment_decision": final["payment_decision"],
        "transfer_status": final["transfer_status"],
        "reason": "standalone verifier independently recomputed invoice arithmetic, policy, roles, capabilities, invocation metadata, identities, final result, run lifecycle digest and full tenant hash-chain",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--db", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--invoice-json", required=True)
    args = parser.parse_args(argv)
    try:
        try:
            invoice = json.loads(args.invoice_json)
        except (ValueError, RecursionError) as exc:
            fail(f"--invoice-json is not valid JSON: {exc}")
        proof = verify(args.db, args.tenant_id, args.run_id, invoice)
    except Block as exc:
        print(json.dumps({"status": "BLOCK", "reason": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1
    except Exception as exc:                  # a verifier answers VERIFIED or BLOCK, never a traceback
        print(json.dumps({"status": "BLOCK", "reason": f"verifier error: {exc.__class__.__name__}: {exc}"},
                         sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(proof, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
