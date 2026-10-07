#!/usr/bin/env python3
"""Check an OLA receipt (ola.receipt/1) offline. Standard library only; it does not import any OLA code.

  verify_receipt.py receipt.json [--head <hash published or timestamped elsewhere>]

Prints a JSON verdict. Exit 0 = CONSISTENT, 1 = INCONSISTENT, 2 = unreadable. CONSISTENT means: the hash chain is intact,
the payment, execution and served records for the session point at each other, and the delivered result matches the
recorded digest. It does NOT mean Stripe took the money or that the operator did not write the chain afresh: unless
--head is given and matches, the chain is only self-consistent."""
import argparse
import hashlib
import json
import sys

GENESIS = "0" * 64
HASH_V2 = "ola.chain/2"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def record_hash(tenant_id, seq, prev, payload_json, record_type=None):
    if record_type is None:
        material = f"{tenant_id}|{seq}|{prev}|{payload_json}"
    else:
        material = f"{HASH_V2}|{tenant_id}|{seq}|{prev}|{len(record_type)}:{record_type}|{payload_json}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def chain_ok(records):
    prev, seq, seen_v2 = GENESIS, 0, False
    for row in records:
        if row.get("seq") != seq or row.get("prev_hash") != prev:
            return False, f"sequence or predecessor mismatch at seq {seq}"
        rtype = row.get("record_type")
        v2 = record_hash(row["tenant_id"], seq, prev, row["payload_json"], rtype) if isinstance(rtype, str) else None
        if v2 is not None and row.get("record_hash") == v2:
            seen_v2 = True
        elif seen_v2 or row.get("record_hash") != record_hash(row["tenant_id"], seq, prev, row["payload_json"]):
            return False, f"record hash mismatch at seq {seq}"
        prev, seq = row["record_hash"], seq + 1
    return True, "ok"


def _payloads(records, rtype, key, session_id):
    out = []
    for row in records:
        if row.get("record_type") != rtype:
            continue
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, ValueError):
            continue
        if isinstance(payload, dict) and payload.get(key) == session_id:
            out.append((row["id"], payload))
    return out


def verify(bundle, head=None):
    checks, limits = {}, list(bundle.get("limits") or [])
    if bundle.get("format") != "ola.receipt/1":
        raise ValueError("not an ola.receipt/1 bundle")
    records, session_id = bundle["chain"], bundle["session_id"]
    checks["chain_intact"], reason = chain_ok(records)
    checks["chain_tenant_consistent"] = all(r.get("tenant_id") == bundle["tenant_id"] for r in records)
    checks["head_hash_is_last_record"] = bool(records) and bundle.get("head_hash") == records[-1]["record_hash"]
    payments = _payloads(records, "stripe.payment_confirmed", "checkout_session_id", session_id)
    execs = _payloads(records, "stripe.ola_execution_completed", "checkout_session_id", session_id)
    served = _payloads(records, "revenue.result_served", "session_id", session_id)
    pay_id, pay = payments[0] if payments else (None, {})
    execution = next((p for _, p in execs if p.get("payment_evidence_id") == pay_id), {})
    result = bundle.get("result")
    checks["payment_record_present"] = bool(payments)
    checks["execution_points_at_payment"] = bool(execution)
    checks["execution_performed"] = execution.get("computation") == "PERFORMED"
    run_id = execution.get("ola_run_id")
    digest = hashlib.sha256(canonical(result).encode("utf-8")).hexdigest() if isinstance(result, dict) else None
    checks["result_bound_to_session"] = (isinstance(result, dict) and result.get("checkout_session_id") == session_id
                                         and result.get("payment_evidence_id") == pay_id and result.get("ola_run_id") == run_id
                                         and bool(run_id))
    checks["served_digest_matches_result"] = bool(digest) and any(
        p.get("run_id") == run_id and p.get("result_sha256") == digest for _, p in served)
    mode = "LIVE" if pay.get("livemode") is True else "TEST" if pay.get("livemode") is False else "UNKNOWN"
    anchored = None
    if head is not None:
        anchored = head.strip().lower() == str(bundle.get("head_hash")).lower()
        checks["head_matches_the_given_hash"] = anchored
    else:
        limits.append("No --head given: the chain is only self-consistent, not anchored outside OLA.")
    verdict = "CONSISTENT" if all(checks.values()) else "INCONSISTENT"
    return {"verdict": verdict, "payment_mode_recorded": mode, "anchored": anchored, "checks": checks,
            "chain_reason": reason, "limits": limits}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("receipt")
    parser.add_argument("--head", default=None)
    args = parser.parse_args(argv)
    try:
        with open(args.receipt, encoding="utf-8") as handle:
            bundle = json.load(handle)
        report = verify(bundle, args.head)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"verdict": "UNREADABLE", "error": str(error)}))
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["verdict"] == "CONSISTENT" else 1


if __name__ == "__main__":
    sys.exit(main())
