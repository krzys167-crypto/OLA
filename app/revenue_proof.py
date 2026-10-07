"""What the evidence chain can prove about a paying customer, and what it cannot.

docs/revenue-marketing-flow.md keeps the status NOT PROVEN until a live payment has been observed end to end. This
module turns that sentence into a computation. It reads records only (the tenant's hash chain and the stripe_events
table), never calls Stripe, reads no configuration flag and trusts no counter: a flag can be set without a customer.

A paid session is PROVEN when all six steps hold. A step that is missing, unparsable or contradictory is a failed
step, never a pass:

  LIVE_PAYMENT      the payment evidence says `livemode: true` (Stripe's own flag, recorded by the webhook; a payment
                    recorded before the flag existed, or without it, is mode UNKNOWN and does not count)
  OBSERVED_WEBHOOK  the webhook state machine's row for the session is COMPLETED and points at that very evidence and run
  RUN_PERFORMED     the run really computed something (`computation: PERFORMED`); a run that computed nothing is not work
  RUN_VERIFIED      the runtime's own verdict is VERIFIED (hash chain, independent agent identities, computed result).
                    This is NOT an independent judge model: none is part of the paid path
  EVIDENCE_BOUND    payment evidence, execution evidence and the webhook row reference each other (event id, session
                    id, evidence id, run id)
  RESULT_SERVED     `revenue.result_served` exists for the session and run, and its digest is the digest of the result
                    the webhook stored

What no record can show is listed under `not_observable`, so that "PROVEN" is never read as more than it is.

The chain is verified first. If it does not verify, no record in it is trusted and nothing is PROVEN."""
import hashlib
import json

from sqlalchemy import select

from . import pipeline_bridge
from .database import SessionLocal
from .hashchain import canonical_json, verify_chain
from .models import StripeEvent

STEPS = ("LIVE_PAYMENT", "OBSERVED_WEBHOOK", "RUN_PERFORMED", "RUN_VERIFIED", "EVIDENCE_BOUND", "RESULT_SERVED")

NOT_OBSERVABLE = (
    {"step": "PUBLIC_HTTPS_WEBHOOK",
     "reason": "a signed delivery shows that Stripe reached the endpoint; whether it is a public HTTPS address is not "
               "visible to the application. The owner confirms the endpoint URL in the Stripe dashboard."},
    {"step": "CUSTOMER_RECEIPT",
     "reason": "RESULT_SERVED means the server handed the result to whoever presented the session id; that the customer "
               "received or read it cannot be observed."},
    {"step": "INDEPENDENT_JUDGE",
     "reason": "the paid run is verified by the runtime itself; no separate judge model is part of the paid path, so "
               "this proof does not claim one."},
)

_RECORD_KEYS = {
    "stripe.payment_confirmed": "checkout_session_id",
    "stripe.ola_execution_completed": "checkout_session_id",
    "revenue.result_served": "session_id",
}


def _payload(row: dict):
    try:
        value = json.loads(row["payload_json"])
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _text(value):
    return value if isinstance(value, str) and value else None


def _mode(payment: dict) -> str:
    live = payment.get("livemode")
    if live is True:
        return "LIVE"
    if live is False:
        return "TEST"
    return "UNKNOWN"


def _digest(result: dict) -> str:
    return hashlib.sha256(canonical_json(result).encode("utf-8")).hexdigest()


def _steps(session_id, payment_row_id, payment, execution, served_rows, webhook_row) -> dict:
    exec_payload = execution[1] if execution else {}
    run_id = _text(exec_payload.get("ola_run_id"))
    event_id = _text(payment.get("stripe_event_id"))
    result = None
    if webhook_row is not None:
        try:
            parsed = json.loads(webhook_row.result_json)
        except (TypeError, ValueError):
            parsed = None
        result = parsed if isinstance(parsed, dict) else None
    observed = bool(
        webhook_row is not None and execution is not None and run_id
        and webhook_row.status == "COMPLETED"
        and webhook_row.payment_evidence_id == payment_row_id
        and webhook_row.run_id == run_id)
    bound = bool(
        observed and event_id and result is not None
        and exec_payload.get("stripe_event_id") == event_id
        and webhook_row.event_id == event_id
        and result.get("checkout_session_id") == session_id
        and result.get("payment_evidence_id") == payment_row_id
        and result.get("ola_run_id") == run_id)
    served = bool(
        bound and any(row.get("run_id") == run_id and row.get("result_sha256") == _digest(result)
                      for row in served_rows))
    return {
        "LIVE_PAYMENT": _mode(payment) == "LIVE",
        "OBSERVED_WEBHOOK": observed,
        "RUN_PERFORMED": execution is not None and exec_payload.get("computation") == "PERFORMED",
        "RUN_VERIFIED": execution is not None and exec_payload.get("ola_status") == "VERIFIED",
        "EVIDENCE_BOUND": bound,
        "RESULT_SERVED": served,
    }


def revenue_proof(tenant_id: str) -> dict:
    chain = pipeline_bridge.load_chain(tenant_id)
    chain_ok, chain_reason = verify_chain(chain)
    report = {
        "status": "NOT_PROVEN",
        "missing": [],
        "chain": {"valid": chain_ok, "reason": chain_reason, "records": len(chain)},
        "counts": {"paid_sessions": 0, "live": 0, "test": 0, "mode_unknown": 0, "proven": 0},
        "sessions": [],
        "not_observable": [dict(item) for item in NOT_OBSERVABLE],
    }
    if not chain_ok:
        report["missing"] = ["EVIDENCE_CHAIN_VALID"]
        return report

    buckets = {kind: {} for kind in _RECORD_KEYS}
    for row in chain:
        key = _RECORD_KEYS.get(row["record_type"])
        payload = _payload(row) if key else None
        session_id = _text(payload.get(key)) if payload else None
        if session_id:
            buckets[row["record_type"]].setdefault(session_id, []).append((row["id"], payload))

    payments = buckets["stripe.payment_confirmed"]
    webhook_rows = {}
    if payments:
        with SessionLocal() as db:
            for row in db.scalars(select(StripeEvent).where(StripeEvent.checkout_session_id.in_(list(payments)))):
                webhook_rows[row.checkout_session_id] = row

    for session_id, records in payments.items():
        payment_row_id, payment = records[0]               # the first payment record of a session is the payment
        execution = next(((row_id, p) for row_id, p in buckets["stripe.ola_execution_completed"].get(session_id, [])
                          if p.get("payment_evidence_id") == payment_row_id), None)
        served_rows = [p for _, p in buckets["revenue.result_served"].get(session_id, [])]
        steps = _steps(session_id, payment_row_id, payment, execution, served_rows, webhook_rows.get(session_id))
        missing = [name for name in STEPS if not steps[name]]
        mode = _mode(payment)
        report["sessions"].append({"session_id": session_id, "payment_mode": mode, "steps": steps,
                                   "status": "NOT_PROVEN" if missing else "PROVEN", "missing": missing})
        counts = report["counts"]
        counts["paid_sessions"] += 1
        counts[{"LIVE": "live", "TEST": "test", "UNKNOWN": "mode_unknown"}[mode]] += 1
        counts["proven"] += 0 if missing else 1

    if report["counts"]["proven"]:
        report["status"] = "PROVEN"
    elif not report["sessions"]:
        report["missing"] = ["PAID_SESSION"]
    else:                                                  # what is left to observe on the session that is closest
        report["missing"] = min((item["missing"] for item in report["sessions"]), key=len)
    return report
