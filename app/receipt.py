"""A receipt a paying customer can check on their own machine.

The tenant's evidence chain is hash-linked, so to re-check one session the whole chain up to that session's last record is
needed; that prefix is the customer's own tenant data. `build_receipt` returns it together with the delivered result and
the claims `revenue_proof` made, in a self-contained JSON bundle. `tools/verify_receipt.py` (standard library only, no
OLA code) recomputes the hashes and the cross-references from the bundle alone.

What a receipt can show: the chain is intact, the records for the session point at each other, and the delivered result
is the one whose digest was recorded. What it cannot show: that Stripe really took the money (the webhook table is not in
the bundle), or that the operator did not write the whole chain afresh. The second needs the head hash to be published
or timestamped outside OLA (`anchor` is empty until that is done), and the receipt says so."""
import json

from sqlalchemy import select

from . import pipeline_bridge
from .database import SessionLocal
from .models import StripeEvent
from .revenue_proof import NOT_OBSERVABLE, revenue_proof

FORMAT = "ola.receipt/1"
SESSION_KEYS = {"stripe.payment_confirmed": "checkout_session_id", "stripe.ola_execution_completed": "checkout_session_id",
                "revenue.result_served": "session_id"}
LIMITS = (
    "Stripe's own record is not in this bundle: only the operator's chain says the payment happened.",
    "A chain that is internally consistent can still have been written afresh by the operator; publish or timestamp "
    "head_hash outside OLA to rule that out (anchor is empty until then).",
    "Delivery means the server handed the result over; that the customer read it is not observable.",
)


def build_receipt(tenant_id: str, session_id: str):
    """The receipt for one session of this tenant, or None when the session is not a paid session on a valid chain."""
    proof = revenue_proof(tenant_id)
    claims = next((item for item in proof["sessions"] if item["session_id"] == session_id), None)
    if claims is None:
        return None
    chain = pipeline_bridge.load_chain(tenant_id)
    last = -1
    for row in chain:
        key = SESSION_KEYS.get(row["record_type"])
        try:
            payload = json.loads(row["payload_json"]) if key else None
        except ValueError:
            payload = None
        if isinstance(payload, dict) and payload.get(key) == session_id:
            last = row["seq"]
    prefix = chain[: last + 1]
    with SessionLocal() as db:
        event = db.scalar(select(StripeEvent).where(StripeEvent.checkout_session_id == session_id))
    try:
        result = json.loads(event.result_json) if event is not None else None
    except ValueError:
        result = None
    return {
        "format": FORMAT,
        "tenant_id": tenant_id,
        "session_id": session_id,
        "head_hash": prefix[-1]["record_hash"],
        "chain": prefix,
        "result": result,
        "claims": {"status": claims["status"], "payment_mode": claims["payment_mode"], "steps": claims["steps"],
                   "missing": claims["missing"]},
        "anchor": None,
        "limits": list(LIMITS),
        "not_observable": [dict(item) for item in NOT_OBSERVABLE],
    }
