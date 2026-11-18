import hashlib
import hmac
import json
import logging
import os
import re
import time
import uuid

from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from .agent_runtime import run_agent_task
from .database import SessionLocal
from .hashchain import GENESIS_HASH, canonical_json, compute_record_hash
from .models import EvidenceRecord, StripeEvent, Tenant

log = logging.getLogger("ola.stripe")

STRIPE_SIGNATURE_TOLERANCE_SECONDS = 300
OLA_OFFER = "ola-execution-audit"
OLA_PRODUCT = "OLA Execution Audit"
# the two events that can start a paid run; a run still requires payment_status == "paid" in the session
PAID_EVENTS = {"checkout.session.completed", "checkout.session.async_payment_succeeded"}
MAX_ID_CHARS = 255          # the stripe_events.event_id / checkout_session_id columns
MAX_TASK_CHARS = 8000       # same bound as /agent-run (Stripe itself caps a metadata value at 500)
DEFAULT_LEASE_SECONDS = 900.0
_TIMESTAMP = re.compile(r"[0-9]{1,15}")


def verify_stripe_signature(payload: bytes, signature_header: str, secret: str, now: int | None = None) -> bool:
    if not signature_header or not secret:
        return False
    timestamp = None
    signatures = []
    for item in signature_header.split(","):
        key, _, value = item.partition("=")
        if key == "t":
            if not _TIMESTAMP.fullmatch(value):      # plain ASCII digits only (no sign, space, underscore, other scripts)
                return False
            timestamp = int(value)
        elif key == "v1" and value:
            signatures.append(value)
    if timestamp is None or not signatures:
        return False
    current = int(time.time()) if now is None else now
    if abs(current - timestamp) > STRIPE_SIGNATURE_TOLERANCE_SECONDS:
        return False
    signed = f"{timestamp}.".encode("utf-8") + payload
    expected = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest().encode("ascii")
    # compared as bytes: compare_digest(str, str) raises TypeError on a non-ASCII candidate (an unauthenticated 500)
    return any(hmac.compare_digest(expected, signature.encode("utf-8", "replace")) for signature in signatures)


def _append_evidence(tenant_id: str, record_type: str, payload: dict) -> str:
    # same chain and hashing (v2, type-bound), through the retrying append (lazy import: see business_runtime)
    from .pipeline_bridge import append_evidence
    return append_evidence(tenant_id, record_type, payload, attempts=96)["id"]


def _text(value, what: str, limit: int = MAX_ID_CHARS) -> str:
    """A non-empty string that fits its column and survives the database and the evidence chain: a lone surrogate
    (JSON \\ud800) or an over-long value used to reach sqlite / sha256 and come back as a 500."""
    if not isinstance(value, str) or not value or len(value) > limit:
        raise HTTPException(status_code=400, detail=f"Stripe {what} must be a non-empty string of at most {limit} characters")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise HTTPException(status_code=400, detail=f"Stripe {what} is not valid UTF-8 text") from None
    return value


def _dict(value, what: str) -> dict:
    """Stripe payload sections must be JSON objects; anything else is a 400, never an AttributeError (500)."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise HTTPException(status_code=400, detail=f"Stripe {what} must be an object")
    return value


def _metadata_task(session: dict) -> str | None:
    metadata = _dict(session.get("metadata"), "metadata")
    task = metadata.get("task")
    if isinstance(task, str) and task.strip():
        return task.strip()
    fields = session.get("custom_fields") or []
    if not isinstance(fields, list):
        raise HTTPException(status_code=400, detail="Stripe custom_fields must be a list")
    for field in fields:
        if isinstance(field, dict) and field.get("key") == "audit_task":
            value = _dict(field.get("text"), "custom field text").get("value")
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def _validate_checkout(session: dict, *, allow_unpaid: bool = False) -> str:
    """Validates the session and returns the audit task. `allow_unpaid` is only for `checkout.session.completed`:
    with an asynchronous payment method (SEPA debit, bank transfer) Stripe sends it with payment_status "unpaid"
    and confirms the money later in `checkout.session.async_payment_succeeded`."""
    metadata = _dict(session.get("metadata"), "metadata")
    if metadata.get("offer") != OLA_OFFER:
        raise HTTPException(status_code=400, detail="unsupported Stripe offer")
    product = metadata.get("product")
    if product is not None and product != OLA_PRODUCT:  # `in {set}` would raise TypeError on a list/dict (500)
        raise HTTPException(status_code=400, detail="unsupported Stripe product")
    status = session.get("status")
    payment_status = session.get("payment_status")
    paid_enough = payment_status == "paid" or (allow_unpaid and payment_status == "unpaid")
    # "complete" has to be SAID: Stripe always sends a status, so a session without one is not confirmed (it used to pass
    # because only a value other than "complete" was refused)
    if not paid_enough or status != "complete":
        raise HTTPException(status_code=400, detail="payment is not confirmed")
    # Stripe's amount_total is an integer number of cents; 9900.0 == 9900 in Python, so the type is checked too
    amount = session.get("amount_total")
    if session.get("currency") != "eur" or type(amount) is not int or amount != 9900:
        raise HTTPException(status_code=400, detail="unexpected payment amount or currency")
    line_items = session.get("line_items") or {}
    if not isinstance(line_items, dict):
        raise HTTPException(status_code=400, detail="Stripe line_items must be an object")
    data = line_items.get("data", [])
    if not isinstance(data, list):
        raise HTTPException(status_code=400, detail="Stripe line_items.data must be a list")
    price_ids = set()
    for item in data:
        if not isinstance(item, dict):
            raise HTTPException(status_code=400, detail="Stripe line item must be an object")
        price = item.get("price")
        price_id = price.get("id") if isinstance(price, dict) else None
        if isinstance(price_id, str):
            price_ids.add(price_id)
    expected_price = os.getenv("OLA_STRIPE_PRICE_ID")
    if price_ids and expected_price and expected_price not in price_ids:
        raise HTTPException(status_code=400, detail="unexpected Stripe price")
    task = _metadata_task(session)
    if not task:
        raise HTTPException(status_code=400, detail="audit task is required")
    return _text(task, "audit task", MAX_TASK_CHARS)


def checkout_task(session: dict) -> str | None:
    """The audit task of a session exactly as the webhook reads it (stripped metadata.task, else the audit_task custom
    field); None when there is none. /payment-success uses this so both sides compare the same string."""
    try:
        return _metadata_task(session)
    except HTTPException:
        return None


def checkout_tenant(session: dict) -> str | None:
    """The tenant a session belongs to (metadata.tenant_id, else OLA_STRIPE_TENANT_ID), as the webhook resolves it."""
    metadata = session.get("metadata")
    tenant_id = (metadata.get("tenant_id") if isinstance(metadata, dict) else None) or os.getenv("OLA_STRIPE_TENANT_ID", "")
    return tenant_id if isinstance(tenant_id, str) and tenant_id else None


def session_is_for_offer(session: dict) -> bool:
    """The session sells this offer (the product name is optional), whatever its payment state."""
    metadata = session.get("metadata")
    if not isinstance(metadata, dict) or metadata.get("offer") != OLA_OFFER:
        return False
    product = metadata.get("product")
    return product is None or product == OLA_PRODUCT


def session_paid_for_offer(session: dict) -> bool:
    """paid + complete + this offer, the acceptance rule the webhook applies; the amount and currency are checked by
    the webhook, which is the only place that starts a run."""
    return session_is_for_offer(session) and session.get("payment_status") == "paid" and session.get("status") == "complete"


def _reject_constant(name):
    raise ValueError(f"non-finite JSON number {name}")


def _parse_event(payload: bytes) -> dict:
    """UTF-8 JSON object or a 400: invalid UTF-8, deep nesting (RecursionError) and NaN are client errors, not 500s."""
    try:
        event = json.loads(payload.decode("utf-8"), parse_constant=_reject_constant)
    except (ValueError, RecursionError, MemoryError) as exc:          # UnicodeDecodeError / JSONDecodeError are ValueErrors
        raise HTTPException(status_code=400, detail="invalid Stripe JSON") from exc
    if not isinstance(event, dict):
        raise HTTPException(status_code=400, detail="Stripe event must be a JSON object")
    return event


# --------------------------------------------------------------------------- claim / lease / fencing
class _LeaseLost(Exception):
    """This worker's claim was reclaimed by another one (its lease ran out): stop, write nothing more."""


def _lease_seconds() -> float:
    try:
        value = float(os.getenv("OLA_STRIPE_LEASE_S", str(DEFAULT_LEASE_SECONDS)))
    except ValueError:
        return DEFAULT_LEASE_SECONDS
    return value if value >= 0 else DEFAULT_LEASE_SECONDS


def _pause(seconds: float) -> None:
    time.sleep(seconds)


def _busy() -> HTTPException:
    return HTTPException(status_code=409, detail="Stripe event is already being processed")


def _claim(event_id: str, session_id: str, task: str):
    """One row per checkout session decides who may run the paid task:
    COMPLETED (same event, or another event id of the same session) -> ("cached", result), no run;
    PROCESSING with a live lease -> 409; FAILED, or PROCESSING whose lease expired -> claimed by compare-and-set;
    no row -> inserted (a concurrent insert hits a unique index -> 409). `claimed_at` is the fencing token: every later
    write of this worker is conditional on it, so a worker that lost its lease cannot overwrite the new owner."""
    with SessionLocal() as db:
        row = db.scalar(select(StripeEvent).where(StripeEvent.event_id == event_id))
        if row is not None and row.checkout_session_id not in (None, session_id):
            raise HTTPException(status_code=409, detail="Stripe event id is bound to a different checkout session")
        if row is None or row.checkout_session_id is None:
            # the row that owns the session decides (a row written before the migration may not know its session yet)
            owner = db.scalar(select(StripeEvent).where(StripeEvent.checkout_session_id == session_id))
            row = owner if owner is not None else row
        if row is None:
            token = time.time()
            db.add(StripeEvent(id=str(uuid.uuid4()), event_id=event_id, status="PROCESSING", task=task,
                               claimed_at=token, checkout_session_id=session_id))
            try:
                db.commit()
            except IntegrityError:
                db.rollback()
                raise _busy() from None
            return "claimed", {"row_event_id": event_id, "token": token, "retry": False,
                               "payment_evidence_id": None, "runtime": None}
        if row.status == "COMPLETED" and row.result_json:
            return "cached", json.loads(row.result_json)
        row_pk, status, claimed_at = row.id, row.status, row.claimed_at
        row_event_id, payment_evidence_id, runtime_json = row.event_id, row.payment_evidence_id, row.runtime_json
        now = time.time()
        if status == "PROCESSING" and claimed_at is None:
            # no lease clock (written by older code): start it now; the row is in flight until the lease runs out
            db.execute(update(StripeEvent).where(StripeEvent.id == row_pk, StripeEvent.status == "PROCESSING",
                                                 StripeEvent.claimed_at.is_(None)).values(claimed_at=now))
            db.commit()
            raise _busy()
        if status == "PROCESSING" and now - claimed_at <= _lease_seconds():
            raise _busy()
        if status not in ("FAILED", "PROCESSING"):
            raise _busy()
        token = now if claimed_at is None or now > claimed_at else claimed_at + 1e-6
        where = [StripeEvent.id == row_pk, StripeEvent.status == status]
        if status == "PROCESSING":
            where.append(StripeEvent.claimed_at == claimed_at)
        try:
            claimed = db.execute(update(StripeEvent).where(*where).values(
                status="PROCESSING", task=task, claimed_at=token, checkout_session_id=session_id))
            db.commit()
        except IntegrityError:
            db.rollback()
            raise _busy() from None
        if claimed.rowcount != 1:
            raise _busy()
    return "claimed", {"row_event_id": row_event_id, "token": token, "retry": True,
                       "payment_evidence_id": payment_evidence_id, "runtime": _load_runtime(runtime_json)}


def _recorded(tenant_id: str, record_type: str, session_id: str) -> str | None:
    """The id of the evidence record of this type already written for this checkout session. A crash between the
    append and the persisting of its id leaves one the row does not know about; a retry must reuse it, not add a second
    (only retries look: a first attempt has nothing to find)."""
    with SessionLocal() as db:
        rows = db.scalars(select(EvidenceRecord).where(
            EvidenceRecord.tenant_id == tenant_id, EvidenceRecord.record_type == record_type,
            EvidenceRecord.payload_json.contains(session_id, autoescape=True)).order_by(EvidenceRecord.seq))
        for record in rows:
            try:
                payload = json.loads(record.payload_json)
            except ValueError:
                continue
            if isinstance(payload, dict) and payload.get("checkout_session_id") == session_id:
                return record.id
    return None


def _load_runtime(text):
    try:
        value = json.loads(text) if text else None
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) and "computation" in value else None


def _fenced_update(row_event_id: str, token: float, **values) -> None:
    with SessionLocal() as db:
        done = db.execute(update(StripeEvent).where(
            StripeEvent.event_id == row_event_id, StripeEvent.status == "PROCESSING", StripeEvent.claimed_at == token,
        ).values(**values)).rowcount
        db.commit()
    if done != 1:
        raise _LeaseLost(row_event_id)


def _set_failed(row_event_id: str, token: float) -> None:
    with SessionLocal() as db:
        db.execute(update(StripeEvent).where(
            StripeEvent.event_id == row_event_id, StripeEvent.status == "PROCESSING",
            StripeEvent.claimed_at == token).values(status="FAILED"))
        db.commit()


def _mark_failed(row_event_id: str, token: float, attempts: int = 4) -> bool:
    """FAILED makes the row retryable at once. The write is retried with a short backoff because the failure that
    brought us here is often a busy database; if it still does not go through, the lease is the backstop (the row
    becomes reclaimable when it runs out) instead of PROCESSING for ever."""
    for attempt in range(attempts):
        try:
            _set_failed(row_event_id, token)
            return True
        except Exception:                                    # busy / locked / transient: back off and try again
            if attempt + 1 < attempts:
                _pause(0.1 * 2 ** attempt)
    log.warning("could not mark stripe event %s FAILED; it becomes reclaimable when its lease expires", row_event_id)
    return False


def _summarise(runtime: dict) -> dict:
    status = runtime.get("status", "UNKNOWN")
    computation = runtime.get("computation")
    if computation not in ("PERFORMED", "NOT_PERFORMED"):      # a runner that does not say: only VERIFIED counts as work done
        computation = "PERFORMED" if status == "VERIFIED" else "NOT_PERFORMED"
    return {"status": status, "run_id": runtime.get("run_id"), "final_result": runtime.get("final_result"),
            "evidence_ids": list(runtime.get("evidence_ids") or []), "computation": computation}


def process_checkout_event(payload: bytes, signature_header: str) -> dict:
    secret = os.getenv("STRIPE_WEBHOOK_SECRET", "")
    if not verify_stripe_signature(payload, signature_header, secret):
        raise HTTPException(status_code=400, detail="invalid Stripe signature")

    event = _parse_event(payload)
    event_id = _text(event.get("id"), "event id")
    event_type = _text(event.get("type"), "event type")
    if event_type == "checkout.session.async_payment_failed":
        # the money never arrived: nothing is run and nothing is charged to the audit; 200 so Stripe does not retry
        return {"status": "NOT_RUN", "event_id": event_id, "event_type": event_type,
                "reason": "asynchronous payment failed"}
    if event_type not in PAID_EVENTS:
        return {"status": "IGNORED", "event_id": event_id, "event_type": event_type}

    session = _dict(_dict(event.get("data"), "data").get("object"), "data.object")
    task = _validate_checkout(session, allow_unpaid=(event_type == "checkout.session.completed"))
    if session.get("payment_status") != "paid":
        # asynchronous method: the order is valid but not paid yet. Run nothing, store nothing, answer 200;
        # `checkout.session.async_payment_succeeded` is the event that starts the run.
        return {"status": "AWAITING_PAYMENT", "event_id": event_id, "event_type": event_type,
                "checkout_session_id": session.get("id")}
    session_id = _text(session.get("id"), "checkout session id")
    tenant_id = _dict(session.get("metadata"), "metadata").get("tenant_id") or os.getenv("OLA_STRIPE_TENANT_ID", "")
    if not isinstance(tenant_id, str):
        raise HTTPException(status_code=400, detail="Stripe tenant_id must be a string")
    if not tenant_id:
        raise HTTPException(status_code=500, detail="Stripe session has no tenant provenance")
    _text(tenant_id, "tenant_id")
    with SessionLocal() as db:
        if db.get(Tenant, tenant_id) is None:
            raise HTTPException(status_code=400, detail="Stripe session names an unknown tenant")

    outcome, claim = _claim(event_id, session_id, task)
    if outcome == "cached":
        return claim
    row_event_id, token, retry = claim["row_event_id"], claim["token"], claim["retry"]
    try:
        payment_evidence_id = claim["payment_evidence_id"]
        if not payment_evidence_id and retry:                # crashed between the append and persisting its id?
            payment_evidence_id = _recorded(tenant_id, "stripe.payment_confirmed", session_id)
            if payment_evidence_id:
                _fenced_update(row_event_id, token, payment_evidence_id=payment_evidence_id)
        if not payment_evidence_id:                          # a retry reuses the evidence of the first attempt
            payload_evidence = {
                "stripe_event_id": row_event_id,
                "checkout_session_id": session_id,
                "offer": OLA_OFFER,
                "product": OLA_PRODUCT,
                "amount_total": session.get("amount_total"),
                "currency": session.get("currency"),
                "task": task,
                "retry_of_failed_attempt": retry,
            }
            if event_id != row_event_id:
                payload_evidence["delivered_by_event_id"] = event_id
            payment_evidence_id = _append_evidence(tenant_id, "stripe.payment_confirmed", payload_evidence)
            _fenced_update(row_event_id, token, payment_evidence_id=payment_evidence_id)

        runtime = claim["runtime"]
        if runtime is None:                                  # a retry reuses a run that already finished (paid once)
            runtime = _summarise(run_agent_task(tenant_id, task))
            _fenced_update(row_event_id, token, run_id=runtime["run_id"], runtime_json=canonical_json(runtime))

        result = {
            "status": "COMPLETED",
            "event_id": row_event_id,
            "checkout_session_id": session_id,
            "payment": "CONFIRMED",
            "ola_status": runtime["status"],
            "computation": runtime["computation"],
            "ola_run_id": runtime["run_id"],
            "ola_final_result": runtime["final_result"],
            "payment_evidence_id": payment_evidence_id,
            "ola_evidence_ids": runtime["evidence_ids"],
        }
        if not (retry and _recorded(tenant_id, "stripe.ola_execution_completed", session_id)):
            _append_evidence(
                tenant_id,
                "stripe.ola_execution_completed",
                {
                    "stripe_event_id": row_event_id,
                    "checkout_session_id": session_id,
                    "ola_run_id": runtime["run_id"],
                    "ola_status": runtime["status"],
                    "computation": runtime["computation"],
                    "ola_final_result": runtime["final_result"],
                    "payment_evidence_id": payment_evidence_id,
                },
            )
        _fenced_update(row_event_id, token, status="COMPLETED", run_id=runtime["run_id"], result_json=canonical_json(result))
    except _LeaseLost:
        raise _busy() from None                              # another worker owns the row now: leave its state alone
    except Exception:
        _mark_failed(row_event_id, token)                    # never leave the row PROCESSING if it can be helped
        raise

    return result
