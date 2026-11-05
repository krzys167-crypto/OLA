import hashlib
import hmac
import json
import os
import time
import uuid

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from .database import SessionLocal, append_evidence_atomic
from .hashchain import canonical_json
from .models import StripeEvent
from .revenue import retrieve_checkout


STRIPE_SIGNATURE_TOLERANCE_SECONDS = 300
OLA_OFFER = "ola-execution-audit"
OLA_PRODUCT = "OLA Execution Audit"


def verify_stripe_signature(payload: bytes, signature_header: str, secret: str, now: int | None = None) -> bool:
    if not signature_header or not secret:
        return False
    timestamp = None
    signatures = []
    for item in signature_header.split(","):
        key, _, value = item.partition("=")
        if key == "t":
            try:
                timestamp = int(value)
            except ValueError:
                return False
        elif key == "v1" and value:
            signatures.append(value)
    if timestamp is None or not signatures:
        return False
    current = int(time.time()) if now is None else now
    if abs(current - timestamp) > STRIPE_SIGNATURE_TOLERANCE_SECONDS:
        return False
    signed = f"{timestamp}.".encode("utf-8") + payload
    expected = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected, signature) for signature in signatures)


def _append_evidence(tenant_id: str, record_type: str, payload: dict) -> str:
    return append_evidence_atomic(tenant_id, record_type, payload)["id"]


def _metadata_task(session: dict) -> str | None:
    metadata = session.get("metadata") or {}
    task = metadata.get("task")
    if isinstance(task, str) and task.strip():
        return task.strip()
    for field in session.get("custom_fields", []) or []:
        if field.get("key") == "audit_task":
            value = field.get("text", {}).get("value")
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def _validate_checkout(session: dict) -> str:
    metadata = session.get("metadata") or {}
    if metadata.get("offer") != OLA_OFFER:
        raise HTTPException(status_code=400, detail="unsupported Stripe offer")
    if metadata.get("product") != OLA_PRODUCT:
        raise HTTPException(status_code=400, detail="unsupported Stripe product")
    if session.get("payment_status") != "paid" or session.get("status") != "complete":
        raise HTTPException(status_code=400, detail="payment is not confirmed")
    if session.get("currency") != "eur" or session.get("amount_total") != 9900:
        raise HTTPException(status_code=400, detail="unexpected payment amount or currency")

    line_items = session.get("line_items")
    items = line_items.get("data") if isinstance(line_items, dict) else None
    expected_price = os.getenv("OLA_STRIPE_PRICE_ID")
    if not isinstance(items, list) or len(items) != 1 or not expected_price:
        raise HTTPException(status_code=400, detail="Stripe line items or configured price are invalid")
    item = items[0]
    if not isinstance(item, dict):
        raise HTTPException(status_code=400, detail="invalid Stripe line item")
    price = item.get("price")
    price_id = price.get("id") if isinstance(price, dict) else None
    if price_id != expected_price or item.get("quantity") != 1:
        raise HTTPException(status_code=400, detail="unexpected Stripe price or quantity")

    task = _metadata_task(session)
    if not task:
        raise HTTPException(status_code=400, detail="audit task is required")
    if not metadata.get("tenant_id"):
        raise HTTPException(status_code=400, detail="tenant provenance is required")
    return task


def _existing_result(event_id: str, checkout_session_id: str) -> dict | None:
    with SessionLocal() as db:
        existing = db.scalar(select(StripeEvent).where(StripeEvent.event_id == event_id))
        if existing is None:
            return None
        if existing.status == "PAID_PENDING_HUMAN_GATE" and existing.result_json:
            result = json.loads(existing.result_json)
            if result.get("checkout_session_id") != checkout_session_id:
                raise HTTPException(status_code=409, detail="Stripe event/session binding conflict")
            return result
        raise HTTPException(status_code=503, detail="Stripe event is not yet safely finalized; retry delivery")


def process_checkout_event(payload: bytes, signature_header: str) -> dict:
    secret = os.getenv("STRIPE_WEBHOOK_SECRET", "")
    if not verify_stripe_signature(payload, signature_header, secret):
        raise HTTPException(status_code=400, detail="invalid Stripe signature")

    try:
        event = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="invalid Stripe JSON") from exc

    event_id = event.get("id")
    event_type = event.get("type")
    if not event_id or not event_type:
        raise HTTPException(status_code=400, detail="Stripe event id and type are required")
    if event_type != "checkout.session.completed":
        return {"status": "IGNORED", "event_id": event_id, "event_type": event_type}

    event_session = event.get("data", {}).get("object", {})
    checkout_session_id = event_session.get("id") if isinstance(event_session, dict) else None
    if not isinstance(checkout_session_id, str) or not checkout_session_id:
        raise HTTPException(status_code=400, detail="Stripe Checkout Session id is required")

    existing = _existing_result(event_id, checkout_session_id)
    if existing is not None:
        return existing

    try:
        session = retrieve_checkout(checkout_session_id)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Stripe session verification is temporarily unavailable") from exc
    if not isinstance(session, dict) or session.get("id") != checkout_session_id:
        raise HTTPException(status_code=400, detail="Stripe session identity mismatch")

    task = _validate_checkout(session)
    metadata = session.get("metadata") or {}
    tenant_id = metadata.get("tenant_id")

    record = StripeEvent(
        id=str(uuid.uuid4()),
        event_id=event_id,
        status="PROCESSING",
        task=task,
    )
    with SessionLocal() as db:
        db.add(record)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            existing = _existing_result(event_id, checkout_session_id)
            if existing is not None:
                return existing
            raise HTTPException(status_code=503, detail="Stripe event is being processed; retry delivery") from None

    try:
        payment_evidence_id = _append_evidence(
            tenant_id,
            "stripe.payment_confirmed",
            {
                "stripe_event_id": event_id,
                "checkout_session_id": checkout_session_id,
                "offer": OLA_OFFER,
                "product": OLA_PRODUCT,
                "amount_total": session.get("amount_total"),
                "currency": session.get("currency"),
                "task": task,
                "state": "PAID_PENDING_HUMAN_GATE",
            },
        )
        result = {
            "status": "PAID_PENDING_HUMAN_GATE",
            "event_id": event_id,
            "checkout_session_id": checkout_session_id,
            "payment": "CONFIRMED",
            "execution": "NOT_STARTED",
            "human_gate": "PENDING",
            "payment_evidence_id": payment_evidence_id,
        }
        with SessionLocal() as db:
            pending = db.scalar(select(StripeEvent).where(StripeEvent.event_id == event_id))
            if pending is None or pending.status != "PROCESSING":
                raise RuntimeError("Stripe event state changed before Human Gate handoff")
            pending.status = "PAID_PENDING_HUMAN_GATE"
            pending.result_json = canonical_json(result)
            db.commit()
        return result
    except Exception as exc:
        with SessionLocal() as db:
            failed = db.scalar(select(StripeEvent).where(StripeEvent.event_id == event_id))
            if failed is not None and failed.status == "PROCESSING":
                failed.status = "FAILED_RETRYABLE"
                db.commit()
        raise HTTPException(status_code=503, detail="Payment verified but Human Gate handoff requires retry") from exc
