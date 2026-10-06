import hashlib
import hmac
import json
import os
import time
import uuid

from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from .agent_runtime import run_agent_task
from .database import SessionLocal
from .hashchain import GENESIS_HASH, canonical_json, compute_record_hash
from .models import EvidenceRecord, StripeEvent, Tenant


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
    # same chain and hashing (v2, type-bound), through the retrying append (lazy import: see business_runtime)
    from .pipeline_bridge import append_evidence
    return append_evidence(tenant_id, record_type, payload, attempts=96)["id"]


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


def _validate_checkout(session: dict) -> str:
    metadata = _dict(session.get("metadata"), "metadata")
    if metadata.get("offer") != OLA_OFFER:
        raise HTTPException(status_code=400, detail="unsupported Stripe offer")
    product = metadata.get("product")
    if product is not None and product != OLA_PRODUCT:  # `in {set}` would raise TypeError on a list/dict (500)
        raise HTTPException(status_code=400, detail="unsupported Stripe product")
    status = session.get("status")
    if session.get("payment_status") != "paid" or (status is not None and status != "complete"):
        raise HTTPException(status_code=400, detail="payment is not confirmed")
    if session.get("currency") != "eur" or session.get("amount_total") != 9900:
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
    return task


def process_checkout_event(payload: bytes, signature_header: str) -> dict:
    secret = os.getenv("STRIPE_WEBHOOK_SECRET", "")
    if not verify_stripe_signature(payload, signature_header, secret):
        raise HTTPException(status_code=400, detail="invalid Stripe signature")

    try:
        event = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="invalid Stripe JSON") from exc

    if not isinstance(event, dict):
        raise HTTPException(status_code=400, detail="Stripe event must be a JSON object")
    event_id = event.get("id")
    event_type = event.get("type")
    if not isinstance(event_id, str) or not isinstance(event_type, str) or not event_id or not event_type:
        raise HTTPException(status_code=400, detail="Stripe event id and type are required strings")
    if event_type != "checkout.session.completed":
        return {"status": "IGNORED", "event_id": event_id, "event_type": event_type}

    session = _dict(_dict(event.get("data"), "data").get("object"), "data.object")
    task = _validate_checkout(session)
    tenant_id = _dict(session.get("metadata"), "metadata").get("tenant_id") or os.getenv("OLA_STRIPE_TENANT_ID", "")
    if not isinstance(tenant_id, str):
        raise HTTPException(status_code=400, detail="Stripe tenant_id must be a string")
    if not tenant_id:
        raise HTTPException(status_code=500, detail="Stripe session has no tenant provenance")
    with SessionLocal() as db:
        if db.get(Tenant, tenant_id) is None:
            raise HTTPException(status_code=400, detail="Stripe session names an unknown tenant")

    retry = False
    with SessionLocal() as db:
        existing = db.scalar(select(StripeEvent).where(StripeEvent.event_id == event_id))
        if existing is not None:
            if existing.status == "COMPLETED" and existing.result_json:
                return json.loads(existing.result_json)
            if existing.status != "FAILED":
                raise HTTPException(status_code=409, detail="Stripe event is already being processed")
            # A FAILED attempt must be retryable (Stripe re-delivers): claim it with a compare-and-set so two
            # concurrent redeliveries cannot both run the paid task.
            claimed = db.execute(
                update(StripeEvent)
                .where(StripeEvent.event_id == event_id, StripeEvent.status == "FAILED")
                .values(status="PROCESSING", task=task)
            )
            db.commit()
            if claimed.rowcount != 1:
                raise HTTPException(status_code=409, detail="Stripe event is already being processed")
            retry = True
        else:
            record = StripeEvent(
                id=str(uuid.uuid4()),
                event_id=event_id,
                status="PROCESSING",
                task=task,
            )
            db.add(record)
            try:
                db.commit()
            except IntegrityError:
                db.rollback()
                raise HTTPException(status_code=409, detail="Stripe event is already being processed") from None

    try:
        payment_evidence_id = _append_evidence(
            tenant_id,
            "stripe.payment_confirmed",
            {
                "stripe_event_id": event_id,
                "checkout_session_id": session.get("id"),
                "offer": OLA_OFFER,
                "product": OLA_PRODUCT,
                "amount_total": session.get("amount_total"),
                "currency": session.get("currency"),
                "task": task,
                "retry_of_failed_attempt": retry,
            },
        )

        runtime = run_agent_task(tenant_id, task)

        result = {
            "status": "COMPLETED",
            "event_id": event_id,
            "checkout_session_id": session.get("id"),
            "payment": "CONFIRMED",
            "ola_status": runtime.get("status", "UNKNOWN"),
            "ola_run_id": runtime.get("run_id"),
            "ola_final_result": runtime.get("final_result"),
            "payment_evidence_id": payment_evidence_id,
            "ola_evidence_ids": runtime.get("evidence_ids", []),
        }
        _append_evidence(
            tenant_id,
            "stripe.ola_execution_completed",
            {
                "stripe_event_id": event_id,
                "checkout_session_id": session.get("id"),
                "ola_run_id": runtime.get("run_id"),
                "ola_status": runtime.get("status", "UNKNOWN"),
                "ola_final_result": runtime.get("final_result"),
                "payment_evidence_id": payment_evidence_id,
            },
        )

        with SessionLocal() as db:
            completed = db.scalar(select(StripeEvent).where(StripeEvent.event_id == event_id))
            completed.status = "COMPLETED"
            completed.run_id = runtime.get("run_id")
            completed.result_json = canonical_json(result)
            db.commit()

    except Exception:
        # never leave the row PROCESSING: Stripe would be told "already being processed" forever
        with SessionLocal() as db:
            failed = db.scalar(select(StripeEvent).where(StripeEvent.event_id == event_id))
            if failed is not None and failed.status == "PROCESSING":
                failed.status = "FAILED"
                db.commit()
        raise

    return result
