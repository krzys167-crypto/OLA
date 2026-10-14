import hashlib
import hmac
import json
import os
import time
import uuid

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from .agent_runtime import run_agent_task
from .database import SessionLocal
from .hashchain import canonical_json
from .models import StripeEvent
from .stripe_mode import StripeModeError, validate_stripe_mode


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
    # One SQLite writer for every tenant's hash chain (NINA, audit, Stripe).
    from .main import append_record
    return append_record(tenant_id, record_type, payload)["id"]


def _session_claim(payload: dict) -> str | None:
    if not isinstance(payload, dict):
        return None
    value = payload.get("checkout_session_id")
    return value if isinstance(value, str) and value else None


def _event_session_claim(event: StripeEvent) -> str | None:
    if not event.result_json:
        return None
    try:
        return _session_claim(json.loads(event.result_json))
    except (json.JSONDecodeError, TypeError):
        return None


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
    try:
        validate_stripe_mode(session.get("livemode"), allow_missing_test_fixture=True)
    except StripeModeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    metadata = session.get("metadata") or {}
    if metadata.get("offer") != OLA_OFFER:
        raise HTTPException(status_code=400, detail="unsupported Stripe offer")
    if metadata.get("product") not in {None, OLA_PRODUCT}:
        raise HTTPException(status_code=400, detail="unsupported Stripe product")
    if session.get("payment_status") != "paid" or session.get("status") not in {None, "complete"}:
        raise HTTPException(status_code=400, detail="payment is not confirmed")
    if session.get("currency") != "eur" or session.get("amount_total") != 9900:
        raise HTTPException(status_code=400, detail="unexpected payment amount or currency")
    line_items = session.get("line_items") or {}
    if isinstance(line_items, dict):
        price_ids = {
            item.get("price", {}).get("id")
            for item in line_items.get("data", [])
            if isinstance(item, dict)
        }
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

    try:
        validate_stripe_mode(event.get("livemode"), allow_missing_test_fixture=True)
    except StripeModeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    event_id = event.get("id")
    event_type = event.get("type")
    if not event_id or not event_type:
        raise HTTPException(status_code=400, detail="Stripe event id and type are required")
    if event_type != "checkout.session.completed":
        return {"status": "IGNORED", "event_id": event_id, "event_type": event_type}

    session = event.get("data", {}).get("object", {})
    task = _validate_checkout(session)
    tenant_id = (session.get("metadata") or {}).get("tenant_id") or os.getenv("OLA_STRIPE_TENANT_ID", "")
    if not tenant_id:
        raise HTTPException(status_code=500, detail="Stripe session has no tenant provenance")

    session_id = session.get("id")
    if not isinstance(session_id, str) or not session_id.startswith(("cs_test_", "cs_live_")):
        raise HTTPException(status_code=400, detail="valid checkout session id required")

    # SQLite write reservation makes the session claim atomic across event IDs.
    # Store the claim in existing result_json to avoid unsafe ALTER TABLE
    # migration of the production/staging StripeEvent table.
    with SessionLocal() as db:
        db.connection().exec_driver_sql("BEGIN IMMEDIATE")
        old_events = db.scalars(select(StripeEvent)).all()
        for old in old_events:
            if old.event_id == event_id or _event_session_claim(old) == session_id:
                # Never return a different tenant's receipt or a legacy
                # unbound result; require explicit operator reconciliation.
                try:
                    stored = json.loads(old.result_json) if old.result_json else None
                except (json.JSONDecodeError, TypeError):
                    stored = None
                if not isinstance(stored, dict) or (
                    stored.get("tenant_id") != tenant_id
                    or stored.get("checkout_session_id") != session_id
                ):
                    raise HTTPException(status_code=409, detail="Stripe claim provenance mismatch; manual recovery required")
                if old.status in {"COMPLETED", "EXECUTION_BLOCKED"}:
                    return stored
                raise HTTPException(status_code=409, detail="checkout already claimed; manual recovery required")

        db.add(StripeEvent(
            id=str(uuid.uuid4()),
            event_id=event_id,
            status="PROCESSING",
            task=task,
            result_json=canonical_json({
                "checkout_session_id": session_id,
                "tenant_id": tenant_id,
                "status": "PROCESSING",
            }),
        ))
        db.commit()

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
            },
        )

        runtime = run_agent_task(tenant_id, task)

        result = {
            "status": "COMPLETED" if runtime.get("status") == "VERIFIED" else "EXECUTION_BLOCKED",
            "event_id": event_id,
            "checkout_session_id": session.get("id"),
            "tenant_id": tenant_id,
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
            completed.status = result["status"]
            completed.run_id = runtime.get("run_id")
            completed.result_json = canonical_json(result)
            db.commit()

    except Exception:
        # Once paid, never re-run blindly on retries. Preserve the session
        # claim and mark failure for authenticated manual reconciliation.
        with SessionLocal() as db:
            failed = db.scalar(select(StripeEvent).where(StripeEvent.event_id == event_id))
            if failed is not None and failed.status == "PROCESSING":
                failed.status = "FAILED"
                db.commit()
        raise

    return result
