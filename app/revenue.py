import hashlib
import hmac
import json
import os
import urllib.parse
import urllib.request
from typing import Any

from .stripe_mode import StripeModeError, validate_stripe_mode

PRODUCT_NAME = "OLA Execution Audit"
OFFER = "ola-execution-audit"


def _stripe_request(path: str, fields: dict[str, Any]) -> dict[str, Any]:
    secret = os.getenv("STRIPE_SECRET_KEY")
    if not secret:
        raise RuntimeError("STRIPE_SECRET_KEY is not configured")
    try:
        validate_stripe_mode(os.getenv("OLA_STRIPE_MODE", "test").strip().lower() == "live")
    except StripeModeError as exc:
        raise RuntimeError(str(exc)) from exc
    req = urllib.request.Request(
        "https://api.stripe.com/v1/" + path,
        data=urllib.parse.urlencode(fields).encode(),
        headers={
            "Authorization": f"Bearer {secret}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        result = json.load(response)
    try:
        validate_stripe_mode(result.get("livemode"), allow_missing_test_fixture=True)
    except StripeModeError as exc:
        raise RuntimeError(str(exc)) from exc
    return result


def create_checkout(task, success_url, cancel_url, tenant_id):
    price_id = os.getenv("OLA_STRIPE_PRICE_ID")
    if not price_id:
        raise RuntimeError("OLA_STRIPE_PRICE_ID is not configured")
    return _stripe_request(
        "checkout/sessions",
        {
            "mode": "payment",
            "line_items[0][price]": price_id,
            "line_items[0][quantity]": "1",
            "success_url": success_url + "?session_id={CHECKOUT_SESSION_ID}",
            "cancel_url": cancel_url,
            "client_reference_id": hashlib.sha256(task.encode()).hexdigest(),
            "metadata[product]": PRODUCT_NAME,
            "metadata[offer]": OFFER,
            "metadata[task]": task,
            "metadata[tenant_id]": tenant_id,
        },
    )


def retrieve_checkout(session_id):
    secret = os.getenv("STRIPE_SECRET_KEY")
    if not secret:
        raise RuntimeError("STRIPE_SECRET_KEY is not configured")
    try:
        validate_stripe_mode(os.getenv("OLA_STRIPE_MODE", "test").strip().lower() == "live")
    except StripeModeError as exc:
        raise RuntimeError(str(exc)) from exc
    req = urllib.request.Request(
        "https://api.stripe.com/v1/checkout/sessions/" + urllib.parse.quote(session_id, safe=""),
        headers={"Authorization": f"Bearer {secret}"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        result = json.load(response)
    try:
        validate_stripe_mode(result.get("livemode"), allow_missing_test_fixture=True)
    except StripeModeError as exc:
        raise RuntimeError(str(exc)) from exc
    return result


def payment_verified(session):
    try:
        validate_stripe_mode(session.get("livemode"), allow_missing_test_fixture=True)
    except StripeModeError:
        return False
    metadata = session.get("metadata", {})
    return (
        session.get("payment_status") == "paid"
        and session.get("status") == "complete"
        and metadata.get("product") == PRODUCT_NAME
        and metadata.get("offer") == OFFER
        and bool(metadata.get("tenant_id"))
        and bool(metadata.get("task"))
    )


def verify_webhook_signature(payload: bytes, signature: str, secret: str, tolerance: int = 300):
    if not signature or not secret:
        return False
    timestamp = None
    signatures = []
    for item in signature.split(","):
        key, _, value = item.partition("=")
        if key == "t":
            timestamp = value
        elif key == "v1":
            signatures.append(value)
    if not timestamp or not signatures:
        return False
    import time
    try:
        if abs(int(time.time()) - int(timestamp)) > tolerance:
            return False
    except ValueError:
        return False
    expected = hmac.new(
        secret.encode(),
        f"{timestamp}.{payload.decode()}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return any(hmac.compare_digest(expected, candidate) for candidate in signatures)
