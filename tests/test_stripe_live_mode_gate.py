"""Regression: no sandbox Checkout or webhook may be promoted in OLA LIVE mode."""
import pytest
from app.stripe_mode import validate_stripe_mode, StripeModeError


def test_live_accepts_exact_live_object_with_live_key(monkeypatch):
    monkeypatch.setenv("OLA_STRIPE_MODE", "live")
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_dummy_test_only")
    validate_stripe_mode(True)


@pytest.mark.parametrize("value", [False, None, "true", 1, 0])
def test_live_rejects_sandbox_unknown_and_fake_boolean(monkeypatch, value):
    monkeypatch.setenv("OLA_STRIPE_MODE", "live")
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_dummy_test_only")
    with pytest.raises(StripeModeError):
        validate_stripe_mode(value)


def test_live_rejects_test_key_even_for_live_object(monkeypatch):
    monkeypatch.setenv("OLA_STRIPE_MODE", "live")
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_dummy_test_only")
    with pytest.raises(StripeModeError):
        validate_stripe_mode(True)


def test_test_mode_rejects_live_object(monkeypatch):
    monkeypatch.setenv("OLA_STRIPE_MODE", "test")
    with pytest.raises(StripeModeError):
        validate_stripe_mode(True)


def test_test_mode_allows_test_object(monkeypatch):
    monkeypatch.setenv("OLA_STRIPE_MODE", "test")
    validate_stripe_mode(False)


def test_missing_test_fixture_is_only_allowed_when_explicit(monkeypatch):
    monkeypatch.setenv("OLA_STRIPE_MODE", "test")
    with pytest.raises(StripeModeError):
        validate_stripe_mode(None)
    validate_stripe_mode(None, allow_missing_test_fixture=True)


def test_invalid_environment_fails_closed(monkeypatch):
    monkeypatch.setenv("OLA_STRIPE_MODE", "production")
    with pytest.raises(StripeModeError):
        validate_stripe_mode(True)


def test_test_mode_rejects_live_key_even_for_test_session(monkeypatch):
    monkeypatch.setenv("OLA_STRIPE_MODE", "test")
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_dummy_test_only")
    with pytest.raises(StripeModeError):
        validate_stripe_mode(False)

from fastapi import HTTPException
from app.stripe_webhook import _validate_checkout
from app.revenue import payment_verified


def _paid_checkout(livemode):
    return {
        "livemode": livemode,
        "metadata": {"tenant_id": "tenant-test", "offer": "ola-execution-audit",
                     "product": "OLA Execution Audit", "task": "safe GO regression"},
        "payment_status": "paid", "status": "complete", "amount_total": 9900,
        "currency": "eur",
    }


def test_live_webhook_rejects_paid_sandbox_checkout(monkeypatch):
    monkeypatch.setenv("OLA_STRIPE_MODE", "live")
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_dummy_test_only")
    with pytest.raises(HTTPException) as exc:
        _validate_checkout(_paid_checkout(False))
    assert exc.value.status_code == 400


def test_live_payment_success_never_promotes_paid_sandbox(monkeypatch):
    monkeypatch.setenv("OLA_STRIPE_MODE", "live")
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_dummy_test_only")
    assert payment_verified(_paid_checkout(False)) is False
    assert payment_verified(_paid_checkout(True)) is True


def test_live_webhook_rejects_missing_livemode(monkeypatch):
    monkeypatch.setenv("OLA_STRIPE_MODE", "live")
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_dummy_test_only")
    with pytest.raises(HTTPException):
        _validate_checkout(_paid_checkout(None))
