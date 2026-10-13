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
