"""Fail-closed Stripe LIVE mode binding shared by checkout, webhook and success route.

Production requires OLA_STRIPE_MODE=live and a live Stripe API key. The
legacy default is TEST for existing tests/staging; operator GO must explicitly
prove LIVE mode and independently check both Stripe Checkout and PaymentIntent.
"""
from __future__ import annotations

import os


class StripeModeError(ValueError):
    pass


def validate_stripe_mode(livemode: object, *, allow_missing_test_fixture: bool = False) -> None:
    mode = os.environ.get("OLA_STRIPE_MODE", "test").strip().lower()
    if mode not in {"test", "live"}:
        raise StripeModeError("OLA_STRIPE_MODE must be explicitly test or live")
    if mode == "live":
        api_key = os.environ.get("STRIPE_SECRET_KEY", "")
        if not api_key.startswith(("sk_live_", "rk_live_")):
            raise StripeModeError("LIVE requires a live Stripe API key")
        if livemode is not True:
            raise StripeModeError("LIVE rejects non-live or unknown Stripe objects")
    else:
        api_key = os.environ.get("STRIPE_SECRET_KEY", "")
        if api_key.startswith(("sk_live_", "rk_live_")):
            raise StripeModeError("TEST cannot use LIVE Stripe API key")
        if livemode is True or (livemode is not False and not allow_missing_test_fixture):
            raise StripeModeError("TEST rejects live or unknown Stripe objects")
