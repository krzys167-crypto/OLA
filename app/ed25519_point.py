"""Strict validation of an Ed25519 public key (public data only; reuses the audited pure-Python arithmetic
of ola_pipeline.ed25519).

Why: a signature only means "this key signed it" for keys that are canonical encodings of points of the
prime-order subgroup. A non-canonical encoding of a small-order point (y = p+1, or x=0 with the sign bit set)
slips past a list of canonical small-order encodings and then verifies for ANY message with R = identity,
S = 0. A key with a torsion component (A + T) validates the same signatures as A, so two different 32-byte
keys could stand for one secret ("one key = one principal" would not hold). Both are refused:
  * the bytes must decode strictly (y < p, on the curve, no negative zero) -- ed25519._decompress does,
  * the point must not be the identity and must satisfy [L]A == identity (prime-order subgroup).
Together these also exclude all eight small-order points in every encoding.
"""
from __future__ import annotations

from ola_pipeline import ed25519 as _ed


def is_prime_order_point(raw: bytes) -> bool:
    pt = _ed._decompress(raw)
    if pt is None or _ed._equal(pt, _ed._ZERO):
        return False
    return _ed._equal(_ed._mul(_ed.L, pt), _ed._ZERO)
