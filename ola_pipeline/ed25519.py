"""Ed25519 (RFC 8032, section 6 reference algorithm) in pure Python, stdlib only.

Used for: key derivation, signing (fallback only) and verification of session attestations.

HONEST LIMITS
* Not constant-time. Python big-int arithmetic leaks timing, so this implementation must NOT be the
  preferred signer for a long-lived secret: `attest.py` uses the `cryptography` package when it is
  installed and records which implementation signed (`signer_impl`). Verification handles only
  public data, so timing is irrelevant there.
* Strict verification: rejects S >= L, non-canonical y (>= p) and the invalid x = 0 / sign = 1 encoding.
  Cofactorless equation  [S]B == R + [h]A  (RFC 8032 permits either form). Behaviour on adversarial
  small-order public keys / R is NOT claimed to be identical to other libraries; the attestation
  verifier therefore only ever accepts a public key that was pinned by the caller.
* Not audited. Cross-checked against RFC 8032 vectors and the `cryptography` package in the tests.
"""
from __future__ import annotations

import hashlib
import os
from typing import Optional, Tuple

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493  # group order
_D = -121665 * pow(121666, P - 2, P) % P
_SQRT_M1 = pow(2, (P - 1) // 4, P)

Point = Tuple[int, int, int, int]


def _inv(x: int) -> int:
    return pow(x, P - 2, P)


def _recover_x(y: int, sign: int) -> Optional[int]:
    if y >= P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * _SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


_GY = 4 * _inv(5) % P
_GX = _recover_x(_GY, 0)
assert _GX is not None
G: Point = (_GX, _GY, 1, _GX * _GY % P)
_ZERO: Point = (0, 1, 1, 0)


def _add(p: Point, q: Point) -> Point:
    a = (p[1] - p[0]) * (q[1] - q[0]) % P
    b = (p[1] + p[0]) * (q[1] + q[0]) % P
    c = 2 * p[3] * q[3] * _D % P
    d = 2 * p[2] * q[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(s: int, p: Point) -> Point:
    q = _ZERO
    while s > 0:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _equal(p: Point, q: Point) -> bool:
    return (p[0] * q[2] - q[0] * p[2]) % P == 0 and (p[1] * q[2] - q[1] * p[2]) % P == 0


def _compress(p: Point) -> bytes:
    zinv = _inv(p[2])
    x, y = p[0] * zinv % P, p[1] * zinv % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s: bytes) -> Optional[Point]:
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def _h512_modl(data: bytes) -> int:
    return int.from_bytes(hashlib.sha512(data).digest(), "little") % L


def _expand(seed: bytes) -> Tuple[int, bytes]:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be exactly 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def generate_seed() -> bytes:
    return os.urandom(32)


def public_key(seed: bytes) -> bytes:
    a, _ = _expand(seed)
    return _compress(_mul(a, G))


def sign(seed: bytes, message: bytes) -> bytes:
    a, prefix = _expand(seed)
    pub = _compress(_mul(a, G))
    r = _h512_modl(prefix + message)
    rs = _compress(_mul(r, G))
    h = _h512_modl(rs + pub + message)
    s = (r + h * a) % L
    return rs + int.to_bytes(s, 32, "little")


def verify(pub: bytes, message: bytes, signature: bytes) -> bool:
    if len(pub) != 32 or len(signature) != 64:
        return False
    a_pt = _decompress(pub)
    if a_pt is None:
        return False
    rs = signature[:32]
    r_pt = _decompress(rs)
    if r_pt is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    h = _h512_modl(rs + pub + message)
    return _equal(_mul(s, G), _add(r_pt, _mul(h, a_pt)))
