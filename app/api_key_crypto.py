"""Fail-closed, version-2 OLA API key verifier.

A deployment MUST supply its own high-entropy OLA_API_KEY_PEPPER through a
protected environment/secret manager. The legacy unsalted SHA-256 key_hash
is NEVER accepted at runtime. Old credentials must be reissued offline before
promoting this version.
"""
from __future__ import annotations

import hashlib
import os

ROUNDS = 310_000
DOMAIN = b"OLA-DI-OS/API-KEY/PBKDF2-HMAC-SHA256/v2\0"
PEPPER_VARIABLE = "OLA_API_KEY_PEPPER"


class KeyConfigurationError(RuntimeError):
    pass


def hash_api_key(raw_key: str) -> str:
    if not isinstance(raw_key, str) or not raw_key or len(raw_key) > 512:
        raise ValueError("invalid API key")
    pepper = os.environ.get(PEPPER_VARIABLE, "")
    # This key is deployment-specific and never checked into the repository.
    if len(pepper.encode("utf-8")) < 32:
        raise KeyConfigurationError("OLA_API_KEY_PEPPER must contain at least 32 UTF-8 bytes")
    return hashlib.pbkdf2_hmac(
        "sha256",
        raw_key.encode("utf-8"),
        DOMAIN + pepper.encode("utf-8"),
        ROUNDS,
    ).hex()
