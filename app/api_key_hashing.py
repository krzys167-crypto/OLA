"""Keyed API-key fingerprints, with bounded verification cost.

This preserves the existing scrypt fingerprint format. It deliberately fails
closed under overload; it is NOT a substitute for edge rate limiting.
"""
import hashlib
import os
import threading

# Per-worker bound: max two concurrent expensive scrypt operations. Requests
# beyond this bound fail immediately rather than allocating more scrypt memory.
_SCRYPT_SLOTS = threading.BoundedSemaphore(value=2)
_MAX_KEY_BYTES = 512


def api_key_fingerprint(raw_key: str) -> str:
    if not isinstance(raw_key, str) or not raw_key:
        raise ValueError("API key required")
    raw = raw_key.encode("utf-8")
    if len(raw) > _MAX_KEY_BYTES:
        raise ValueError("API key too long")
    pepper = os.environ.get("OLA_API_KEY_PEPPER", "")
    if len(pepper.encode("utf-8")) < 32:
        raise RuntimeError("API key hashing secret is not configured")
    if not _SCRYPT_SLOTS.acquire(blocking=False):
        raise RuntimeError("API key hashing temporarily at capacity")
    try:
        return hashlib.scrypt(
            raw, salt=pepper.encode("utf-8"),
            n=1 << 14, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=32,
        ).hex()
    finally:
        _SCRYPT_SLOTS.release()
