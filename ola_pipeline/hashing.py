"""SHA-256 helpers. Canonical JSON = sorted keys, no whitespace, UTF-8."""
import hashlib
import json
from typing import Any


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def canonical_hash(obj: Any) -> str:
    return sha256_hex(canonical_bytes(obj))
