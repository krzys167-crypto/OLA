"""Scoped, integrity-protected, one-use capability vouchers.

This prototype is not production isolation. Its replay ledger must be shared and
durable across every worker before runtime integration; SQLite is provided for
contract/recovery tests on a shared local file, not as a cloud multi-host store.
"""
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import time
import threading
from typing import Callable

MAX_CANONICAL_BYTES = 65536
MAX_JSON_DEPTH = 16
MAX_JSON_NODES = 4096
MAX_SAFE_INTEGER = (1 << 53) - 1
MAX_VOUCHER_TTL_SECONDS = 300
HEX32_RE = re.compile(r"^[0-9a-f]{32}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def _validate_json(value, *, depth=0, counter=None):
    if counter is None:
        counter = [0]
    counter[0] += 1
    if counter[0] > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
        raise ValueError("canonical value exceeds structural limits")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ValueError("canonical integer exceeds safe range")
        return
    if isinstance(value, float):
        raise ValueError("floating-point values are forbidden")
    if isinstance(value, str):
        if len(value) > MAX_CANONICAL_BYTES or any(
            ord(ch) < 32 or 0xD800 <= ord(ch) <= 0xDFFF for ch in value
        ):
            raise ValueError("canonical string is invalid")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json(item, depth=depth + 1, counter=counter)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 256 or any(
                ord(ch) < 32 or 0xD800 <= ord(ch) <= 0xDFFF for ch in key
            ):
                raise ValueError("canonical object key is invalid")
            _validate_json(item, depth=depth + 1, counter=counter)
        return
    raise ValueError("canonical value is not JSON")


def _canonical(value) -> bytes:
    _validate_json(value)
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")
    if len(encoded) > MAX_CANONICAL_BYTES:
        raise ValueError("canonical value exceeds byte limit")
    return encoded


def _digest(value) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _required_text(value, name, *, max_length=256):
    if not isinstance(value, str) or not value or len(value) > max_length or any(
        ord(ch) < 32 or 0xD800 <= ord(ch) <= 0xDFFF for ch in value
    ):
        raise PermissionError(f"{name} invalid")
    return value


@dataclass(frozen=True)
class ExecutionRequest:
    run_id: str
    tenant_id: str
    principal_id: str
    capability: str
    arguments: dict
    policy_version: str


@dataclass(frozen=True)
class CapabilityVoucher:
    voucher_id: str
    run_id: str
    tenant_id: str
    principal_id: str
    capability: str
    arguments_digest: str
    policy_version: str
    issued_at: int
    expires_at: int
    nonce: str
    signature: str


class VoucherIssuer:
    """Issuer for explicitly allowlisted capabilities; fail closed on key absence."""

    def __init__(self, secret: bytes, allowed_capabilities: set[str], ttl_seconds: int = 60):
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("voucher secret must be at least 32 bytes")
        if type(ttl_seconds) is not int or ttl_seconds <= 0 or ttl_seconds > MAX_VOUCHER_TTL_SECONDS:
            raise ValueError("voucher TTL must be between 1 and 300 seconds")
        if not isinstance(allowed_capabilities, (set, frozenset)) or not allowed_capabilities:
            raise ValueError("capability allowlist must be non-empty")
        if any(not isinstance(item, str) or not item for item in allowed_capabilities):
            raise ValueError("capability allowlist entries must be non-empty strings")
        self._secret = secret
        self._allowed = frozenset(allowed_capabilities)
        self._ttl = ttl_seconds

    def issue(self, request: ExecutionRequest, *, now: int | None = None) -> CapabilityVoucher:
        if not isinstance(request, ExecutionRequest):
            raise ValueError("execution request is required")
        for name in ("run_id", "tenant_id", "principal_id", "capability", "policy_version"):
            _required_text(getattr(request, name), name)
        if not isinstance(request.arguments, dict):
            raise ValueError("arguments must be an object")
        _canonical(request.arguments)
        if request.capability not in self._allowed:
            raise PermissionError("capability not allowlisted")
        issued = int(time.time()) if now is None else now
        if type(issued) is not int:
            raise ValueError("issuance time must be an integer")
        body = {
            "voucher_id": secrets.token_hex(16),
            "run_id": request.run_id,
            "tenant_id": request.tenant_id,
            "principal_id": request.principal_id,
            "capability": request.capability,
            "arguments_digest": _digest(request.arguments),
            "policy_version": request.policy_version,
            "issued_at": issued,
            "expires_at": issued + self._ttl,
            "nonce": secrets.token_hex(16),
        }
        signature = hmac.new(self._secret, _canonical(body), hashlib.sha256).hexdigest()
        return CapabilityVoucher(**body, signature=signature)


class MemoryReplayLedger:
    """Single-process replay ledger; only suitable for isolated tests."""

    def __init__(self):
        self._consumed: set[tuple[str, str, str]] = set()
        self._lock = threading.Lock()

    def consume(self, tenant_id: str, nonce: str, voucher_id: str, now: int) -> None:
        nonce_key = (tenant_id, "nonce", nonce)
        voucher_key = (tenant_id, "voucher", voucher_id)
        with self._lock:
            if nonce_key in self._consumed or voucher_key in self._consumed:
                raise PermissionError("voucher replay detected")
            self._consumed.add(nonce_key)
            self._consumed.add(voucher_key)


class SQLiteReplayLedger:
    """Atomic durable replay ledger for local-file contract tests.

    The file must be shared by all processes that consume the same vouchers.
    A local SQLite file is not a production multi-host replay store.
    """

    def __init__(self, path: str):
        if not isinstance(path, str) or not path or path == ":memory:":
            raise ValueError("replay ledger requires a persistent SQLite file path")
        self._path = path
        try:
            with sqlite3.connect(self._path, timeout=10) as db:
                db.execute("""
                    CREATE TABLE IF NOT EXISTS consumed_vouchers (
                        tenant_id TEXT NOT NULL,
                        nonce TEXT NOT NULL,
                        voucher_id TEXT NOT NULL,
                        consumed_at INTEGER NOT NULL,
                        PRIMARY KEY (tenant_id, nonce),
                        UNIQUE (tenant_id, voucher_id)
                    )
                """)
                db.commit()
        except sqlite3.Error:
            raise PermissionError("durable replay ledger unavailable") from None

    def consume(self, tenant_id: str, nonce: str, voucher_id: str, now: int) -> None:
        try:
            with sqlite3.connect(self._path, timeout=10, isolation_level=None) as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute(
                    "INSERT INTO consumed_vouchers (tenant_id, nonce, voucher_id, consumed_at) "
                    "VALUES (?, ?, ?, ?)",
                    (tenant_id, nonce, voucher_id, now),
                )
                db.commit()
        except sqlite3.IntegrityError:
            raise PermissionError("voucher replay detected") from None
        except sqlite3.Error:
            raise PermissionError("durable replay ledger unavailable") from None


class VoucherVerifier:
    """Validates voucher signature, allowlist, scope, time window and replay."""

    def __init__(
        self,
        secret: bytes,
        allowed_capabilities: set[str],
        *,
        replay_ledger=None,
        clock: Callable[[], int] = lambda: int(time.time()),
    ):
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("voucher secret must be at least 32 bytes")
        if not isinstance(allowed_capabilities, (set, frozenset)) or not allowed_capabilities:
            raise ValueError("capability allowlist must be non-empty")
        if any(not isinstance(item, str) or not item for item in allowed_capabilities):
            raise ValueError("capability allowlist entries must be non-empty strings")
        self._secret = secret
        self._allowed = frozenset(allowed_capabilities)
        self._clock = clock
        self._ledger = replay_ledger or MemoryReplayLedger()

    def verify_and_consume(self, voucher: CapabilityVoucher, request: ExecutionRequest) -> None:
        if not isinstance(voucher, CapabilityVoucher) or not isinstance(request, ExecutionRequest):
            raise PermissionError("voucher or request invalid")
        for name in ("run_id", "tenant_id", "principal_id", "capability", "policy_version"):
            _required_text(getattr(request, name), name)
            _required_text(getattr(voucher, name), f"voucher.{name}")
        if not isinstance(request.arguments, dict):
            raise PermissionError("request arguments invalid")
        try:
            arguments_digest = _digest(request.arguments)
        except (TypeError, ValueError, UnicodeError):
            raise PermissionError("request arguments invalid") from None
        if request.capability not in self._allowed or voucher.capability not in self._allowed:
            raise PermissionError("capability not allowlisted")
        if not isinstance(voucher.arguments_digest, str) or HEX64_RE.fullmatch(voucher.arguments_digest) is None:
            raise PermissionError("voucher arguments digest invalid")
        if HEX32_RE.fullmatch(voucher.voucher_id or "") is None or HEX32_RE.fullmatch(voucher.nonce or "") is None:
            raise PermissionError("voucher identifier or nonce invalid")
        if HEX64_RE.fullmatch(voucher.signature or "") is None:
            raise PermissionError("voucher signature encoding invalid")
        if type(voucher.issued_at) is not int or type(voucher.expires_at) is not int:
            raise PermissionError("voucher time fields invalid")
        if voucher.expires_at <= voucher.issued_at or voucher.expires_at - voucher.issued_at > MAX_VOUCHER_TTL_SECONDS:
            raise PermissionError("voucher lifetime invalid")

        body = {
            "voucher_id": voucher.voucher_id,
            "run_id": voucher.run_id,
            "tenant_id": voucher.tenant_id,
            "principal_id": voucher.principal_id,
            "capability": voucher.capability,
            "arguments_digest": voucher.arguments_digest,
            "policy_version": voucher.policy_version,
            "issued_at": voucher.issued_at,
            "expires_at": voucher.expires_at,
            "nonce": voucher.nonce,
        }
        expected = hmac.new(self._secret, _canonical(body), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, voucher.signature):
            raise PermissionError("voucher signature invalid")

        now = self._clock()
        if type(now) is not int:
            raise PermissionError("verifier clock invalid")
        if now < voucher.issued_at:
            raise PermissionError("voucher not yet valid")
        if now >= voucher.expires_at:
            raise PermissionError("voucher expired")

        expected_scope = [
            request.run_id, request.tenant_id, request.principal_id,
            request.capability, arguments_digest, request.policy_version,
        ]
        actual_scope = [
            voucher.run_id, voucher.tenant_id, voucher.principal_id,
            voucher.capability, voucher.arguments_digest, voucher.policy_version,
        ]
        if not hmac.compare_digest(_canonical(expected_scope), _canonical(actual_scope)):
            raise PermissionError("voucher scope mismatch")

        # Atomic consume before the effect. Production requires a shared durable
        # store with database-level uniqueness across every execution worker.
        self._ledger.consume(voucher.tenant_id, voucher.nonce, voucher.voucher_id, now)


class MockExecutor:
    """Contract-test executor; records an effect only after voucher verification."""

    def __init__(self, verifier: VoucherVerifier):
        self._verifier = verifier
        self.effects: list[dict] = []

    def execute(self, voucher: CapabilityVoucher, request: ExecutionRequest):
        self._verifier.verify_and_consume(voucher, request)
        effect = {
            "run_id": request.run_id,
            "tenant_id": request.tenant_id,
            "principal_id": request.principal_id,
            "capability": request.capability,
            "arguments_digest": _digest(request.arguments),
        }
        self.effects.append(effect)
        return {"status": "executed", **effect}
