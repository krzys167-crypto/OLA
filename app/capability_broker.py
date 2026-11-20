"""Capability voucher prototype: scoped, integrity-protected, single-use authorization.

This module is a testable application-level enforcement primitive, not production
isolation. Production deployment requires a durable replay store and protected key
management; the in-memory ledger is intentionally suitable only for single-process
contract tests.
"""
from dataclasses import dataclass
import hashlib
import hmac
import json
import secrets
import time
from typing import Callable


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _digest(value) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


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
        if ttl_seconds <= 0 or ttl_seconds > 300:
            raise ValueError("voucher TTL must be between 1 and 300 seconds")
        self._secret = secret
        self._allowed = frozenset(allowed_capabilities)
        self._ttl = ttl_seconds

    def issue(self, request: ExecutionRequest, *, now: int | None = None) -> CapabilityVoucher:
        if not all((request.run_id, request.tenant_id, request.principal_id,
                    request.capability, request.policy_version)):
            raise ValueError("request identity and scope fields are required")
        if request.capability not in self._allowed:
            raise PermissionError("capability not allowlisted")
        issued = int(time.time() if now is None else now)
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


class VoucherVerifier:
    """Validates scope, integrity, expiry, and replay in a single-process ledger."""

    def __init__(self, secret: bytes, *, clock: Callable[[], int] = lambda: int(time.time())):
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("voucher secret must be at least 32 bytes")
        self._secret = secret
        self._clock = clock
        self._consumed: set[str] = set()

    def verify_and_consume(self, voucher: CapabilityVoucher, request: ExecutionRequest) -> None:
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
        if self._clock() >= voucher.expires_at:
            raise PermissionError("voucher expired")
        expected_scope = (
            request.run_id, request.tenant_id, request.principal_id,
            request.capability, _digest(request.arguments), request.policy_version,
        )
        actual_scope = (
            voucher.run_id, voucher.tenant_id, voucher.principal_id,
            voucher.capability, voucher.arguments_digest, voucher.policy_version,
        )
        if not hmac.compare_digest(_canonical(expected_scope), _canonical(actual_scope)):
            raise PermissionError("voucher scope mismatch")
        if voucher.voucher_id in self._consumed:
            raise PermissionError("voucher replay detected")
        # Consume before the effect. Durable atomic consumption is required in production.
        self._consumed.add(voucher.voucher_id)


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
