"""Per-agent and per-approver identity for the Agent Firewall: Ed25519 signed requests against a key registry
that lives in the tenant evidence chain.

Why: before this, `agent_id` and `approver_id` were strings asserted by whoever held the tenant API key, so
"an agent cannot approve its own action" only stopped the same string doing both. Here a principal is a PUBLIC
KEY enrolled in the chain; a request counts as coming from it only if it carries a valid signature.

Model (all state is derived from the tenant chain; nothing is cached)
    identity.enroll   principal_id, role (agent | approver | runner | witness), public_key (Ed25519, 32 bytes hex)
    identity.revoke   principal_id, reason_sha256
    signed request    {schema, tenant_id, purpose, principal_id, subject_sha256, ts, nonce} signed over its canonical
                      JSON. `subject_sha256` binds the signature to the exact thing being authorised (the action
                      digest, the consume target, the approval reason), `ts` bounds replay in time, `nonce` is
                      single-use per principal.

Rules (each has a test)
* A public key can belong to ONE principal, ever. A principal id is never reused, not even after revocation. So the
  approver key cannot be an agent key, and a revoked key cannot come back under another name.
* Small-order public keys are refused at enrolment (their signatures are forgeable).
* Unknown, revoked or wrong-role principal, bad signature, stale/future timestamp, reused nonce -> denied (401).
* Mode `OLA_FIREWALL_AGENT_AUTH`: `off` (default) = unsigned requests still work and are recorded as
  `identity: asserted`; a signature that IS supplied is always verified (a bad one is 401, never ignored).
  `required` = every authorize / approve / consume must be signed, and a decision that was not made by a verified
  agent can be neither approved nor consumed. Any other value is a 503, not "off".
* Enrolment. With `OLA_IDENTITY_ENROLL_TOKEN_SHA256` set (sha256 hex of an operator token), enrol/revoke also need
  the header `X-Enroll-Token`. In `required` mode without that variable enrolment is disabled (503): otherwise an
  agent that holds the tenant API key could enrol itself as its own approver.

HONEST LIMITS
* The enrolment token / tenant API key is still the root of trust. Whoever holds both can enrol any key. This
  separates agents (private key only) from operators (token), it is not an identity provider and does not prove an
  approver is a person.
* The nonce check is a scan before the write. Two concurrent identical requests can both pass it; the single-permit
  and one-approval rules of the firewall still hold, which is what makes that harmless. Defense in depth, not a lock.
* Private keys are the caller's problem: this module never stores one. `generate_keypair` and `sign_request` are
  client helpers (tests, scripts), not a key-management system.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import pipeline_bridge as pb
from .ed25519_point import is_prime_order_point
from .hashchain import canonical_json, verify_chain

SCHEMA = "ola.identity/1"
REQUEST_SCHEMA = "ola.identity.request/1"
ENROLL_TYPE, REVOKE_TYPE = "identity.enroll", "identity.revoke"
ROLES = ("agent", "approver", "runner", "witness")
PURPOSES = ("firewall.authorize", "firewall.approve", "firewall.consume", "cfr.result", "cfr.witness")
MAX_PRINCIPALS = 256
DEFAULT_SKEW_S = 300

_ID = re.compile(r"^[A-Za-z0-9_.:@-]{1,64}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_HEX128 = re.compile(r"^[0-9a-fA-F]{128}$")

# The eight points of order dividing 8 on Edwards25519 (RFC 8032 section 5.1 encodings, canonical forms).
SMALL_ORDER_KEYS = frozenset(bytes.fromhex(h) for h in (
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
))


class IdentityError(ValueError):
    """Malformed input (HTTP 400)."""


class IdentityDenied(PermissionError):
    """The request is not proven to come from an enrolled, active principal (HTTP 401)."""


class IdentityConflict(RuntimeError):
    """The registry does not allow this change (HTTP 409)."""


class IdentityUnavailable(RuntimeError):
    """Misconfiguration, or the chain cannot be read/verified (HTTP 503)."""


def _sha(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def auth_mode() -> str:
    mode = os.getenv("OLA_FIREWALL_AGENT_AUTH", "").strip().lower()
    if mode in ("", "off"):
        return "off"
    if mode == "required":
        return "required"
    raise IdentityUnavailable("OLA_FIREWALL_AGENT_AUTH must be 'off' or 'required'")


def _skew() -> int:
    try:
        return pb._int_env("OLA_IDENTITY_MAX_SKEW_S", DEFAULT_SKEW_S)
    except pb.PipelineNotConfigured as exc:
        raise IdentityUnavailable(str(exc)) from exc


def _now() -> float:
    return time.time()


# ------------------------------------------------------------------ client helpers (tests, scripts)
def generate_keypair() -> Tuple[str, str]:
    """(private seed hex, public key hex). The caller keeps the private half; this module never stores it."""
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return seed.hex(), pub.hex()


def request_message(tenant_id: str, purpose: str, principal_id: str, subject_sha256: str, ts: float, nonce: str) -> bytes:
    return canonical_json({"schema": REQUEST_SCHEMA, "tenant_id": tenant_id, "purpose": purpose,
                           "principal_id": principal_id, "subject_sha256": subject_sha256, "ts": ts,
                           "nonce": nonce}).encode("utf-8")


def sign_request(seed_hex: str, tenant_id: str, purpose: str, principal_id: str, subject_sha256: str,
                 ts: Optional[float] = None, nonce: Optional[str] = None) -> Dict[str, Any]:
    ts = _now() if ts is None else ts
    nonce = nonce or secrets.token_urlsafe(18)
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    sig = key.sign(request_message(tenant_id, purpose, principal_id, subject_sha256, ts, nonce))
    return {"ts": ts, "nonce": nonce, "signature": sig.hex()}


# ------------------------------------------------------------------ registry (derived from the chain)
def _payloads(chain: List[dict], types: Tuple[str, ...]):
    for rec in chain:
        if rec["record_type"] in types:
            try:
                p = json.loads(rec["payload_json"])
            except ValueError:
                continue
            if isinstance(p, dict):
                yield rec, p


def registry(chain: List[dict]) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    """principal_id -> entry, public_key_hex -> principal_id. First enrolment of an id or a key wins; a later record
    that tries to reuse either is ignored when reading (enrol() never writes one)."""
    reg: Dict[str, Dict[str, Any]] = {}
    keys: Dict[str, str] = {}
    for rec, p in _payloads(chain, (ENROLL_TYPE, REVOKE_TYPE)):
        if p.get("schema") != SCHEMA:
            continue
        pid = p.get("principal_id")
        if rec["record_type"] == ENROLL_TYPE:
            pub, role = p.get("public_key"), p.get("role")
            if pid in reg or pub in keys or role not in ROLES or not isinstance(pub, str):
                continue
            reg[pid] = {"principal_id": pid, "role": role, "public_key": pub, "status": "active",
                        "enroll_seq": rec["seq"], "revoked_seq": None}
            keys[pub] = pid
        elif pid in reg and reg[pid]["status"] == "active":
            reg[pid]["status"], reg[pid]["revoked_seq"] = "revoked", rec["seq"]
    return reg, keys


def _chain(tenant_id: str) -> List[dict]:
    try:
        chain = pb.load_chain(tenant_id)
    except Exception as exc:                                         # noqa: BLE001 - fail closed
        raise IdentityUnavailable(f"evidence could not be read ({type(exc).__name__})") from exc
    ok, why = verify_chain(chain)
    if not ok:
        raise IdentityUnavailable(f"the tenant evidence chain does not verify ({why})")
    return chain


def principals(tenant_id: str) -> List[Dict[str, Any]]:
    reg, _ = registry(_chain(tenant_id))
    return [{k: v for k, v in e.items()} for e in sorted(reg.values(), key=lambda e: e["enroll_seq"])]


# ------------------------------------------------------------------ enrolment
def _check_enroll_token(token: Any) -> None:
    configured = os.getenv("OLA_IDENTITY_ENROLL_TOKEN_SHA256", "").strip().lower()
    if not configured:
        if auth_mode() == "required":
            raise IdentityUnavailable("enrolment is disabled: set OLA_IDENTITY_ENROLL_TOKEN_SHA256 "
                                      "(sha256 hex of an operator token) when OLA_FIREWALL_AGENT_AUTH=required")
        return
    if not _HEX64.fullmatch(configured):
        raise IdentityUnavailable("OLA_IDENTITY_ENROLL_TOKEN_SHA256 must be 64 hex characters")
    given = hashlib.sha256(token.encode("utf-8")).hexdigest() if isinstance(token, str) and token else ""
    if not hmac.compare_digest(given, configured):
        raise IdentityDenied("a valid enrolment token is required")


def _public_key_bytes(value: Any) -> bytes:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise IdentityError("public_key must be 64 hex characters (an Ed25519 public key)")
    raw = bytes.fromhex(value)
    if raw in SMALL_ORDER_KEYS:
        raise IdentityError("public_key is a small-order point and is refused")
    if not is_prime_order_point(raw):
        # non-canonical encodings of small-order points (they verify a universal forgery) and keys with a torsion
        # component (A + T: one secret behind two different keys) are not keys of one principal
        raise IdentityError("public_key must be a canonical encoding of a point of the prime-order subgroup "
                            "(small-order, non-canonical and torsion keys are refused)")
    try:
        Ed25519PublicKey.from_public_bytes(raw)
    except Exception as exc:                                         # noqa: BLE001
        raise IdentityError("public_key is not a valid Ed25519 public key") from exc
    return raw


def _append(tenant_id: str, rtype: str, payload: dict) -> dict:
    try:
        return pb.append_evidence(tenant_id, rtype, payload)
    except Exception as exc:                                         # noqa: BLE001 - no record, no change
        raise IdentityUnavailable(f"the change could not be recorded ({type(exc).__name__})") from exc


def enroll(tenant_id: str, principal_id: Any, role: Any, public_key: Any, token: Any = None) -> Dict[str, Any]:
    _check_enroll_token(token)
    if not isinstance(principal_id, str) or not _ID.fullmatch(principal_id):
        raise IdentityError("principal_id must match [A-Za-z0-9_.:@-]{1,64}")
    if role not in ROLES:
        raise IdentityError("role must be 'agent', 'approver', 'runner' or 'witness'")
    raw = _public_key_bytes(public_key)
    pub = raw.hex()
    reg, keys = registry(_chain(tenant_id))
    if principal_id in reg:
        raise IdentityConflict("this principal id was already enrolled (ids are never reused; rotate with a new id)")
    if pub in keys:
        raise IdentityConflict("this public key already belongs to another principal")
    if len(reg) >= MAX_PRINCIPALS:
        raise IdentityConflict(f"at most {MAX_PRINCIPALS} principals per tenant")
    rec = _append(tenant_id, ENROLL_TYPE, {"schema": SCHEMA, "principal_id": principal_id, "role": role,
                                           "public_key": pub, "key_sha256": hashlib.sha256(raw).hexdigest(),
                                           "enrolled_at": _now()})
    # first enrolment of an id / key wins a race, exactly as registry() reads it
    reg2, keys2 = registry(_chain(tenant_id))
    if reg2.get(principal_id, {}).get("enroll_seq") != rec["seq"] or keys2.get(pub) != principal_id:
        raise IdentityConflict("another enrolment of this principal or key was recorded first")
    return {"principal_id": principal_id, "role": role, "key_sha256": hashlib.sha256(raw).hexdigest(),
            "status": "active", "evidence_seq": rec["seq"]}


def revoke(tenant_id: str, principal_id: Any, reason: Any, token: Any = None) -> Dict[str, Any]:
    _check_enroll_token(token)
    if not isinstance(principal_id, str) or not _ID.fullmatch(principal_id):
        raise IdentityError("principal_id must match [A-Za-z0-9_.:@-]{1,64}")
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 1000:
        raise IdentityError("reason is required (1-1000 characters)")
    reg, _ = registry(_chain(tenant_id))
    e = reg.get(principal_id)
    if e is None:
        raise IdentityConflict("no such principal")
    if e["status"] != "active":
        raise IdentityConflict("this principal is already revoked")
    rec = _append(tenant_id, REVOKE_TYPE, {"schema": SCHEMA, "principal_id": principal_id,
                                           "reason_sha256": hashlib.sha256(reason.encode("utf-8")).hexdigest(),
                                           "revoked_at": _now()})
    return {"principal_id": principal_id, "status": "revoked", "evidence_seq": rec["seq"]}


# ------------------------------------------------------------------ verification of a signed request
def _num(v: Any) -> bool:
    if not isinstance(v, (int, float)) or isinstance(v, bool):
        return False
    try:
        return math.isfinite(v)
    except OverflowError:                                  # an int beyond float range (10**400): refused, never a 500
        return False


def nonce_used(chain: List[dict], principal_id: str, nonce: str) -> bool:
    for _, p in _payloads(chain, ("firewall.decision", "firewall.approval", "firewall.execution", "cfr.result", "cfr.witness")):
        a = p.get("auth")
        if isinstance(a, dict) and a.get("principal_id") == principal_id and a.get("nonce") == nonce:
            return True
    return False


def duplicate_nonce_seqs(chain: List[dict]) -> set:
    """Seqs of records that reuse a (principal, nonce) already carried by a LOWER seq. Two requests with the same
    nonce can both pass nonce_used() when they read the chain before either appended; the chain order decides:
    the first record owns the nonce, every later one is void."""
    first: Dict[Tuple[str, str], int] = {}
    void = set()
    for rec, p in _payloads(chain, ("firewall.decision", "firewall.approval", "firewall.execution",
                                    "cfr.result", "cfr.witness")):
        a = p.get("auth")
        if isinstance(a, dict) and isinstance(a.get("principal_id"), str) and isinstance(a.get("nonce"), str):
            k = (a["principal_id"], a["nonce"])
            if k in first and first[k] != rec["seq"]:
                void.add(rec["seq"])
            else:
                first.setdefault(k, rec["seq"])
    return void


def verify(chain: List[dict], tenant_id: str, purpose: str, principal_id: str, role: str, subject_sha256: str,
           auth: Any) -> Dict[str, Any]:
    """Raise IdentityDenied unless `auth` proves that `principal_id` (active, with this role) signed exactly
    this purpose and subject recently and for the first time. `chain` must already be verified."""
    if purpose not in PURPOSES:
        raise IdentityError("unknown purpose")
    if not isinstance(auth, dict):
        raise IdentityDenied("a signed request is required (auth.ts, auth.nonce, auth.signature)")
    ts, nonce, sig = auth.get("ts"), auth.get("nonce"), auth.get("signature")
    if not _num(ts) or not isinstance(nonce, str) or not _NONCE.fullmatch(nonce) \
            or not isinstance(sig, str) or not _HEX128.fullmatch(sig):
        raise IdentityDenied("auth must carry a numeric ts, a 16-64 character nonce and a 128-hex signature")
    if abs(_now() - float(ts)) > _skew():
        raise IdentityDenied("the signed timestamp is outside the allowed clock skew")
    reg, _ = registry(chain)
    entry = reg.get(principal_id)
    if entry is None:
        raise IdentityDenied("unknown principal")
    if entry["status"] != "active":
        raise IdentityDenied("this principal is revoked")
    if entry["role"] != role:
        raise IdentityDenied(f"this principal is not enrolled as '{role}'")
    raw = bytes.fromhex(entry["public_key"])
    if not is_prime_order_point(raw):                       # a record enrolled before this check: never trusted
        raise IdentityDenied("the enrolled public key is not a valid prime-order Ed25519 key")
    try:
        Ed25519PublicKey.from_public_bytes(raw).verify(
            bytes.fromhex(sig), request_message(tenant_id, purpose, principal_id, subject_sha256, ts, nonce))
    except (InvalidSignature, ValueError):
        raise IdentityDenied("the signature does not verify for this principal, purpose and subject") from None
    if nonce_used(chain, principal_id, nonce):
        raise IdentityDenied("this nonce was already used")
    return {"principal_id": principal_id, "role": role, "key_sha256": hashlib.sha256(raw).hexdigest(),
            "nonce": nonce, "ts": float(ts), "signature_sha256": hashlib.sha256(bytes.fromhex(sig)).hexdigest()}
