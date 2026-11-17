"""Evidence Cryptography V4 storage-compatible primitives.

V4 stores its protocol metadata inside payload_json so the existing immutable
EvidenceRecord schema remains unchanged. V1/V2/V3 are delegated to a separately
maintained legacy verifier; this module never reinterprets their hashes.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Mapping

DOMAIN = "OLA-EVIDENCE-CHAIN-V4"
VERSION = 4
GENESIS_HASH = "0" * 64
KEYRING_ENV = "OLA_EVIDENCE_V4_KEYRING_JSON"
ACTIVE_KEY_ENV = "OLA_EVIDENCE_V4_ACTIVE_KEY_ID"
V2_META_KEY = "__ola_evidence_v2__"
V4_META_KEY = "__ola_evidence_v4__"
MAX_PAYLOAD_BYTES = 1_048_576
MAX_JSON_DEPTH = 32
MAX_KEYRING_ENTRIES = 32
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_TRUSTED_PRODUCER = "ola_runtime"
_PUBLIC_PRODUCER = "tenant_api"
_PRIVILEGED_PREFIXES = (
    "workflow.", "task.", "human.", "agent.", "provenance.", "decision.",
    "execution.", "verification.", "stripe.", "revenue.",
)


class EvidenceV4Error(ValueError):
    """Base class for fail-closed Evidence V4 errors."""


class MissingKeyError(EvidenceV4Error):
    pass


class UnknownKeyError(EvidenceV4Error):
    pass


class InvalidKeyringError(EvidenceV4Error):
    pass


class InvalidRecordError(EvidenceV4Error):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


@dataclass(frozen=True)
class Keyring:
    keys: Mapping[str, bytes] = field(repr=False)
    active_key_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.keys, Mapping) or not self.keys:
            raise InvalidKeyringError("empty V4 keyring")
        if len(self.keys) > MAX_KEYRING_ENTRIES:
            raise InvalidKeyringError("too many V4 keys")
        copied: dict[str, bytes] = {}
        for key_id, key in self.keys.items():
            if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
                raise InvalidKeyringError("invalid key_id")
            if not isinstance(key, bytes) or len(key) < 32:
                raise InvalidKeyringError("V4 keys must contain at least 256 bits")
            copied[key_id] = bytes(key)
        if not isinstance(self.active_key_id, str) or self.active_key_id not in copied:
            raise UnknownKeyError("active V4 key_id is not present in keyring")
        object.__setattr__(self, "keys", MappingProxyType(copied))


def load_keyring(environ: Mapping[str, str] | None = None) -> Keyring:
    env = os.environ if environ is None else environ
    raw = env.get(KEYRING_ENV)
    active = env.get(ACTIVE_KEY_ENV)
    if not raw or not active:
        raise MissingKeyError("V4 keyring and active key_id are required")
    try:
        parsed = json.loads(raw, object_pairs_hook=_unique_object)
    except (TypeError, ValueError, RecursionError) as exc:
        raise InvalidKeyringError("V4 keyring is invalid JSON or contains duplicate keys") from exc
    if not isinstance(parsed, dict) or not parsed or len(parsed) > MAX_KEYRING_ENTRIES:
        raise InvalidKeyringError("V4 keyring must be a non-empty object")
    keys: dict[str, bytes] = {}
    for key_id, encoded in parsed.items():
        if not isinstance(encoded, str):
            raise InvalidKeyringError("key material must be base64 text")
        try:
            keys[key_id] = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError) as exc:
            raise InvalidKeyringError("invalid base64 key material") from exc
    return Keyring(keys=keys, active_key_id=active)


def _check_depth(value: Any, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise InvalidRecordError("payload nesting limit exceeded")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise InvalidRecordError("payload object keys must be strings")
            _check_depth(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _check_depth(item, depth + 1)
    elif isinstance(value, float) and not math.isfinite(value):
        raise InvalidRecordError("non-finite JSON number")


def canonical_json(value: Any) -> str:
    _check_depth(value)
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise InvalidRecordError("payload is not canonicalizable JSON") from exc
    if len(encoded.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        raise InvalidRecordError("payload size limit exceeded")
    return encoded


def _is_privileged(record_type: str) -> bool:
    return record_type.startswith(_PRIVILEGED_PREFIXES)


def seal_payload_v4(
    record_type: str,
    payload: Mapping[str, Any],
    keyring: Keyring,
    *,
    producer: str = _TRUSTED_PRODUCER,
) -> str:
    """Create the storage envelope using the existing EvidenceRecord columns."""
    if not isinstance(record_type, str) or not record_type.strip():
        raise InvalidRecordError("record_type required")
    if not isinstance(payload, Mapping) or V2_META_KEY in payload or V4_META_KEY in payload:
        raise InvalidRecordError("payload must be an object without reserved evidence metadata")
    if producer not in (_TRUSTED_PRODUCER, _PUBLIC_PRODUCER):
        raise InvalidRecordError("unknown evidence producer")
    if _is_privileged(record_type) and producer != _TRUSTED_PRODUCER:
        raise InvalidRecordError("public producer may not write privileged evidence")
    value = dict(payload)
    value[V4_META_KEY] = {
        "version": VERSION,
        "key_id": keyring.active_key_id,
        "record_type": record_type,
        "producer": producer,
    }
    return canonical_json(value)


def _record_material(record: Mapping[str, Any]) -> tuple[bytes, str]:
    required = ("tenant_id", "seq", "prev_hash", "record_type", "payload_json")
    if any(name not in record for name in required):
        raise InvalidRecordError("missing V4 authenticated field")
    if not isinstance(record["tenant_id"], str) or not record["tenant_id"]:
        raise InvalidRecordError("tenant_id required")
    if type(record["seq"]) is not int or record["seq"] < 0:
        raise InvalidRecordError("invalid sequence")
    if not isinstance(record["prev_hash"], str) or not _HASH_RE.fullmatch(record["prev_hash"]):
        raise InvalidRecordError("invalid predecessor hash")
    record_type = record["record_type"]
    if not isinstance(record_type, str) or not record_type:
        raise InvalidRecordError("record_type required")
    payload_json = record["payload_json"]
    if not isinstance(payload_json, str) or len(payload_json.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        raise InvalidRecordError("invalid payload size")
    try:
        payload = json.loads(payload_json, object_pairs_hook=_unique_object)
    except (ValueError, RecursionError) as exc:
        raise InvalidRecordError(str(exc)) from exc
    if not isinstance(payload, dict):
        raise InvalidRecordError("V4 payload must be a JSON object")
    if V2_META_KEY in payload:
        raise InvalidRecordError("V4 payload may not contain legacy V2 metadata")
    if canonical_json(payload) != payload_json:
        raise InvalidRecordError("payload_json is not canonical")
    metadata = payload.get(V4_META_KEY)
    if not isinstance(metadata, dict) or set(metadata) != {"version", "key_id", "record_type", "producer"}:
        raise InvalidRecordError("V4 metadata is missing or malformed")
    if type(metadata["version"]) is not int or metadata["version"] != VERSION:
        raise InvalidRecordError("unsupported evidence version")
    key_id = metadata["key_id"]
    if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
        raise InvalidRecordError("invalid key_id")
    if metadata["record_type"] != record_type:
        raise InvalidRecordError("record type metadata mismatch")
    producer = metadata["producer"]
    if producer not in (_TRUSTED_PRODUCER, _PUBLIC_PRODUCER):
        raise InvalidRecordError("invalid evidence producer")
    if _is_privileged(record_type) and producer != _TRUSTED_PRODUCER:
        raise InvalidRecordError("public producer may not write privileged evidence")
    if "producer" in record and record["producer"] != producer:
        raise InvalidRecordError("producer metadata mismatch")
    envelope = {
        "domain": DOMAIN,
        "version": VERSION,
        "key_id": key_id,
        "tenant_id": record["tenant_id"],
        "seq": record["seq"],
        "prev_hash": record["prev_hash"],
        "record_type": record_type,
        "producer": producer,
        "payload_json": payload_json,
    }
    return canonical_json(envelope).encode("utf-8"), key_id


def sign_record(record: Mapping[str, Any], keyring: Keyring) -> str:
    """Return HMAC-SHA256 for a storage-shaped EvidenceRecord mapping."""
    material, key_id = _record_material(record)
    if key_id != keyring.active_key_id:
        raise InvalidRecordError("new V4 records must use the active key_id")
    return hmac.new(keyring.keys[key_id], material, hashlib.sha256).hexdigest()


def verify_record(record: Mapping[str, Any], keyring: Keyring) -> bool:
    """Verify the key named in the V4 payload envelope; no fallback is permitted."""
    if not isinstance(record, Mapping):
        raise InvalidRecordError("record must be an object")
    material, key_id = _record_material(record)
    key = keyring.keys.get(key_id)
    if key is None:
        raise UnknownKeyError("unknown V4 key_id")
    supplied = record.get("record_hash")
    if not isinstance(supplied, str) or not _HASH_RE.fullmatch(supplied):
        raise InvalidRecordError("invalid record_hash")
    expected = hmac.new(key, material, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, supplied)


def _stored_version(record: Mapping[str, Any]) -> int:
    try:
        payload = json.loads(record["payload_json"])
    except (KeyError, TypeError, ValueError, RecursionError) as exc:
        raise InvalidRecordError("invalid payload while resolving evidence version") from exc
    if not isinstance(payload, dict):
        raise InvalidRecordError("evidence payload must be an object")
    if V4_META_KEY in payload and V2_META_KEY in payload:
        raise InvalidRecordError("ambiguous legacy and V4 metadata")
    if V4_META_KEY in payload:
        meta = payload[V4_META_KEY]
        if not isinstance(meta, dict) or meta.get("version") != VERSION:
            raise InvalidRecordError("invalid V4 version metadata")
        return VERSION
    if V2_META_KEY in payload:
        meta = payload[V2_META_KEY]
        if not isinstance(meta, dict) or type(meta.get("version")) is not int:
            raise InvalidRecordError("invalid legacy version metadata")
        if meta["version"] not in (2, 3):
            raise InvalidRecordError("unsupported legacy version")
        return meta["version"]
    return 1


def verify_mixed_chain(
    records: list[Mapping[str, Any]],
    keyring: Keyring,
    *,
    legacy_verifier: Callable[..., tuple[bool, str]] | None = None,
) -> tuple[bool, str]:
    """Verify contiguous V1/V2/V3 and V4 segments without reinterpreting history.

    Legacy segments are passed intact to a separately maintained verifier.
    V4 records are checked here. Sequence and predecessor continuity span
    segment boundaries.
    """
    if not isinstance(records, list) or not records:
        return False, "empty evidence chain"
    expected_seq = 0
    expected_prev = GENESIS_HASH
    expected_tenant: str | None = None
    legacy_segment: list[Mapping[str, Any]] = []

    def flush_legacy() -> tuple[bool, str]:
        nonlocal legacy_segment
        if not legacy_segment:
            return True, "ok"
        if legacy_verifier is None:
            return False, "legacy verifier unavailable"
        segment = legacy_segment
        legacy_segment = []
        try:
            result = legacy_verifier(
                segment,
                start_seq=segment[0]["seq"],
                start_prev_hash=segment[0]["prev_hash"],
            )
        except Exception:
            return False, "legacy verifier raised an exception"
        if not isinstance(result, tuple) or len(result) != 2 or result[0] is not True:
            return False, "legacy verification failed"
        return True, str(result[1])

    for record in records:
        if not isinstance(record, Mapping):
            return False, "invalid record"
        tenant_id = record.get("tenant_id")
        if not isinstance(tenant_id, str) or not tenant_id:
            return False, "invalid tenant_id"
        if expected_tenant is None:
            expected_tenant = tenant_id
        elif tenant_id != expected_tenant:
            return False, "tenant boundary mismatch"
        if type(record.get("seq")) is not int or record["seq"] != expected_seq:
            return False, "sequence mismatch"
        if not isinstance(record.get("prev_hash"), str) or not _HASH_RE.fullmatch(record["prev_hash"]):
            return False, "invalid predecessor hash"
        if record["prev_hash"] != expected_prev:
            return False, "predecessor mismatch"
        if not isinstance(record.get("record_type"), str) or not record["record_type"]:
            return False, "invalid record_type"
        if not isinstance(record.get("payload_json"), str):
            return False, "invalid payload_json"
        try:
            version = _stored_version(record)
        except EvidenceV4Error as exc:
            return False, str(exc)
        if version == VERSION:
            ok, reason = flush_legacy()
            if not ok:
                return False, reason
            try:
                if not verify_record(record, keyring):
                    return False, "V4 authentication failed"
            except EvidenceV4Error as exc:
                return False, str(exc)
        elif version in (1, 2, 3):
            legacy_segment.append(record)
        else:
            return False, "unsupported evidence version"
        expected_prev = record.get("record_hash")
        if not isinstance(expected_prev, str) or not _HASH_RE.fullmatch(expected_prev):
            return False, "invalid record_hash"
        expected_seq += 1
    return flush_legacy()
