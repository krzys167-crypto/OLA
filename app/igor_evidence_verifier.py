"""Independent evidence verifier for IGOR.

This module intentionally does not import app.hashchain or app.evidence_v4.
It independently implements the historical V1/V2/V3 readers and the V4
storage-envelope contract. It is read-only and never signs evidence.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import re
from typing import Any, Mapping

GENESIS_HASH = "0" * 64
V2_META_KEY = "__ola_evidence_v2__"
V4_META_KEY = "__ola_evidence_v4__"
V4_DOMAIN = "OLA-EVIDENCE-CHAIN-V4"
V3_DOMAIN = "OLA-EVIDENCE-CHAIN-V3"
V2_DOMAIN = "OLA-EVIDENCE-CHAIN-V2"
V3_PEPPER_ENV = "OLA_API_KEY_PEPPER"
V4_KEYRING_ENV = "OLA_EVIDENCE_V4_KEYRING_JSON"
V4_ACTIVE_KEY_ENV = "OLA_EVIDENCE_V4_ACTIVE_KEY_ID"
MAX_PAYLOAD_BYTES = 1_048_576
MAX_JSON_DEPTH = 32
MAX_KEYRING_ENTRIES = 32
KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
TRUSTED_PRODUCER = "ola_runtime"
PUBLIC_PRODUCER = "tenant_api"
PRIVILEGED_PREFIXES = (
    "workflow.", "task.", "human.", "agent.", "provenance.", "decision.",
    "execution.", "verification.", "stripe.", "revenue.",
)


class IndependentEvidenceError(ValueError):
    pass


def _reject_duplicate_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    )


def _depth(value, level=0):
    if level > MAX_JSON_DEPTH:
        raise IndependentEvidenceError("payload depth limit exceeded")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise IndependentEvidenceError("non-string JSON member")
            _depth(item, level + 1)
    elif isinstance(value, list):
        for item in value:
            _depth(item, level + 1)
    elif isinstance(value, float) and not math.isfinite(value):
        raise IndependentEvidenceError("non-finite JSON number")


def _json_object(raw, *, strict=False):
    if not isinstance(raw, str):
        raise IndependentEvidenceError("invalid payload_json")
    if strict and len(raw.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        raise IndependentEvidenceError("V4 payload size limit exceeded")
    try:
        if strict:
            value = json.loads(raw, object_pairs_hook=_reject_duplicate_members)
        else:
            value = json.loads(raw)
    except (TypeError, ValueError, RecursionError) as exc:
        raise IndependentEvidenceError("invalid payload_json") from exc
    if not isinstance(value, dict):
        raise IndependentEvidenceError("payload must be an object")
    if strict:
        _depth(value)
        if _canonical(value) != raw:
            raise IndependentEvidenceError("V4 payload is not canonical")
    return value


def _keyring(environ):
    raw = environ.get(V4_KEYRING_ENV, "")
    active = environ.get(V4_ACTIVE_KEY_ENV, "")
    if not raw or not active:
        raise IndependentEvidenceError("V4 keyring unavailable")
    try:
        encoded_keys = json.loads(raw, object_pairs_hook=_reject_duplicate_members)
    except (TypeError, ValueError) as exc:
        raise IndependentEvidenceError("invalid V4 keyring JSON") from exc
    if not isinstance(encoded_keys, dict) or not encoded_keys or len(encoded_keys) > MAX_KEYRING_ENTRIES:
        raise IndependentEvidenceError("invalid V4 keyring size")
    keys = {}
    for key_id, encoded in encoded_keys.items():
        if not isinstance(key_id, str) or not KEY_ID_PATTERN.fullmatch(key_id):
            raise IndependentEvidenceError("invalid V4 key identifier")
        if not isinstance(encoded, str):
            raise IndependentEvidenceError("invalid V4 key encoding")
        try:
            key = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError) as exc:
            raise IndependentEvidenceError("invalid V4 key encoding") from exc
        if len(key) < 32:
            raise IndependentEvidenceError("V4 key shorter than 256 bits")
        keys[key_id] = key
    if active not in keys:
        raise IndependentEvidenceError("active V4 key is absent")
    return keys


def _legacy_metadata(payload, record):
    meta = payload.get(V2_META_KEY)
    if meta is None:
        return 1, None
    if not isinstance(meta, dict) or set(meta) != {"version", "record_type", "producer"}:
        raise IndependentEvidenceError("legacy evidence metadata malformed")
    version = meta["version"]
    if type(version) is not int or version not in (2, 3):
        raise IndependentEvidenceError("unsupported legacy evidence version")
    if meta["record_type"] != record.get("record_type"):
        raise IndependentEvidenceError("legacy record type binding mismatch")
    producer = meta["producer"]
    if producer not in (TRUSTED_PRODUCER, PUBLIC_PRODUCER):
        raise IndependentEvidenceError("legacy producer invalid")
    if is_privileged_type(record.get("record_type")) and producer != TRUSTED_PRODUCER:
        raise IndependentEvidenceError("untrusted producer on privileged record")
    return version, producer


def is_privileged_type(record_type):
    return isinstance(record_type, str) and record_type.startswith(PRIVILEGED_PREFIXES)


def _legacy_digest(record, payload, version, producer, environ):
    tenant = record["tenant_id"]
    seq = record["seq"]
    previous = record["prev_hash"]
    record_type = record["record_type"]
    payload_json = record["payload_json"]
    if version == 1:
        material = f"{tenant}|{seq}|{previous}|{payload_json}".encode("utf-8")
        return hashlib.sha256(material).hexdigest()
    common = {
        "tenant_id": tenant,
        "seq": seq,
        "prev_hash": previous,
        "record_type": record_type,
        "producer": producer,
        "payload_json": payload_json,
    }
    if version == 2:
        material = _canonical({"domain": V2_DOMAIN, **common}).encode("utf-8")
        return hashlib.sha256(material).hexdigest()
    pepper = environ.get(V3_PEPPER_ENV, "")
    if not isinstance(pepper, str) or len(pepper.encode("utf-8")) < 32:
        raise IndependentEvidenceError("historical V3 pepper unavailable")
    derived_key = hmac.new(
        pepper.encode("utf-8"), b"OLA-EVIDENCE-CHAIN-KEY-V3", hashlib.sha256
    ).digest()
    material = _canonical({"domain": V3_DOMAIN, **common}).encode("utf-8")
    return hmac.new(derived_key, material, hashlib.sha256).hexdigest()


def _v4_digest(record, payload, environ):
    if V2_META_KEY in payload:
        raise IndependentEvidenceError("V4 payload contains legacy V2 metadata")
    metadata = payload.get(V4_META_KEY)
    if not isinstance(metadata, dict) or set(metadata) != {"version", "key_id", "record_type", "producer"}:
        raise IndependentEvidenceError("V4 metadata malformed")
    if type(metadata["version"]) is not int or metadata["version"] != 4:
        raise IndependentEvidenceError("unsupported V4 version")
    key_id = metadata["key_id"]
    if not isinstance(key_id, str) or not KEY_ID_PATTERN.fullmatch(key_id):
        raise IndependentEvidenceError("invalid V4 key_id")
    if metadata["record_type"] != record.get("record_type"):
        raise IndependentEvidenceError("V4 record type binding mismatch")
    producer = metadata["producer"]
    if producer not in (TRUSTED_PRODUCER, PUBLIC_PRODUCER):
        raise IndependentEvidenceError("V4 producer invalid")
    if is_privileged_type(record.get("record_type")) and producer != TRUSTED_PRODUCER:
        raise IndependentEvidenceError("untrusted V4 producer on privileged record")
    keys = _keyring(environ)
    key = keys.get(key_id)
    if key is None:
        raise IndependentEvidenceError("unknown V4 key_id")
    envelope = {
        "domain": V4_DOMAIN,
        "version": 4,
        "key_id": key_id,
        "tenant_id": record["tenant_id"],
        "seq": record["seq"],
        "prev_hash": record["prev_hash"],
        "record_type": record["record_type"],
        "producer": producer,
        "payload_json": record["payload_json"],
    }
    material = _canonical(envelope).encode("utf-8")
    if len(material) > MAX_PAYLOAD_BYTES:
        raise IndependentEvidenceError("V4 authenticated material exceeds size limit")
    return hmac.new(key, material, hashlib.sha256).hexdigest()


def evidence_version(record):
    payload = _json_object(record.get("payload_json"), strict=False)
    if V4_META_KEY in payload and V2_META_KEY in payload:
        raise IndependentEvidenceError("ambiguous evidence version metadata")
    if V4_META_KEY in payload:
        meta = payload[V4_META_KEY]
        if not isinstance(meta, dict) or type(meta.get("version")) is not int or meta["version"] != 4:
            raise IndependentEvidenceError("invalid V4 metadata")
        return 4
    version, _ = _legacy_metadata(payload, record)
    return version


def verify_chain(records, environ=None):
    env = os.environ if environ is None else environ
    if not isinstance(records, (list, tuple)) or not records:
        return False, "empty evidence chain"
    expected_prev = GENESIS_HASH
    expected_seq = 0
    expected_tenant = None
    try:
        for record in records:
            if not isinstance(record, Mapping):
                return False, "record must be an object"
            tenant = record.get("tenant_id")
            if not isinstance(tenant, str) or not tenant:
                return False, "tenant_id invalid"
            if expected_tenant is None:
                expected_tenant = tenant
            elif tenant != expected_tenant:
                return False, "tenant boundary mismatch"
            seq = record.get("seq")
            if type(seq) is not int or seq != expected_seq:
                return False, "sequence mismatch"
            previous = record.get("prev_hash")
            if not isinstance(previous, str) or not HASH_PATTERN.fullmatch(previous):
                return False, "predecessor hash malformed"
            if previous != expected_prev:
                return False, "predecessor mismatch"
            record_type = record.get("record_type")
            if not isinstance(record_type, str) or not record_type:
                return False, "record_type invalid"
            supplied = record.get("record_hash")
            if not isinstance(supplied, str) or not HASH_PATTERN.fullmatch(supplied):
                return False, "record_hash malformed"
            payload = _json_object(record.get("payload_json"), strict=False)
            version = evidence_version(record)
            if version == 4:
                payload = _json_object(record["payload_json"], strict=True)
                expected = _v4_digest(record, payload, env)
            else:
                version, producer = _legacy_metadata(payload, record)
                expected = _legacy_digest(record, payload, version, producer, env)
            if not hmac.compare_digest(expected, supplied):
                return False, "record hash mismatch"
            expected_prev = supplied
            expected_seq += 1
        return True, "ok"
    except IndependentEvidenceError as exc:
        # Preserve bounded, verifier-authored diagnostics for auditability.
        # Parser and runtime exceptions remain deliberately non-descriptive.
        return False, str(exc)
    except (TypeError, KeyError, ValueError, OverflowError, RecursionError):
        return False, "evidence verification failed closed"


def trusted_record(record):
    """Trust policy only; caller must first verify the complete tenant chain."""
    try:
        payload = _json_object(record.get("payload_json"), strict=False)
        if V4_META_KEY in payload:
            if V2_META_KEY in payload:
                return False
            meta = payload[V4_META_KEY]
            version = meta.get("version") if isinstance(meta, dict) else None
            producer = meta.get("producer") if isinstance(meta, dict) else None
            bound_type = meta.get("record_type") if isinstance(meta, dict) else None
            return (
                type(version) is int and version == 4
                and bound_type == record.get("record_type")
                and producer == TRUSTED_PRODUCER
                and is_privileged_type(record.get("record_type"))
            )
        version, producer = _legacy_metadata(payload, record)
        return (
            version in (2, 3)
            and producer == TRUSTED_PRODUCER
            and is_privileged_type(record.get("record_type"))
        )
    except (IndependentEvidenceError, TypeError, KeyError, ValueError):
        return False
