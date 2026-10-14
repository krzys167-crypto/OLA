"""Strict versioned OLA evidence record hashes (v2 candidate).

No migration, signing, anchoring or production runtime integration here.
A hash alone is not evidence of authenticity against an attacker able to
rewrite all data and recompute every link; an external signed anchor is required.
"""
import hashlib
import hmac
import json
import re

GENESIS_HASH = "0" * 64
DOMAIN = b"OLA-EVIDENCE-RECORD-V2\x00"
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
FIELDS = ("hash_version", "id", "tenant_id", "seq", "prev_hash", "record_type", "payload_json")


class InvalidRecord(ValueError):
    pass


def _reject_constant(value):
    raise InvalidRecord(f"non-finite JSON value: {value}")


def canonical_material(record):
    if not isinstance(record, dict):
        raise InvalidRecord("record must be an object")
    if any(k not in record for k in FIELDS):
        raise InvalidRecord("missing required evidence field")
    if type(record["hash_version"]) is not int or record["hash_version"] != 2:
        raise InvalidRecord("expected hash version 2")
    if type(record["seq"]) is not int or record["seq"] < 0:
        raise InvalidRecord("invalid sequence")
    for field in ("id", "tenant_id", "record_type"):
        if not isinstance(record[field], str) or not record[field].strip():
            raise InvalidRecord(f"invalid {field}")
    if not isinstance(record["prev_hash"], str) or not _SHA256.fullmatch(record["prev_hash"]):
        raise InvalidRecord("invalid predecessor hash")
    raw = record["payload_json"]
    if not isinstance(raw, str):
        raise InvalidRecord("payload must be a JSON string")
    try:
        payload = json.loads(raw, parse_constant=_reject_constant)
    except (json.JSONDecodeError, ValueError) as exc:
        raise InvalidRecord("invalid payload JSON") from exc
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    if raw != canonical:
        raise InvalidRecord("payload_json is not canonical")
    material = {name: record[name] for name in FIELDS}
    return json.dumps(material, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def compute_record_hash_v2(record):
    return hashlib.sha256(DOMAIN + canonical_material(record)).hexdigest()


def verify_chain_v2(records, *, expected_tenant_id, expected_count=None, expected_tip_hash=None, genesis_hash=GENESIS_HASH):
    if not isinstance(records, list) or not records:
        return False, "missing evidence"
    if not isinstance(expected_tenant_id, str) or not expected_tenant_id:
        return False, "expected tenant not supplied"
    if expected_count is not None and len(records) != expected_count:
        return False, "evidence count mismatch"
    if not isinstance(genesis_hash, str) or not _SHA256.fullmatch(genesis_hash):
        return False, "genesis hash invalid"
    expected_prev, seen_ids = genesis_hash, set()
    for index, record in enumerate(records):
        try:
            expected = compute_record_hash_v2(record)
        except (InvalidRecord, TypeError, OverflowError) as exc:
            return False, f"record schema invalid: {exc}"
        if record["seq"] != index or record["prev_hash"] != expected_prev:
            return False, "sequence/predecessor mismatch"
        if record["tenant_id"] != expected_tenant_id:
            return False, "tenant mismatch"
        if record["id"] in seen_ids:
            return False, "duplicate record id"
        seen_ids.add(record["id"])
        actual = record.get("record_hash")
        if not isinstance(actual, str) or not _SHA256.fullmatch(actual):
            return False, "record hash missing/invalid"
        if not hmac.compare_digest(expected, actual):
            return False, "record hash mismatch"
        expected_prev = actual
    if expected_tip_hash is not None and not hmac.compare_digest(expected_prev, expected_tip_hash):
        return False, "tip hash mismatch"
    return True, "ok"
