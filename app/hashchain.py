"""Versioned append-only evidence hashing.

Version 1 retained exclusively for pre-migration records and historical tests;
all new canonical writes explicitly use v2, which binds id and record_type.
A signed external tip anchor is still necessary against wholesale DB replacement.
"""
import hashlib
import json

from .hashchain_v2 import InvalidRecord, compute_record_hash_v2

GENESIS_HASH = "0" * 64


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_record_hash(tenant_id, seq, prev_hash, payload_json, *,
                        record_id=None, record_type=None, hash_version=1):
    if hash_version == 1:
        material = f"{tenant_id}|{seq}|{prev_hash}|{payload_json}".encode("utf-8")
        return hashlib.sha256(material).hexdigest()
    if hash_version != 2:
        raise ValueError("unsupported evidence hash version")
    if not record_id or not record_type:
        raise ValueError("v2 requires record id and type")
    return compute_record_hash_v2({
        "hash_version": 2,
        "id": record_id,
        "tenant_id": tenant_id,
        "seq": seq,
        "prev_hash": prev_hash,
        "record_type": record_type,
        "payload_json": payload_json,
    })


def verify_chain(records):
    expected_prev = GENESIS_HASH
    expected_seq = 0
    expected_tenant = None
    highest_version = 1
    seen_ids = set()
    for r in records:
        if not isinstance(r, dict):
            return False, "evidence record is not an object"
        if expected_tenant is None:
            expected_tenant = r.get("tenant_id")
        elif r.get("tenant_id") != expected_tenant:
            return False, "tenant boundary mismatch"
        if r.get("seq") != expected_seq or r.get("prev_hash") != expected_prev:
            return False, "sequence or predecessor mismatch"
        version = r.get("hash_version", 1)
        if type(version) is not int or version not in {1, 2}:
            return False, "unsupported evidence hash version"
        if version < highest_version:
            return False, "evidence hash version downgrade"
        highest_version = version
        if version == 2 and r.get("id") in seen_ids:
            return False, "duplicate evidence record id"
        try:
            expected = compute_record_hash(
                r["tenant_id"], r["seq"], r["prev_hash"], r["payload_json"],
                record_id=r.get("id"), record_type=r.get("record_type"),
                hash_version=version,
            )
        except (KeyError, TypeError, ValueError, InvalidRecord, OverflowError):
            return False, "evidence record schema invalid"
        if r.get("record_hash") != expected:
            return False, "record hash mismatch"
        if version == 2:
            seen_ids.add(r["id"])
        expected_prev = r["record_hash"]
        expected_seq += 1
    return True, "ok"
