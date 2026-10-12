import hashlib
import json

GENESIS_HASH = "0" * 64


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_record_hash(tenant_id, seq, prev_hash, payload_json):
    material = f"{tenant_id}|{seq}|{prev_hash}|{payload_json}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def verify_chain(records):
    expected_prev = GENESIS_HASH
    expected_seq = 0
    expected_tenant = None
    for r in records:
        if expected_tenant is None:
            expected_tenant = r["tenant_id"]
        elif r["tenant_id"] != expected_tenant:
            return False, "tenant boundary mismatch"
        if r["seq"] != expected_seq or r["prev_hash"] != expected_prev:
            return False, "sequence or predecessor mismatch"
        expected = compute_record_hash(r["tenant_id"], r["seq"], r["prev_hash"], r["payload_json"])
        if r["record_hash"] != expected:
            return False, "record hash mismatch"
        expected_prev = r["record_hash"]
        expected_seq += 1
    return True, "ok"
