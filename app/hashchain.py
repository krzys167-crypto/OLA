import hashlib
import json

GENESIS_HASH = "0" * 64


def canonical_json(value):
    # allow_nan=False: NaN/Infinity are not JSON; a record that contains them cannot be read back by a strict
    # verifier (and GET /evidence/{id} would fail for ever).
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


HASH_V2 = "ola.chain/2"


def compute_record_hash(tenant_id, seq, prev_hash, payload_json, record_type=None):
    """v1 (record_type=None): sha256(tenant|seq|prev|payload) - does NOT cover the record type, kept so chains
    written before v2 still verify. v2 (record_type given): the type is hashed too, with a domain-separation tag,
    so a record cannot be retyped (a generic record re-labelled as identity.enroll) without breaking the chain.
    The type is length-prefixed, so no (type, payload) pair can be re-split into another one."""
    if record_type is None:
        material = f"{tenant_id}|{seq}|{prev_hash}|{payload_json}"
    else:
        material = f"{HASH_V2}|{tenant_id}|{seq}|{prev_hash}|{len(record_type)}:{record_type}|{payload_json}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def verify_chain(records):
    """Every record is accepted as v2 (type-bound) or as legacy v1, but v1 only BEFORE the first v2 record: once a
    chain has started to bind types it must keep doing so, so a record cannot be swapped for a v1 one to dodge
    the type binding. Legacy v1 records are not type-bound (documented limit); records are expected to carry
    `record_type` - a record without it can only be verified as v1."""
    expected_prev = GENESIS_HASH
    expected_seq = 0
    seen_v2 = False
    for r in records:
        if r["seq"] != expected_seq or r["prev_hash"] != expected_prev:
            return False, "sequence or predecessor mismatch"
        rt = r.get("record_type")
        v2 = compute_record_hash(r["tenant_id"], r["seq"], r["prev_hash"], r["payload_json"], rt) \
            if isinstance(rt, str) else None
        if v2 is not None and r["record_hash"] == v2:
            seen_v2 = True
        elif seen_v2 or r["record_hash"] != compute_record_hash(r["tenant_id"], r["seq"], r["prev_hash"],
                                                                 r["payload_json"]):
            return False, "record hash mismatch"
        expected_prev = r["record_hash"]
        expected_seq += 1
    return True, "ok"
