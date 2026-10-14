import json

import pytest

from app import hashchain_v2 as h


def make(seq=0, previous=h.GENESIS_HASH, id="r-1", record_type="fault.detected", tenant="tenant-a"):
    r = {
        "hash_version": 2,
        "id": id,
        "tenant_id": tenant,
        "seq": seq,
        "prev_hash": previous,
        "record_type": record_type,
        "payload_json": json.dumps({"value": 1}, sort_keys=True, separators=(",", ":")),
    }
    r["record_hash"] = h.compute_record_hash_v2(r)
    return r


def test_valid_two_record_chain():
    r1 = make()
    r2 = make(1, r1["record_hash"], id="r-2")
    assert h.verify_chain_v2(
        [r1, r2], expected_tenant_id="tenant-a", expected_count=2,
        expected_tip_hash=r2["record_hash"],
    ) == (True, "ok")


@pytest.mark.parametrize("field,replacement", [
    ("record_type", "verification.passed"),
    ("id", "forged-id"),
    ("tenant_id", "tenant-b"),
    ("payload_json", '{"value":2}'),
    ("hash_version", 1),
])
def test_mutated_fields_block_without_rehash(field, replacement):
    r = make()
    r[field] = replacement
    assert h.verify_chain_v2([r], expected_tenant_id="tenant-a")[0] is False


def test_missing_schema_version_fails_closed():
    r = make()
    del r["hash_version"]
    assert h.verify_chain_v2([r], expected_tenant_id="tenant-a")[0] is False


def test_duplicate_ids_fails_even_when_rehashed():
    r1 = make()
    r2 = make(1, r1["record_hash"])
    assert h.verify_chain_v2([r1, r2], expected_tenant_id="tenant-a") == (False, "duplicate record id")


def test_wrong_record_order_and_tip_hash():
    r1 = make()
    r2 = make(1, r1["record_hash"], id="r-2")
    assert h.verify_chain_v2([r2, r1], expected_tenant_id="tenant-a")[0] is False
    assert h.verify_chain_v2(
        [r1, r2], expected_tenant_id="tenant-a", expected_tip_hash="f" * 64
    )[0] is False


def test_canonical_json_and_invalid_numbers_rejected():
    r = make()
    r["payload_json"] = '{"z":2, "a":1}'
    with pytest.raises(h.InvalidRecord):
        h.compute_record_hash_v2(r)
    r["payload_json"] = '{"value":NaN}'
    with pytest.raises(h.InvalidRecord):
        h.compute_record_hash_v2(r)


def test_empty_chain_and_count_fail_closed():
    assert h.verify_chain_v2([], expected_tenant_id="tenant-a")[0] is False
    assert h.verify_chain_v2([make()], expected_tenant_id="tenant-a", expected_count=2)[0] is False
