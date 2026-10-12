"""Regression: cross-tenant evidence must not form a single VERIFIED chain."""
from app.hashchain import GENESIS_HASH, compute_record_hash, verify_chain


def record(tenant, seq, previous):
    payload = '{"event":"example"}'
    return {
        "tenant_id": tenant, "seq": seq, "prev_hash": previous,
        "payload_json": payload,
        "record_hash": compute_record_hash(tenant, seq, previous, payload),
    }


def test_mixed_tenant_chain_is_rejected_even_when_hashes_match():
    first = record("tenant-A", 0, GENESIS_HASH)
    second = record("tenant-B", 1, first["record_hash"])
    valid, reason = verify_chain([first, second])
    assert not valid
    assert reason == "tenant boundary mismatch"


def test_same_tenant_chain_is_valid():
    first = record("tenant-A", 0, GENESIS_HASH)
    second = record("tenant-A", 1, first["record_hash"])
    valid, reason = verify_chain([first, second])
    assert valid, reason
