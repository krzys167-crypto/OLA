import base64
import hashlib
import hmac
import json
from pathlib import Path

import pytest

from app.evidence_v4 import (
    ACTIVE_KEY_ENV, KEYRING_ENV, GENESIS_HASH, MAX_JSON_DEPTH, MAX_PAYLOAD_BYTES,
    V2_META_KEY, V4_META_KEY,
    Keyring, MissingKeyError, InvalidKeyringError, UnknownKeyError,
    canonical_json, load_keyring, seal_payload_v4, sign_record, verify_record,
    verify_mixed_chain,
)

KEY_A = b"a" * 32
KEY_B = b"b" * 32


def _ring(active="k1", keys=None):
    return Keyring(keys=keys or {"k1": KEY_A, "k2": KEY_B}, active_key_id=active)


def _record(seq=0, prev=GENESIS_HASH, keyring=None, payload=None, record_type="provenance.runtime", tenant_id="tenant-a"):
    ring = keyring or _ring()
    row = {
        "tenant_id": tenant_id,
        "seq": seq,
        "prev_hash": prev,
        "record_type": record_type,
        "payload_json": seal_payload_v4(record_type, payload or {"run_id": "r1", "result": 391}, ring),
    }
    row["record_hash"] = sign_record(row, ring)
    return row


def _legacy(version, seq, prev, digest):
    if version == 1:
        payload = {"run_id": "legacy"}
    else:
        payload = {
            "run_id": "legacy",
            V2_META_KEY: {
                "version": version,
                "record_type": "task.received",
                "producer": "ola_runtime",
            },
        }
    return {
        "tenant_id": "tenant-a", "seq": seq, "prev_hash": prev,
        "record_type": "task.received", "payload_json": canonical_json(payload),
        "record_hash": digest,
    }


def test_v4_sign_and_verify_with_existing_database_record_shape():
    ring = _ring()
    row = _record(keyring=ring)
    payload = json.loads(row["payload_json"])
    assert set(row) == {"tenant_id", "seq", "prev_hash", "record_type", "payload_json", "record_hash"}
    assert payload[V4_META_KEY] == {
        "version": 4, "key_id": "k1", "record_type": "provenance.runtime",
        "producer": "ola_runtime",
    }
    assert verify_record(row, ring)


def test_rotation_keeps_old_key_for_history_and_new_key_for_writes():
    old = _ring("k1")
    new = _ring("k2")
    first = _record(keyring=old)
    second = _record(1, first["record_hash"], new)
    assert verify_record(first, new)
    assert verify_record(second, new)
    assert json.loads(second["payload_json"])[V4_META_KEY]["key_id"] == "k2"


def test_unknown_key_id_fails_closed():
    row = _record()
    payload = json.loads(row["payload_json"])
    payload[V4_META_KEY]["key_id"] = "missing"
    row["payload_json"] = canonical_json(payload)
    with pytest.raises(UnknownKeyError):
        verify_record(row, _ring())


def test_key_substitution_is_detected():
    row = _record()
    payload = json.loads(row["payload_json"])
    payload[V4_META_KEY]["key_id"] = "k2"
    row["payload_json"] = canonical_json(payload)
    assert not verify_record(row, _ring())


def test_missing_keyring_fails_closed():
    with pytest.raises(MissingKeyError):
        load_keyring({})


def test_restart_reloads_same_external_keyring():
    env = {
        KEYRING_ENV: json.dumps({"k1": base64.b64encode(KEY_A).decode()}),
        ACTIVE_KEY_ENV: "k1",
    }
    before = load_keyring(env)
    after = load_keyring(dict(env))
    row = _record(keyring=before)
    assert verify_record(row, after)


def test_keyring_copies_and_freezes_caller_mapping():
    supplied = {"k1": KEY_A}
    ring = Keyring(keys=supplied, active_key_id="k1")
    supplied["k1"] = KEY_B
    supplied["k2"] = KEY_B
    assert ring.keys["k1"] == KEY_A
    assert "k2" not in ring.keys
    assert "aaaaaaaaaaaaaaaa" not in repr(ring)
    with pytest.raises(TypeError):
        ring.keys["k1"] = KEY_B


def test_duplicate_keyring_json_members_are_rejected():
    encoded_a = base64.b64encode(KEY_A).decode()
    encoded_b = base64.b64encode(KEY_B).decode()
    env = {
        KEYRING_ENV: '{"k1":"' + encoded_a + '","k1":"' + encoded_b + '"}',
        ACTIVE_KEY_ENV: "k1",
    }
    with pytest.raises(InvalidKeyringError):
        load_keyring(env)


def test_payload_canonicalization_is_stable():
    assert canonical_json({"z": 1, "a": 2}) == '{"a":2,"z":1}'


def test_noncanonical_payload_is_rejected():
    row = _record()
    row["payload_json"] = '{ "result":391,"run_id":"r1","' + V4_META_KEY + '":' + json.dumps(
        json.loads(row["payload_json"])[V4_META_KEY], separators=(",", ":")
    ) + '}'
    with pytest.raises(ValueError, match="payload_json is not canonical"):
        verify_record(row, _ring())


def test_duplicate_payload_json_members_are_rejected():
    row = _record()
    row["payload_json"] = '{"x":1,"x":2}'
    with pytest.raises(ValueError, match="duplicate JSON object key"):
        verify_record(row, _ring())


@pytest.mark.parametrize("field,value", [
    ("tenant_id", "tenant-b"),
    ("seq", 1),
    ("prev_hash", "1" * 64),
])
def test_authenticated_record_fields_cannot_be_substituted(field, value):
    row = _record()
    row[field] = value
    assert not verify_record(row, _ring())


def test_record_type_substitution_fails_closed():
    row = _record()
    row["record_type"] = "provenance.changed"
    with pytest.raises(ValueError, match="record type metadata mismatch"):
        verify_record(row, _ring())


def test_payload_mutation_is_detected():
    row = _record()
    payload = json.loads(row["payload_json"])
    payload["result"] = 392
    row["payload_json"] = canonical_json(payload)
    assert not verify_record(row, _ring())


def test_v4_rejects_payload_reserved_metadata_collision():
    with pytest.raises(ValueError, match="reserved evidence metadata"):
        seal_payload_v4("task.received", {V2_META_KEY: {}}, _ring())


def test_key_loss_fails_closed_without_legacy_fallback():
    signed = _record(keyring=_ring("k1"))
    no_old_key = Keyring(keys={"k2": KEY_B}, active_key_id="k2")
    with pytest.raises(UnknownKeyError):
        verify_record(signed, no_old_key)


def test_backup_restore_preserves_verifiability_with_restored_secret():
    original = _ring("k1")
    row = _record(keyring=original)
    evidence_backup = json.dumps(row, sort_keys=True)
    secret_backup = {
        KEYRING_ENV: json.dumps({
            "k1": base64.b64encode(KEY_A).decode(),
            "k2": base64.b64encode(KEY_B).decode(),
        }),
        ACTIVE_KEY_ENV: "k2",
    }
    restored_row = json.loads(evidence_backup)
    restored_keyring = load_keyring(secret_backup)
    assert verify_record(restored_row, restored_keyring)


def test_mixed_v3_v4_requires_explicit_legacy_verifier():
    v3 = _legacy(3, 0, GENESIS_HASH, "1" * 64)
    v4 = _record(1, "1" * 64)
    assert verify_mixed_chain([v3, v4], _ring())[0] is False
    ok, _ = verify_mixed_chain(
        [v3, v4], _ring(), legacy_verifier=lambda segment, **_anchor: (segment == [v3], "legacy-fixture-ok")
    )
    assert ok


def test_mixed_v1_v2_v3_v4_keeps_continuity_across_legacy_boundary():
    v1 = _legacy(1, 0, GENESIS_HASH, "1" * 64)
    v2 = _legacy(2, 1, "1" * 64, "2" * 64)
    v3 = _legacy(3, 2, "2" * 64, "3" * 64)
    v4 = _record(3, "3" * 64)
    seen = []

    def verify_legacy(segment, *, start_seq, start_prev_hash):
        seen.append(([ _version(item) for item in segment ], start_seq, start_prev_hash))
        return True, "verified-by-test-legacy-adapter"

    assert verify_mixed_chain([v1, v2, v3, v4], _ring(), legacy_verifier=verify_legacy)[0]
    assert seen == [([1, 2, 3], 0, GENESIS_HASH)]


def _version(row):
    payload = json.loads(row["payload_json"])
    if V2_META_KEY not in payload:
        return 1
    return payload[V2_META_KEY]["version"]


def test_legacy_verifier_exceptions_fail_closed():
    v3 = _legacy(3, 0, GENESIS_HASH, "1" * 64)
    ok, reason = verify_mixed_chain(
        [v3], _ring(), legacy_verifier=lambda _segment, **_anchor: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    assert not ok
    assert reason == "legacy verifier raised an exception"



def test_provenance_labelled_historical_v1_v2_v3_fixture_and_v4_transition():
    fixture_path = Path(__file__).parent / "fixtures" / "evidence_legacy_v1_v2_v3.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    assert fixture["fixture_schema"] == "ola-evidence-legacy-compatibility-fixture-v1"
    provenance = fixture["provenance"]
    assert provenance["v1_v2_algorithm_source_commit"] == "c46b469836fc841638654850158c82d728164f3c"
    assert provenance["v1_v2_algorithm_source_blob"] == "60f12f96bcb0291201b432747cfd16b12921d2c3"
    assert provenance["v3_algorithm_source_commit"] == "c46b469836fc841638654850158c82d728164f3c"
    assert provenance["v3_algorithm_source_blob"] == "60f12f96bcb0291201b432747cfd16b12921d2c3"
    pepper = provenance["v3_test_pepper"]
    legacy = fixture["records"]

    def verify_historical(segment, *, start_seq, start_prev_hash):
        expected_seq = start_seq
        expected_prev = start_prev_hash
        for row in segment:
            if row["seq"] != expected_seq or row["prev_hash"] != expected_prev:
                return False, "legacy continuity mismatch"
            payload = json.loads(row["payload_json"])
            metadata = payload.get(V2_META_KEY)
            if metadata is None:
                material = f'{row["tenant_id"]}|{row["seq"]}|{row["prev_hash"]}|{row["payload_json"]}'.encode()
                expected = hashlib.sha256(material).hexdigest()
            else:
                version = metadata["version"]
                common = {
                    "tenant_id": row["tenant_id"], "seq": row["seq"],
                    "prev_hash": row["prev_hash"], "record_type": row["record_type"],
                    "producer": metadata["producer"], "payload_json": row["payload_json"],
                }
                if metadata["record_type"] != row["record_type"]:
                    return False, "legacy type binding mismatch"
                if version == 2:
                    material = canonical_json({"domain": "OLA-EVIDENCE-CHAIN-V2", **common}).encode()
                    expected = hashlib.sha256(material).hexdigest()
                elif version == 3:
                    material = canonical_json({"domain": "OLA-EVIDENCE-CHAIN-V3", **common}).encode()
                    derived = hmac.new(
                        pepper.encode("utf-8"), b"OLA-EVIDENCE-CHAIN-KEY-V3", hashlib.sha256
                    ).digest()
                    expected = hmac.new(derived, material, hashlib.sha256).hexdigest()
                else:
                    return False, "unsupported fixture version"
            if not hmac.compare_digest(expected, row["record_hash"]):
                return False, "legacy hash mismatch"
            expected_seq += 1
            expected_prev = row["record_hash"]
        return True, "historical fixture verified"

    v4 = _record(3, legacy[-1]["record_hash"], tenant_id=legacy[-1]["tenant_id"])
    ok, reason = verify_mixed_chain(legacy + [v4], _ring(), legacy_verifier=verify_historical)
    assert ok, reason



def test_mixed_chain_rejects_cross_tenant_boundary():
    v1 = _legacy(1, 0, GENESIS_HASH, "1" * 64)
    v2 = _legacy(1, 1, v1["record_hash"], "2" * 64)
    v2["tenant_id"] = "tenant-other"
    ok, reason = verify_mixed_chain(
        [v1, v2], _ring(), legacy_verifier=lambda _segment, **_anchor: (True, "not enough")
    )
    assert not ok
    assert reason == "tenant boundary mismatch"


def test_mixed_chain_rejects_boolean_sequence():
    v1 = _legacy(1, 0, GENESIS_HASH, "1" * 64)
    v1["seq"] = False
    ok, reason = verify_mixed_chain(
        [v1], _ring(), legacy_verifier=lambda _segment, **_anchor: (True, "not enough")
    )
    assert not ok
    assert reason == "sequence mismatch"


def test_v4_rejects_ambiguous_v2_and_v4_metadata():
    row = _record()
    payload = json.loads(row["payload_json"])
    payload[V2_META_KEY] = {"version": 2, "record_type": row["record_type"], "producer": "ola_runtime"}
    row["payload_json"] = canonical_json(payload)
    with pytest.raises(ValueError, match="legacy V2 metadata"):
        verify_record(row, _ring())



def test_payload_depth_and_size_limits_are_enforced():
    nested = {"leaf": True}
    for _ in range(MAX_JSON_DEPTH + 2):
        nested = {"nested": nested}
    with pytest.raises(ValueError, match="nesting limit"):
        canonical_json(nested)
    with pytest.raises(ValueError, match="size limit"):
        canonical_json({"blob": "x" * MAX_PAYLOAD_BYTES})
