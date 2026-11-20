import base64
import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from app import evidence_v4
from app import igor_evidence_verifier as independent


FIXTURES = Path(__file__).parent / "fixtures"
V4_KEY_ID = "evidence-efficiency-test"
V4_KEY = b"evidence-efficiency-test-key-material-32bytes"
TENANT_ID = "evidence-efficiency-tenant"


def _fixture_environment():
    legacy = json.loads(
        (FIXTURES / "evidence_legacy_v1_v2_v3.json").read_text(encoding="utf-8")
    )
    v4 = json.loads(
        (FIXTURES / "evidence_v4_independent.json").read_text(encoding="utf-8")
    )
    environment = {
        "OLA_API_KEY_PEPPER": legacy["provenance"]["v3_test_pepper"],
        "OLA_EVIDENCE_V4_KEYRING_JSON": json.dumps({
            v4["provenance"]["test_key_id"]: base64.b64encode(
                hashlib.sha256(v4["provenance"]["test_key_seed"].encode("utf-8")).digest()
            ).decode("ascii")
        }),
        "OLA_EVIDENCE_V4_ACTIVE_KEY_ID": v4["provenance"]["test_key_id"],
    }
    return legacy, v4, environment


def _v4_chain(count=3):
    keyring = evidence_v4.Keyring(
        keys={V4_KEY_ID: V4_KEY},
        active_key_id=V4_KEY_ID,
    )
    records = []
    previous = evidence_v4.GENESIS_HASH
    for seq in range(count):
        payload_json = evidence_v4.seal_payload_v4(
            "provenance.runtime",
            {"run_id": f"run-{seq}", "value": seq},
            keyring,
        )
        record = {
            "tenant_id": TENANT_ID,
            "seq": seq,
            "prev_hash": previous,
            "record_type": "provenance.runtime",
            "payload_json": payload_json,
        }
        record["record_hash"] = evidence_v4.sign_record(record, keyring)
        previous = record["record_hash"]
        records.append(record)
    return keyring, records


class EvidenceWriteEfficiencyTests(unittest.TestCase):
    def test_independent_verifier_parses_each_payload_once_and_keyring_once(self):
        legacy, v4, environment = _fixture_environment()
        records = legacy["records"] + [v4["record"]]
        payloads = {record["payload_json"] for record in records}
        parse_counts = {payload: 0 for payload in payloads}
        original_loads = independent.json.loads

        def counted_loads(raw, *args, **kwargs):
            if raw in parse_counts:
                parse_counts[raw] += 1
            return original_loads(raw, *args, **kwargs)

        with (
            patch.object(independent.json, "loads", side_effect=counted_loads),
            patch.object(independent, "_keyring", wraps=independent._keyring) as keyring_load,
        ):
            result = independent.verify_chain(records, environment)

        self.assertEqual(result, (True, "ok"))
        self.assertEqual(set(parse_counts.values()), {1})
        keyring_load.assert_called_once()

    def test_independent_verifier_loads_keyring_once_for_many_v4_records(self):
        _, records = _v4_chain(8)
        environment = {
            "OLA_EVIDENCE_V4_KEYRING_JSON": json.dumps({
                V4_KEY_ID: base64.b64encode(V4_KEY).decode("ascii")
            }),
            "OLA_EVIDENCE_V4_ACTIVE_KEY_ID": V4_KEY_ID,
        }
        payloads = {record["payload_json"] for record in records}
        parse_counts = {payload: 0 for payload in payloads}
        original_loads = independent.json.loads

        def counted_loads(raw, *args, **kwargs):
            if raw in parse_counts:
                parse_counts[raw] += 1
            return original_loads(raw, *args, **kwargs)

        with (
            patch.object(independent.json, "loads", side_effect=counted_loads),
            patch.object(independent, "_keyring", wraps=independent._keyring) as keyring_load,
        ):
            result = independent.verify_chain(records, environment)

        self.assertEqual(result, (True, "ok"))
        self.assertEqual(set(parse_counts.values()), {1})
        keyring_load.assert_called_once()

    def test_mixed_verifier_parses_each_v4_payload_once_and_keeps_integrity_checks(self):
        keyring, records = _v4_chain(5)
        payloads = {record["payload_json"] for record in records}
        parse_counts = {payload: 0 for payload in payloads}
        original_loads = evidence_v4.json.loads

        def counted_loads(raw, *args, **kwargs):
            if raw in parse_counts:
                parse_counts[raw] += 1
            return original_loads(raw, *args, **kwargs)

        with patch.object(evidence_v4.json, "loads", side_effect=counted_loads):
            result = evidence_v4.verify_mixed_chain(records, keyring)

        self.assertEqual(result, (True, "ok"))
        self.assertEqual(set(parse_counts.values()), {1})

        tampered = [dict(record) for record in records]
        tampered[2]["record_hash"] = "f" * 64
        self.assertFalse(evidence_v4.verify_mixed_chain(tampered, keyring)[0])

        duplicate = [dict(record) for record in records]
        duplicate[2]["payload_json"] = (
            duplicate[2]["payload_json"][:-1] + ',"run_id":"duplicate"}'
        )
        self.assertFalse(evidence_v4.verify_mixed_chain(duplicate, keyring)[0])

    def test_independent_verifier_keeps_legacy_duplicate_semantics_and_rejects_v4_duplicates(self):
        tenant_id = "legacy-duplicate-json"
        payload_json = '{"event":"first","event":"last"}'
        legacy_record = {
            "tenant_id": tenant_id,
            "seq": 0,
            "record_type": "task.received",
            "payload_json": payload_json,
            "prev_hash": "0" * 64,
            "record_hash": hashlib.sha256(
                f"{tenant_id}|0|{'0' * 64}|{payload_json}".encode("utf-8")
            ).hexdigest(),
        }
        self.assertEqual(independent.verify_chain([legacy_record]), (True, "ok"))

        _, records = _v4_chain(2)
        records[1]["payload_json"] = (
            records[1]["payload_json"][:-1] + ',"run_id":"duplicate"}'
        )
        environment = {
            "OLA_EVIDENCE_V4_KEYRING_JSON": json.dumps({
                V4_KEY_ID: base64.b64encode(V4_KEY).decode("ascii")
            }),
            "OLA_EVIDENCE_V4_ACTIVE_KEY_ID": V4_KEY_ID,
        }
        self.assertFalse(independent.verify_chain(records, environment)[0])

    def test_independent_verifier_still_rejects_a_tampered_record_hash(self):
        _, records = _v4_chain(3)
        records[1]["record_hash"] = "f" * 64
        environment = {
            "OLA_EVIDENCE_V4_KEYRING_JSON": json.dumps({
                V4_KEY_ID: base64.b64encode(V4_KEY).decode("ascii")
            }),
            "OLA_EVIDENCE_V4_ACTIVE_KEY_ID": V4_KEY_ID,
        }
        self.assertFalse(independent.verify_chain(records, environment)[0])


if __name__ == "__main__":
    unittest.main()
