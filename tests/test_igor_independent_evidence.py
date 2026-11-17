import ast
import base64
import hashlib
import json
from pathlib import Path

from app import igor_evidence_verifier as independent
from app.igor import IgorVerifier


FIXTURES = Path(__file__).parent / "fixtures"


def _legacy_fixture():
    return json.loads((FIXTURES / "evidence_legacy_v1_v2_v3.json").read_text(encoding="utf-8"))


def _v4_fixture():
    return json.loads((FIXTURES / "evidence_v4_independent.json").read_text(encoding="utf-8"))


def _environment(legacy, v4):
    return {
        "OLA_API_KEY_PEPPER": legacy["provenance"]["v3_test_pepper"],
        "OLA_EVIDENCE_V4_KEYRING_JSON": json.dumps({
            v4["provenance"]["test_key_id"]: base64.b64encode(
                hashlib.sha256(v4["provenance"]["test_key_seed"].encode("utf-8")).digest()
            ).decode("ascii")
        }),
        "OLA_EVIDENCE_V4_ACTIVE_KEY_ID": v4["provenance"]["test_key_id"],
    }


def test_igor_independently_verifies_provenance_labelled_v1_v2_v3_v4_chain():
    legacy = _legacy_fixture()
    v4 = _v4_fixture()
    records = legacy["records"] + [v4["record"]]
    ok, reason = independent.verify_chain(records, _environment(legacy, v4))
    assert ok, reason
    assert independent.trusted_record(legacy["records"][0]) is False
    assert independent.trusted_record(legacy["records"][1]) is True
    assert independent.trusted_record(legacy["records"][2]) is True
    assert independent.trusted_record(v4["record"]) is True


def test_igor_fails_closed_when_v4_keyring_is_missing():
    legacy = _legacy_fixture()
    v4 = _v4_fixture()
    env = {"OLA_API_KEY_PEPPER": legacy["provenance"]["v3_test_pepper"]}
    ok, _ = independent.verify_chain(legacy["records"] + [v4["record"]], env)
    assert not ok


def test_igor_fails_closed_on_wrong_v3_pepper():
    legacy = _legacy_fixture()
    v4 = _v4_fixture()
    env = _environment(legacy, v4)
    env["OLA_API_KEY_PEPPER"] = "wrong-v3-test-pepper-material-0123456789"
    ok, _ = independent.verify_chain(legacy["records"] + [v4["record"]], env)
    assert not ok


def test_igor_fails_closed_on_v4_key_substitution():
    legacy = _legacy_fixture()
    v4 = _v4_fixture()
    row = dict(v4["record"])
    payload = json.loads(row["payload_json"])
    payload["__ola_evidence_v4__"]["key_id"] = "unknown-key"
    row["payload_json"] = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    ok, _ = independent.verify_chain(legacy["records"] + [row], _environment(legacy, v4))
    assert not ok


def test_igor_rejects_cross_tenant_legacy_record():
    legacy = _legacy_fixture()
    v4 = _v4_fixture()
    records = [dict(row) for row in legacy["records"]] + [v4["record"]]
    records[1]["tenant_id"] = "tenant-substitution"
    ok, reason = independent.verify_chain(records, _environment(legacy, v4))
    assert not ok
    assert reason == "tenant boundary mismatch"


def test_igor_verifier_has_no_shared_writer_verifier_imports():
    source = Path(independent.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported.append(node.module or "")
        elif isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
    assert not any(name in {"app.hashchain", "app.evidence_v4"} for name in imported)



def test_igor_runtime_verifier_accepts_v4_only_after_independent_chain_verification(monkeypatch):
    legacy = _legacy_fixture()
    v4 = _v4_fixture()
    env = _environment(legacy, v4)
    monkeypatch.setenv("OLA_API_KEY_PEPPER", env["OLA_API_KEY_PEPPER"])
    monkeypatch.setenv("OLA_EVIDENCE_V4_KEYRING_JSON", env["OLA_EVIDENCE_V4_KEYRING_JSON"])
    monkeypatch.setenv("OLA_EVIDENCE_V4_ACTIVE_KEY_ID", env["OLA_EVIDENCE_V4_ACTIVE_KEY_ID"])
    result = IgorVerifier().verify_records(
        legacy["records"] + [v4["record"]],
        "abc123",
        "fixture task",
        "verified",
        expected_run_id="agent-run",
    )
    assert result.status == "VERIFIED"
    assert result.checks["chain"] is True
    assert result.evidence_ids == ()



def test_igor_rejects_over_depth_v4_payload_before_hash_acceptance():
    legacy = _legacy_fixture()
    v4 = _v4_fixture()
    row = dict(v4["record"])
    payload = json.loads(row["payload_json"])
    nested = {"leaf": True}
    for _ in range(independent.MAX_JSON_DEPTH + 2):
        nested = {"nested": nested}
    payload["deep"] = nested
    row["payload_json"] = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    ok, _ = independent.verify_chain(
        legacy["records"] + [row], _environment(legacy, v4)
    )
    assert not ok



def test_igor_preserves_v1_duplicate_json_member_semantics():
    tenant_id = "legacy-duplicate-json"
    payload_json = '{"event":"first","event":"last"}'
    record = {
        "tenant_id": tenant_id,
        "seq": 0,
        "record_type": "task.received",
        "payload_json": payload_json,
        "prev_hash": "0" * 64,
        "record_hash": hashlib.sha256(
            f"{tenant_id}|0|{'0' * 64}|{payload_json}".encode("utf-8")
        ).hexdigest(),
    }
    assert independent.verify_chain([record]) == (True, "ok")


def test_igor_rejects_duplicate_json_members_in_v4():
    legacy = _legacy_fixture()
    v4 = _v4_fixture()
    row = dict(v4["record"])
    row["payload_json"] = row["payload_json"][:-1] + ',"run_id":"duplicate"}'
    ok, _ = independent.verify_chain(
        legacy["records"] + [row], _environment(legacy, v4)
    )
    assert not ok
