import hashlib
import json
import subprocess
import sys

import pytest
from app.decision_report_v2 import build_decision_report_v2, inspect_decision_report_v2, DOMAIN


def make_report(**bindings):
    return build_decision_report_v2(
        legacy_report={"schema": "ola.decision-report.v1", "policy": {"status": "VERIFIED"}},
        **bindings)


def test_legacy_verified_and_complete_bindings_cannot_promote():
    report = make_report(source_sha="a" * 40, policy_digest="b" * 64,
                         evidence_root="c" * 64, human_approval_digest="d" * 64)
    assert inspect_decision_report_v2(report) == {
        "integrity": "LOCAL", "assurance": "UNKNOWN", "production_eligible": False}


def test_missing_bindings_stay_unknown():
    report = make_report()
    assert all(v is None for v in report["bindings"].values())
    assert report["assurance"]["status"] == "UNKNOWN"


@pytest.mark.parametrize("field,width", [("source_sha", 40), ("policy_digest", 64),
    ("evidence_root", 64), ("human_approval_digest", 64)])
def test_each_binding_is_hash_bound(field, width):
    report = make_report(**{field: "a" * width})
    report["bindings"][field] = "b" * width
    assert inspect_decision_report_v2(report)["integrity"] == "BLOCKED"


@pytest.mark.parametrize("value", ["main", "c78135d", "A" * 40, "g" * 40, True, 123])
def test_invalid_source_rejected(value):
    with pytest.raises(ValueError):
        make_report(source_sha=value)


@pytest.mark.parametrize("promotion", ["LOCAL", "ATTESTED", "VERIFIED"])
def test_even_resealed_promotion_is_blocked(promotion):
    report = make_report()
    report["assurance"]["status"] = promotion
    report.pop("report_sha256")
    report["report_sha256"] = hashlib.sha256(DOMAIN + json.dumps(
        report, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    assert inspect_decision_report_v2(report)["integrity"] == "BLOCKED"


def test_snapshot_cannot_change_after_build():
    legacy = {"schema": "ola.decision-report.v1", "policy": {"status": "UNKNOWN"}}
    report = build_decision_report_v2(legacy_report=legacy)
    legacy["policy"]["status"] = "VERIFIED"
    assert report["legacy_report"]["policy"]["status"] == "UNKNOWN"


@pytest.mark.parametrize("value", [None, [], {}, {"bindings": None}])
def test_malformed_input_fails_closed(value):
    assert inspect_decision_report_v2(value)["integrity"] == "BLOCKED"


def test_cli_local_only_and_bad_json(tmp_path):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(make_report()))
    command = [sys.executable, "scripts/inspect_decision_report_v2.py", str(path)]
    good = subprocess.run(command, capture_output=True, text=True)
    assert good.returncode == 0
    assert json.loads(good.stdout)["assurance"] == "UNKNOWN"
    path.write_text('{"schema":1,"schema":2}')
    bad = subprocess.run(command, capture_output=True, text=True)
    assert bad.returncode == 1
    assert json.loads(bad.stdout)["integrity"] == "BLOCKED"
