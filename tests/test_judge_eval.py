"""scripts/judge_eval.py against the Ollama TEST DOUBLE (protocol + arithmetic of the harness only).

These tests do not say anything about any real judge: the fake answers by a rule whose confusion matrix is
known in advance, and the harness must reproduce exactly that matrix. Real-judge numbers come from the CI job
`judge-accuracy` (annotations "judge accuracy").
"""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent / "pipeline_suite"))
from fake_ollama import FakeOllama  # noqa: E402
from ola_pipeline.config import Policy, ProviderConfig  # noqa: E402
from ola_pipeline.verify import CANARY_TASK  # noqa: E402

_spec = importlib.util.spec_from_file_location("judge_eval", ROOT / "scripts" / "judge_eval.py")
je = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(je)

DATASET = ROOT / "tests" / "data" / "judge_eval.json"


def _verdict(decision, score=95, corrections=()):
    return json.dumps({"decision": decision, "quality_score": score, "findings": [],
                       "required_corrections": list(corrections), "reason": "test"})


def _item_of(messages):
    """The (task, output) the harness sent to the judge."""
    body = messages[1]["content"].split("INPUT:\n", 1)[1]
    obj = json.loads(body)
    return obj["task"], obj["nina_output"]


@pytest.fixture
def fake():
    f = FakeOllama().start()
    f.add_model("judge-test")
    yield f
    f.stop()


@pytest.fixture
def items():
    return je.load_dataset(DATASET)[0]


def _cfg(fake, **kw):
    return ProviderConfig("ollama-local", "judge-test", base_url=fake.url, timeout_s=10.0, temperature=0.0, **kw)


def _run(fake, items, rule, **kw):
    labels = {(i["task"], i["output"]): i["label"] for i in items}
    fake.script("judge-test", lambda idx, msgs: rule(labels[_item_of(msgs)], idx))
    return je.evaluate(items, _cfg(fake), Policy(allow_test_double=True), **kw)


# ---- the labelled set itself -------------------------------------------------------------------------------

def test_dataset_is_well_formed():
    items, sha = je.load_dataset(DATASET)
    assert len(sha) == 64
    assert len({i["id"] for i in items}) == len(items)
    assert {i["label"] for i in items} == {"correct", "wrong"}
    assert all(i["task"].strip() and i["output"].strip() for i in items)
    assert all(i["task"] != CANARY_TASK for i in items)
    assert len({(i["task"], i["output"]) for i in items}) == len(items), "an (task, output) pair must be unique"
    wrong = sum(i["label"] == "wrong" for i in items)
    assert wrong >= 20 and len(items) - wrong >= 20, "both classes need enough items to say anything"
    assert {"injection", "abstain"} <= {i["category"] for i in items}


def test_every_task_with_a_wrong_answer_also_has_a_correct_one_in_the_arithmetic_and_fact_groups():
    items, _ = je.load_dataset(DATASET)
    by_task = {}
    for i in items:
        by_task.setdefault(i["task"], set()).add(i["label"])
    for i in items:
        if i["category"] in ("arithmetic", "capital", "fact"):
            assert by_task[i["task"]] == {"correct", "wrong"}, i["id"]


def test_load_dataset_rejects_the_canary_and_bad_labels(tmp_path):
    p = tmp_path / "d.json"
    p.write_text(json.dumps({"items": [{"id": "a", "category": "x", "task": CANARY_TASK, "output": "4", "label": "correct"}]}))
    with pytest.raises(ValueError, match="canary"):
        je.load_dataset(p)
    p.write_text(json.dumps({"items": [{"id": "a", "category": "x", "task": "t", "output": "o", "label": "maybe"}]}))
    with pytest.raises(ValueError, match="label"):
        je.load_dataset(p)
    p.write_text(json.dumps({"items": [{"id": "a", "category": "x", "task": "t", "output": "o", "label": "wrong"},
                                       {"id": "a", "category": "x", "task": "t2", "output": "o", "label": "wrong"}]}))
    with pytest.raises(ValueError, match="duplicate"):
        je.load_dataset(p)


# ---- arithmetic of the harness -----------------------------------------------------------------------------

@pytest.mark.parametrize("k,n,lo,hi", [(0, 10, 0.0, 0.2775), (10, 10, 0.7225, 1.0), (5, 10, 0.2366, 0.7634)])
def test_wilson_interval_matches_reference_values(k, n, lo, hi):
    got_lo, got_hi = je.wilson(k, n)
    assert got_lo == pytest.approx(lo, abs=1e-3) and got_hi == pytest.approx(hi, abs=1e-3)


def test_wilson_of_nothing_is_undefined_not_zero():
    assert je.wilson(0, 0) == (None, None)


@pytest.mark.parametrize("text,expected", [
    (_verdict("PASS", 95), "ACCEPT"),
    (_verdict("PASS", 70), "ACCEPT"),
    (_verdict("PASS", 69), "REJECT"),                          # below min_quality_score -> Igor downgrades to REVIEW
    (_verdict("PASS", 99, ["fix the units"]), "REJECT"),       # PASS with outstanding corrections -> REVIEW
    (_verdict("REVIEW", 90), "REJECT"),
    (_verdict("BLOCK", 5), "REJECT"),
    ("definitely not json", "NO_VERDICT"),
    (json.dumps({"decision": "MAYBE", "quality_score": 50, "findings": [], "required_corrections": [], "reason": ""}), "NO_VERDICT"),
    ("", "NO_VERDICT"),
])
def test_classify_applies_the_same_rule_as_igor(text, expected):
    assert je.classify(text, 70)[0] == expected


# ---- end to end against judges with a known confusion matrix -----------------------------------------------

def test_perfect_judge_has_no_false_accepts(fake, items):
    r = _run(fake, items, lambda label, idx: _verdict("PASS", 95) if label == "correct" else _verdict("BLOCK", 5))
    s = r["summary"]
    assert s["false_accept"]["k"] == 0 and s["false_accept"]["n"] == sum(i["label"] == "wrong" for i in items)
    assert s["correct_accepted"]["k"] == s["correct_accepted"]["n"] > 0
    assert s["pass_precision"]["rate"] == 1.0
    assert r["meta"]["runtime_kind"] == "TEST_DOUBLE", "a fake must never be reported as an observed runtime"


def test_rubber_stamp_judge_accepts_every_wrong_answer(fake, items):
    r = _run(fake, items, lambda label, idx: _verdict("PASS", 100))
    s = r["summary"]
    assert s["false_accept"]["k"] == s["false_accept"]["n"] > 0
    assert s["false_accept"]["rate"] == 1.0
    n_wrong, n_ok = s["false_accept"]["n"], s["correct_accepted"]["n"]
    assert s["pass_precision"]["k"] == n_ok and s["pass_precision"]["n"] == n_ok + n_wrong
    # every category with wrong answers shows the false accepts, including the injection items
    assert all(c["false_accept"] == c["wrong_n"] for c in s["by_category"].values() if c["wrong_n"])


def test_paranoid_judge_rejects_everything_and_precision_is_undefined(fake, items):
    r = _run(fake, items, lambda label, idx: _verdict("REVIEW", 40))
    s = r["summary"]
    assert s["false_accept"]["k"] == 0 and s["correct_accepted"]["k"] == 0
    assert s["correct_rejected"]["k"] == s["correct_rejected"]["n"]
    assert s["pass_precision"]["rate"] is None, "no PASS was issued: precision is undefined, not 100%"


def test_unusable_judge_counts_as_no_verdict_never_as_accept(fake, items):
    r = _run(fake, items, lambda label, idx: "definitely not json")
    s = r["summary"]
    assert s["verdicts_obtained"] == 0
    assert s["false_accept"]["k"] == 0 and s["wrong_no_verdict"]["k"] == s["wrong_no_verdict"]["n"] > 0
    assert s["correct_no_verdict"]["k"] == s["correct_no_verdict"]["n"] > 0


def test_repeat_detects_a_judge_that_changes_its_mind(fake, items):
    # first call per item accepts, the second rejects: every item changes verdict
    seen = {}

    def rule(label, idx):
        return _verdict("PASS", 90)

    labels = {(i["task"], i["output"]): i["label"] for i in items}

    def flip(idx, msgs):
        key = _item_of(msgs)
        seen[key] = seen.get(key, 0) + 1
        return _verdict("PASS", 90) if seen[key] == 1 else _verdict("REVIEW", 90)

    fake.script("judge-test", flip)
    r = je.evaluate(items, _cfg(fake), Policy(allow_test_double=True), repeat=2)
    assert r["items_with_changing_verdict"] == len(items)
    assert len(r["runs"]) == 2 * len(items)


def test_unknown_model_gives_no_verdict_and_cli_exit_code_2(fake, tmp_path, capsys):
    out = tmp_path / "r.json"
    rc = je.main(["--model", "not-pulled", "--base-url", fake.url, "--timeout", "5", "--limit", "3", "--out", str(out)])
    assert rc == 2, "nothing ran: the exit code must say UNKNOWN, not success"
    assert "UNKNOWN" in capsys.readouterr().err
    data = json.loads(out.read_text())
    assert data["summary"]["verdicts_obtained"] == 0 and data["summary"]["false_accept"]["k"] == 0


def test_cli_writes_a_result_that_names_the_dataset_and_the_runtime(fake, tmp_path, capsys):
    fake.script("judge-test", lambda idx, msgs: _verdict("BLOCK", 5))
    out = tmp_path / "r.json"
    rc = je.main(["--model", "judge-test", "--base-url", fake.url, "--limit", "5", "--out", str(out)])
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["schema"] == "ola.judge-eval/1" and data["items"] == 5
    assert data["dataset_sha256"] == je.load_dataset(DATASET)[1]
    assert data["meta"]["runtime_kind"] == "TEST_DOUBLE"
    line = capsys.readouterr().out
    assert "JUDGE EVAL:" in line and "runtime=TEST_DOUBLE" in line


def test_a_judge_that_times_out_is_no_verdict_with_the_reason_recorded(fake, items):
    fake.delays["judge-test"] = 1.5
    cfg = ProviderConfig("ollama-local", "judge-test", base_url=fake.url, timeout_s=0.5, temperature=0.0)
    r = je.evaluate(items[:2], cfg, Policy(allow_test_double=True))
    assert [x["verdict"] for x in r["runs"]] == ["NO_VERDICT", "NO_VERDICT"]
    assert all(x["detail"] == "TIMEOUT" for x in r["runs"])
    assert r["summary"]["false_accept"]["k"] == 0 and r["summary"]["verdicts_obtained"] == 0


def test_results_are_split_by_category_with_the_counts_of_the_dataset(fake, items):
    r = _run(fake, items, lambda label, idx: _verdict("PASS", 100))
    by_cat = r["summary"]["by_category"]
    assert set(by_cat) == {i["category"] for i in items}
    for cat, c in by_cat.items():
        assert c["wrong_n"] == sum(1 for i in items if i["category"] == cat and i["label"] == "wrong")
        assert c["correct_n"] == sum(1 for i in items if i["category"] == cat and i["label"] == "correct")
    assert by_cat["injection"]["wrong_n"] == by_cat["injection"]["false_accept"] == 3, "a rubber stamp falls for every injection"
    assert by_cat["abstain"]["false_accept"] == by_cat["abstain"]["wrong_n"] == 2


def test_rejections_record_why_but_do_not_change_the_summary(fake, items):
    r = _run(fake, items, lambda label, idx: json.dumps(
        {"decision": "PASS", "quality_score": 95, "findings": [], "required_corrections": ["state your uncertainty"],
         "reason": "needs a caveat"}))
    rejected = [x for x in r["runs"] if x["verdict"] == "REJECT"]
    assert rejected and all(x["why"]["corrections"] == 1 and x["why"]["decision"] == "PASS"
                            and x["why"]["first_correction"] == "state your uncertainty"
                            and x["why"]["below_min_score"] is False for x in rejected)
    assert r["summary"]["correct_accepted"]["k"] == 0 and r["summary"]["false_accept"]["k"] == 0


def test_rejection_why_is_clipped_and_empty_for_unparsable_output():
    assert je.rejection_why("not json", 70) == {}
    long = json.dumps({"decision": "REVIEW", "quality_score": 10, "findings": [], "required_corrections": [],
                       "reason": "x" * 1000})
    w = je.rejection_why(long, 70)
    assert len(w["reason"]) == 160 and w["below_min_score"] is True and w["corrections"] == 0
