"""The v2 labelled set: reproducible, labels independently re-derived, v1 preserved."""
import hashlib
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
V1 = ROOT / "tests" / "data" / "judge_eval.json"
V2 = ROOT / "tests" / "data" / "judge_eval_v2.json"


def _gen():
    spec = importlib.util.spec_from_file_location("make_v2", ROOT / "scripts" / "make_judge_eval_v2.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.build()


def test_committed_file_is_exactly_what_the_generator_produces():
    assert json.loads(V2.read_text(encoding="utf-8")) == _gen()


def test_v1_items_are_preserved_unchanged():
    v1 = json.loads(V1.read_text(encoding="utf-8"))["items"]
    v2 = json.loads(V2.read_text(encoding="utf-8"))["items"]
    assert v2[:len(v1)] == v1


def test_enough_wrong_answers_for_a_15_percent_bound_to_be_reachable_with_a_few_misses():
    items = json.loads(V2.read_text(encoding="utf-8"))["items"]
    wrong = [i for i in items if i["label"] == "wrong"]
    assert len(wrong) >= 70 and len({i["id"] for i in items}) == len(items)


def test_generated_labels_are_correct_by_an_independent_derivation():
    factor = {"minutes": 60, "seconds": 60, "days": 7, "centimetres": 100, "grams": 1000}
    checked = 0
    for i in json.loads(V2.read_text(encoding="utf-8"))["items"]:
        t, o, good = i["task"], i["output"], i["label"] == "correct"
        if m := re.match(r"What is (\d+) ([+\-*]) (\d+)\?", t):
            a, b = int(m[1]), int(m[3])
            truth = {"+": a + b, "-": a - b, "*": a * b}[m[2]]
        elif m := re.match(r"How many (\w+) are in (\d+)", t):
            truth = int(m[2]) * factor[m[1]]
        elif m := re.match(r"How many letters are in the word '(\w+)'", t):
            truth = len(m[1])
        elif m := re.match(r"What is the first letter of the word '(\w+)'", t):
            truth = m[1][0]
        elif m := re.match(r"Write the word '(\w+)' backwards", t):
            truth = m[1][::-1]
        else:
            continue                                  # hand-written v1 item
        assert (str(truth) == o) == good, i
        checked += 1
    assert checked >= 90


def test_the_calibration_canary_is_not_in_the_set():
    from ola_pipeline.verify import CANARY_TASK
    assert all(i["task"] != CANARY_TASK for i in json.loads(V2.read_text(encoding="utf-8"))["items"])
