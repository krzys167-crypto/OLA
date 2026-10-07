#!/usr/bin/env python3
"""Build tests/data/judge_eval_v2.json: the v1 set plus generated items whose labels are correct BY CONSTRUCTION.

Why: with n = 26 wrong answers (v1) the 95% Wilson upper bound of the false-accept rate is 12.9% at 0/26 and 18.9% at
1/26, so a 15% limit can only be met by a judge that never accepts a wrong answer - the set, not the judge, is the limit.
v2 has 72 wrong answers (0/72 -> 5.1%, 2/72 -> 9.6%, 4/72 -> 13.4%, 5/72 -> 15.2%). Everything is seeded and deterministic:

    python scripts/make_judge_eval_v2.py > tests/data/judge_eval_v2.json

Generated categories (exact answers computed in code, wrong ones are plausible near-misses):
  arith2   two-operand arithmetic          units   fixed conversions (minutes in N hours, ...)
  strings  length / first letter / reverse of a word
"""
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
V1 = ROOT / "tests" / "data" / "judge_eval.json"


def pair(cat, idx, task, right, wrong):
    base = dict(category=cat, task=task)
    return [dict(id=f"{cat}-{idx:02d}c", output=str(right), label="correct", **base),
            dict(id=f"{cat}-{idx:02d}w", output=str(wrong), label="wrong", **base)]


def near_miss(rng, value, lo=1):
    """A plausible wrong integer: off by 1-10, or digits swapped; never equal to value."""
    while True:
        kind = rng.choice(("off", "off", "swap"))
        if kind == "off":
            w = value + rng.choice((-1, 1)) * rng.randint(1, 10)
        else:
            s = str(abs(value))
            if len(s) < 2:
                continue
            i = rng.randrange(len(s) - 1)
            w = int(s[:i] + s[i + 1] + s[i] + s[i + 2:]) * (1 if value >= 0 else -1)
        if w != value and w >= lo - 10**9:
            return w


def build():
    doc = json.loads(V1.read_text(encoding="utf-8"))
    items = list(doc["items"])
    rng = random.Random(20261005)
    for i in range(1, 25):
        op = rng.choice(("+", "-", "*"))
        a, b = (rng.randint(11, 99), rng.randint(11, 99)) if op != "*" else (rng.randint(12, 49), rng.randint(3, 19))
        r = {"+": a + b, "-": a - b, "*": a * b}[op]
        items += pair("arith2", i, f"What is {a} {op} {b}? Answer with the number only.", r, near_miss(rng, r))
    units = [("How many minutes are in {n} hours? Answer with the number only.", 60),
             ("How many seconds are in {n} minutes? Answer with the number only.", 60),
             ("How many days are in {n} weeks? Answer with the number only.", 7),
             ("How many centimetres are in {n} metres? Answer with the number only.", 100),
             ("How many grams are in {n} kilograms? Answer with the number only.", 1000)]
    for i in range(1, 11):
        t, f = units[(i - 1) % len(units)]
        n = rng.randint(2, 19)
        items += pair("units", i, t.format(n=n), n * f, near_miss(rng, n * f))
    words = ["planet", "window", "garden", "bridge", "silver", "market", "orange", "pencil", "rocket", "forest", "castle", "button"]
    rng.shuffle(words)
    for i, w in enumerate(words, 1):
        kind = ("length", "first", "reverse")[(i - 1) % 3]
        if kind == "length":
            items += pair("strings", i, f"How many letters are in the word '{w}'? Answer with the number only.", len(w), len(w) + rng.choice((-1, 1)))
        elif kind == "first":
            wrong = next(c for c in w[1:] if c != w[0])
            items += pair("strings", i, f"What is the first letter of the word '{w}'? Answer with the letter only.", w[0], wrong)
        else:
            wr = list(w[::-1]); j = rng.randrange(len(wr) - 1)
            while wr[j] == wr[j + 1]:
                j = rng.randrange(len(wr) - 1)
            wr[j], wr[j + 1] = wr[j + 1], wr[j]
            items += pair("strings", i, f"Write the word '{w}' backwards. Answer with the word only.", w[::-1], "".join(wr))
    ids = [x["id"] for x in items]
    assert len(set(ids)) == len(ids)
    return {"schema": doc["schema"], "note": doc["note"] + " v2 = v1 + generated items with labels correct by construction "
            "(scripts/make_judge_eval_v2.py, seed 20261005).", "items": items}


if __name__ == "__main__":
    json.dump(build(), sys.stdout, ensure_ascii=False, indent=1)
    sys.stdout.write("\n")
