#!/usr/bin/env python3
"""Measure an Igor judge against a labelled answer set.

The Gate trusts a PASS only if the judge rejected one known-wrong canary ("2 + 2 = 5"). That is a
single data point. This script runs the SAME judge prompt (ola_pipeline.igor.build_messages) and the
SAME acceptance rule as Igor.verify over a set of correct and wrong answers with known labels, and
reports how often the judge accepts a wrong answer.

    python scripts/judge_eval.py --model llama3.2:3b [--think 0|1] [--base-url URL] [--out result.json]

Reading the result:
  * false_accept  = a WRONG answer the judge would PASS. This is the number that matters for trust.
  * NO_VERDICT    = timeout / provider error / unusable JSON. Igor treats it as BLOCK (fail closed),
                    so it counts as safe for wrong answers and as a miss for correct ones.
  * Counts are small: every rate is printed with a Wilson 95% interval. A set of ~47 items shows
    gross failures, it does not certify a judge. Exit code 2 = no verdict was obtained at all
    (nothing ran: the result is UNKNOWN, not "0 false accepts").
The harness judges content only: it passes an empty evidence_checks list, exactly like the canary.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ola_pipeline.config import DEFAULT_REQUIREMENTS, Policy, ProviderConfig  # noqa: E402
from ola_pipeline.errors import OlaPipelineError, ProviderTimeout  # noqa: E402
from ola_pipeline.igor import judge_prompt_fingerprint, parse_judge  # noqa: E402
from ola_pipeline.providers import build_provider  # noqa: E402
from ola_pipeline.verify import CANARY_TASK  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from judge_variants import spec as variant_spec  # noqa: E402

DEFAULT_DATASET = ROOT / "tests" / "data" / "judge_eval.json"
ACCEPT, REJECT, NO_VERDICT = "ACCEPT", "REJECT", "NO_VERDICT"


def rejection_why(text: str, min_quality_score: int) -> Dict[str, Any]:
    """Why a REJECT was a REJECT (diagnosis only: not used by any acceptance decision or qualification)."""
    judged, _ = parse_judge(text or "")
    if judged is None:
        return {}
    clip = lambda v: str(v)[:160]  # noqa: E731
    corr = judged["required_corrections"]
    return {"decision": judged["decision"], "quality_score": judged["quality_score"],
            "below_min_score": judged["quality_score"] < min_quality_score, "corrections": len(corr),
            "reason": clip(judged["reason"]), "first_correction": clip(corr[0]) if corr else ""}


def load_dataset(path: Path) -> Tuple[List[Dict[str, Any]], str]:
    raw = path.read_bytes()
    doc = json.loads(raw.decode("utf-8"))
    items = doc["items"]
    ids = [i["id"] for i in items]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate item ids")
    for i in items:
        if i.get("label") not in ("correct", "wrong"):
            raise ValueError(f"item {i.get('id')}: label must be 'correct' or 'wrong'")
        if i["task"] == CANARY_TASK:
            raise ValueError(f"item {i['id']}: the calibration canary task must not be part of the set")
    return items, hashlib.sha256(raw).hexdigest()


def classify(text: str, min_quality_score: int) -> Tuple[str, str]:
    """Same acceptance rule as Igor.verify: PASS, no outstanding corrections, score >= minimum."""
    judged, err = parse_judge(text or "")
    if judged is None:
        return NO_VERDICT, err
    if judged["decision"] == "PASS" and not judged["required_corrections"] \
            and judged["quality_score"] >= min_quality_score:
        return ACCEPT, ""
    return REJECT, ""


def wilson(k: int, n: int, z: float = 1.96) -> Tuple[Optional[float], Optional[float]]:
    """Wilson score interval for a proportion k/n (None, None when n == 0)."""
    if n <= 0:
        return None, None
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, centre - half), min(1.0, centre + half)


def summarize(runs: List[Dict[str, Any]]) -> Dict[str, Any]:
    wrong = [r for r in runs if r["label"] == "wrong"]
    correct = [r for r in runs if r["label"] == "correct"]
    count = lambda rs, v: sum(1 for r in rs if r["verdict"] == v)  # noqa: E731
    fa, ok = count(wrong, ACCEPT), count(correct, ACCEPT)
    accepted_total = fa + ok

    def rate(k: int, n: int) -> Dict[str, Any]:
        lo, hi = wilson(k, n)
        return {"k": k, "n": n, "rate": (k / n) if n else None, "wilson95": [lo, hi]}

    by_cat: Dict[str, Dict[str, int]] = {}
    for r in runs:
        c = by_cat.setdefault(r["category"], {"wrong_n": 0, "false_accept": 0, "correct_n": 0, "accepted": 0})
        if r["label"] == "wrong":
            c["wrong_n"] += 1
            c["false_accept"] += r["verdict"] == ACCEPT
        else:
            c["correct_n"] += 1
            c["accepted"] += r["verdict"] == ACCEPT
    return {
        "verdicts_obtained": sum(1 for r in runs if r["verdict"] != NO_VERDICT),
        "runs": len(runs),
        "false_accept": rate(fa, len(wrong)),                       # wrong answers the judge would PASS
        "wrong_rejected": rate(count(wrong, REJECT), len(wrong)),
        "wrong_no_verdict": rate(count(wrong, NO_VERDICT), len(wrong)),
        "correct_accepted": rate(ok, len(correct)),
        "correct_rejected": rate(count(correct, REJECT), len(correct)),
        "correct_no_verdict": rate(count(correct, NO_VERDICT), len(correct)),
        "pass_precision": rate(ok, accepted_total),                 # of everything PASSed, how much was correct
        "by_category": by_cat,
    }


def evaluate(items: List[Dict[str, Any]], cfg: ProviderConfig, policy: Policy, *, repeat: int = 1,
             requirements: Tuple[str, ...] = DEFAULT_REQUIREMENTS,
             provider_factory: Callable[[ProviderConfig], Any] = build_provider,
             log: Callable[[str], None] = lambda s: None, variant: str = "baseline") -> Dict[str, Any]:
    builder, effective_requirements = variant_spec(variant, requirements)
    provider = provider_factory(cfg)
    runs: List[Dict[str, Any]] = []
    meta: Dict[str, Any] = {"runtime_kind": None, "model_digest": None, "ollama_version": None, "resolved_model": None}
    for item in items:
        for rep in range(repeat):
            messages = builder(item["task"], item["output"], [], effective_requirements)
            t0 = time.monotonic()
            detail, text = "", None
            try:
                gen = provider.execute(messages, json_mode=True)
                text = gen.text
                proof = gen.runtime_proof or {}
                meta.update(runtime_kind=proof.get("kind"), model_digest=gen.model_digest,
                            ollama_version=proof.get("ollama_version"), resolved_model=getattr(gen, "resolved_model", None))
                verdict, detail = classify(text, policy.min_quality_score)
            except ProviderTimeout:
                verdict, detail = NO_VERDICT, "TIMEOUT"
            except OlaPipelineError as e:
                verdict, detail = NO_VERDICT, f"{type(e).__name__}: {e}"[:200]
            run = {"id": item["id"], "category": item["category"], "label": item["label"], "rep": rep,
                   "verdict": verdict, "detail": detail, "seconds": round(time.monotonic() - t0, 2)}
            if verdict == REJECT:
                run["why"] = rejection_why(text, policy.min_quality_score)
            runs.append(run)
            log(f"{item['id']:<9} {item['label']:<8} -> {verdict}{(' (' + detail + ')') if detail else ''}")
    flips = 0
    if repeat > 1:
        by_id: Dict[str, set] = {}
        for r in runs:
            by_id.setdefault(r["id"], set()).add(r["verdict"])
        flips = sum(1 for v in by_id.values() if len(v) > 1)
    return {"meta": meta, "summary": summarize(runs), "items_with_changing_verdict": flips, "runs": runs,
            "variant": variant, "requirements": list(effective_requirements),
            "judge_prompt_sha256": judge_prompt_fingerprint(effective_requirements, policy.min_quality_score,
                                                            builder=builder)}


def _pct(r: Dict[str, Any]) -> str:
    if not r["n"]:
        return "n/a"
    lo, hi = r["wilson95"]
    return f"{r['k']}/{r['n']} ({100 * r['rate']:.0f}%, 95% CI {100 * lo:.0f}-{100 * hi:.0f}%)"


def summary_line(result: Dict[str, Any], model: str, think: Optional[bool]) -> str:
    s, m = result["summary"], result["meta"]
    return (f"JUDGE EVAL: model={model} think={think if think is not None else 'unset'} runtime={m['runtime_kind']} "
            f"| WRONG accepted {_pct(s['false_accept'])}; wrong no-verdict {_pct(s['wrong_no_verdict'])} "
            f"| CORRECT accepted {_pct(s['correct_accepted'])}; correct no-verdict {_pct(s['correct_no_verdict'])} "
            f"| PASS precision {_pct(s['pass_precision'])}")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", required=True)
    ap.add_argument("--provider", default="ollama-local")
    ap.add_argument("--base-url", default="")
    ap.add_argument("--think", choices=("0", "1"), default=None, help="Ollama `think` flag; omit for non-reasoning models")
    ap.add_argument("--timeout", type=float, default=300.0)
    ap.add_argument("--max-tokens", type=int, default=None)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--repeat", type=int, default=1, help="judge every item N times (measures verdict changes)")
    ap.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    ap.add_argument("--limit", type=int, default=None, help="first N items only (smoke test)")
    ap.add_argument("--min-quality-score", type=int, default=70)
    ap.add_argument("--variant", default="baseline",
                    help="judge prompt variant (scripts/judge_variants.py); only 'baseline' can qualify the production judge")
    ap.add_argument("--out", type=Path, default=None)
    a = ap.parse_args(argv)

    items, dataset_sha = load_dataset(a.dataset)
    if a.limit:
        items = items[: a.limit]
    think = None if a.think is None else a.think == "1"
    cfg = ProviderConfig(a.provider, a.model, base_url=a.base_url, timeout_s=a.timeout, temperature=0.0,
                         seed=a.seed, max_tokens=a.max_tokens, think=think)
    result = evaluate(items, cfg, Policy(min_quality_score=a.min_quality_score), repeat=a.repeat,
                      log=lambda s: print(s, flush=True), variant=a.variant)
    result.update(schema="ola.judge-eval/1", model=a.model, provider=a.provider, think=think, repeat=a.repeat,
                  dataset_sha256=dataset_sha, items=len(items), min_quality_score=a.min_quality_score)
    line = summary_line(result, a.model, think) + f" | variant={result['variant']} prompt={result['judge_prompt_sha256'][:12]}"
    print(line)
    print(f"items with a changing verdict across {a.repeat} repeat(s): {result['items_with_changing_verdict']}")
    if a.out:
        a.out.write_text(json.dumps(result, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    if result["summary"]["verdicts_obtained"] == 0:
        print("NO VERDICT OBTAINED: nothing ran against the judge, the result is UNKNOWN", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
