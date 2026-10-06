#!/usr/bin/env python3
"""Checks run by .github/workflows/cfr-docker.yml on what the container range produced (stdlib only; runnable by hand).
Every check prints ONE line and exits 0, or says what is wrong and exits 1. Nothing here is a score: it asks whether the
mechanics worked (the fault is visible, the fix is accepted, the hidden assertions hold, a restart is observed, the
independent witness agrees within the manifest's tolerance).

  ci_check.py assertions FILE id=pass|fail [id=...]   FILE: the JSON lines assertions.sh prints; every listed id must match
  ci_check.py all-pass FILE MANIFEST                   every assertion the manifest names (visible + hidden) is `pass`
  ci_check.py metrics FILE [--recovered] [--blast-radius N] [--restarts N] [--min-restarts N]
                           [--min-availability X] [--max-availability X]
  ci_check.py witness RANGE_METRICS_FILE OBSERVATION_FILE MANIFEST
"""
import argparse
import json
import os
import sys
from pathlib import Path


def _fail(msg: str) -> int:
    print(f"FAIL: {msg}")
    if os.environ.get("GITHUB_ACTIONS") == "true":          # a red check says why as an annotation (readable via REST)
        esc = msg.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::error title=cfr container check failed::{esc[:1500]}")
    return 1


def _assertions(path: str) -> dict:
    out = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            row = json.loads(line)
            out[row["id"]] = row["result"]
    return out


def _json(path: str):
    text = Path(path).read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except ValueError:
        raise SystemExit(_fail(f"{path} is not JSON: {text.strip()[:200]!r}"))


def cmd_assertions(a) -> int:
    got = _assertions(a.file)
    bad = []
    for item in a.expect:
        key, _, want = item.partition("=")
        if want not in ("pass", "fail"):
            return _fail(f"bad expectation {item!r}")
        if got.get(key) != want:
            bad.append(f"{key}: expected {want}, got {got.get(key)!r}")
    if bad:
        return _fail("; ".join(bad) + f" | all: {got}")
    print("assertions as expected: " + ", ".join(a.expect))
    return 0


def cmd_all_pass(a) -> int:
    got = _assertions(a.file)
    manifest = _json(a.manifest)
    ids = list(manifest["required_assertions"]) + list(manifest["hidden_assertions"])
    bad = {i: got.get(i, "missing") for i in ids if got.get(i) != "pass"}
    if bad:
        return _fail(f"not pass: {bad}")
    print(f"all {len(ids)} assertions pass (visible + hidden)")
    return 0


def cmd_metrics(a) -> int:
    m = _json(a.file)
    bad = []
    if a.recovered and not isinstance(m.get("mttr_s"), (int, float)):
        bad.append(f"never recovered (mttr_s={m.get('mttr_s')!r})")
    if a.blast_radius is not None and m.get("blast_radius") != a.blast_radius:
        bad.append(f"blast_radius {m.get('blast_radius')!r} != {a.blast_radius}")
    if a.restarts is not None and m.get("restarts") != a.restarts:
        bad.append(f"restarts {m.get('restarts')!r} != {a.restarts}")
    if a.min_restarts is not None and not (isinstance(m.get("restarts"), int) and m["restarts"] >= a.min_restarts):
        bad.append(f"restarts {m.get('restarts')!r} < {a.min_restarts}")
    av = m.get("availability")
    if a.min_availability is not None and not (isinstance(av, (int, float)) and av >= a.min_availability):
        bad.append(f"availability {av!r} < {a.min_availability}")
    if a.max_availability is not None and not (isinstance(av, (int, float)) and av <= a.max_availability):
        bad.append(f"availability {av!r} > {a.max_availability} (a fault that was injected must cost something)")
    if bad:
        return _fail("; ".join(bad) + f" | metrics: {m}")
    print("metrics: " + " ".join(f"{k}={m.get(k)}" for k in ("availability", "latency_p95_ms", "mttr_s", "blast_radius", "restarts",
                                                             "downtime_s")))
    return 0


def cmd_witness(a) -> int:
    rm, obs, manifest = _json(a.range_metrics), _json(a.observation), _json(a.manifest)
    wm = obs["metrics"]
    tol = manifest["independent_measurement"]["tolerance"]
    bad = []
    for key in ("mttr_s", "availability", "downtime_s", "latency_p95_ms"):
        if not isinstance(rm.get(key), (int, float)) or not isinstance(wm.get(key), (int, float)):
            bad.append(f"{key}: range={rm.get(key)!r} witness={wm.get(key)!r} (one side did not measure it)")
    if not bad:
        d = {k: abs(rm[k] - wm[k]) for k in ("mttr_s", "availability", "downtime_s")}
        d["latency_p95_rel"] = abs(rm["latency_p95_ms"] - wm["latency_p95_ms"]) / max(rm["latency_p95_ms"], wm["latency_p95_ms"], 1e-9)
        for key in ("mttr_s", "availability", "downtime_s", "latency_p95_rel"):
            if d[key] > tol[key]:
                bad.append(f"{key}: |range - witness| = {d[key]:.4f} > tolerance {tol[key]}")
    if bad:
        return _fail("; ".join(bad))
    print("witness agrees with the range within the manifest tolerance: " +
          " ".join(f"{k}(range/witness)={rm[k]}/{wm[k]}" for k in ("availability", "latency_p95_ms", "mttr_s", "downtime_s")))
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="ci_check.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("assertions"); s.add_argument("file"); s.add_argument("expect", nargs="+"); s.set_defaults(fn=cmd_assertions)
    s = sub.add_parser("all-pass"); s.add_argument("file"); s.add_argument("manifest"); s.set_defaults(fn=cmd_all_pass)
    s = sub.add_parser("metrics"); s.add_argument("file"); s.add_argument("--recovered", action="store_true")
    s.add_argument("--blast-radius", type=int); s.add_argument("--restarts", type=int); s.add_argument("--min-restarts", type=int)
    s.add_argument("--min-availability", type=float); s.add_argument("--max-availability", type=float); s.set_defaults(fn=cmd_metrics)
    s = sub.add_parser("witness"); s.add_argument("range_metrics"); s.add_argument("observation"); s.add_argument("manifest")
    s.set_defaults(fn=cmd_witness)
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
