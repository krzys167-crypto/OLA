"""Independent observer ("witness") for Certificate Apocalypse.

The runner measures the range with the range's own monitor and attests the numbers. A witness is a SECOND principal with
its own Ed25519 key that watches the same services by itself and signs what IT saw (POST /cfr/witness). The server
compares the two, can only lower the result, and marks it DISPUTED when they disagree (app/cfr.py: reconcile).

What makes it independent here (and what does not)
  own probe loop     its own timeline (state-witness/timeline.jsonl), its own clock samples; it never reads the range's
                     timeline.jsonl or events.jsonl
  pinned trust anchor the range CA is copied when the witness starts; replacing the CA later (the tempting "fix") does
                     not change what the witness trusts, so the services that break are seen as broken
  own incident start  MTTR runs from the first failure it OBSERVED, not from the injection time the range logged
  own key            enrolled with role `witness`; the server refuses a runner key as a witness key
What does not make it independent: in local-process mode the participant and the witness share a machine, so a participant
who can read the witness key or stop its process can defeat it. The protocol enforces separate keys and cross-checks; WHERE
the witness runs (a host the participant cannot reach) is the deployment's job.

Subcommands
  up       start the observer daemon (--range-state: where the range keeps ports.json, certs/ca.crt and run.json)
  down     stop it
  observe  print the observation (metrics + assertions) it would sign; exit 3 when it observed no incident
  submit   observe, sign with OLA_WITNESS_SEED and POST /cfr/witness
Environment for submit: OLA_URL, OLA_API_KEY, OLA_TENANT_ID, OLA_WITNESS_ID, OLA_WITNESS_SEED (hex Ed25519 seed)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
import cfr_range as rng  # noqa: E402

WITNESS_METRICS = ("availability", "latency_p95_ms", "mttr_s", "downtime_s")


def compute_witness_metrics(timeline: List[Dict[str, Any]], *, stable_s: float = rng.STABLE_S) -> Optional[Dict[str, Any]]:
    """What a witness can see from outside. None = it saw no failure (nothing to measure) or fewer than two rounds.

    The incident starts at the first round in which ANY service failed a verified probe. Then the same definitions as the
    range's metrics apply (rng.compute_metrics), computed from THIS timeline only.
    """
    rounds = sorted((r for r in timeline if isinstance(r.get("results"), dict) and set(r["results"]) >= set(rng.SERVICES)),
                    key=lambda r: r["t"])
    first_bad = next((r["t"] for r in rounds if any(not p["ok"] for p in r["results"].values())), None)
    if first_bad is None or len(rounds) < 2:
        return None
    m = rng.compute_metrics(rounds, [{"t": first_bad, "event": "fault_injected"}], stable_s=stable_s)
    return None if m is None else {k: m[k] for k in WITNESS_METRICS}


def stable_now(timeline: List[Dict[str, Any]], stable_s: float) -> str:
    """pass: the latest `stable_s` seconds of this timeline hold only fully healthy rounds (and the window is covered)."""
    rounds = sorted((r for r in timeline if isinstance(r.get("results"), dict) and set(r["results"]) >= set(rng.SERVICES)),
                    key=lambda r: r["t"])
    if len(rounds) < 2:
        return "unknown"
    end = rounds[-1]["t"]
    if end - rounds[0]["t"] < stable_s:
        return "unknown"
    window = [r for r in rounds if r["t"] >= end - stable_s]
    return "pass" if all(p["ok"] for r in window for p in r["results"].values()) else "fail"


# ------------------------------------------------------------------ daemon
def _run(wstate: Path, range_state: Path) -> Dict[str, Any]:
    return json.loads((range_state / "run.json").read_text())


def serve(wstate: Path, range_state: Path) -> None:
    host = rng.host_for(_run(wstate, range_state)["seed"])
    ca = wstate / "ca.crt"
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *a: stop.set())
    signal.signal(signal.SIGINT, lambda *a: stop.set())
    (wstate / "ready").write_text("1")
    while not stop.is_set():
        t = rng.now()
        try:
            ports = json.loads((range_state / "ports.json").read_text())
        except (OSError, ValueError):
            ports = {}
        if set(ports) >= set(rng.SERVICES):
            res = {svc: rng.probe(int(ports[svc]), host, ca) for svc in rng.SERVICES}
            rng._append(wstate / "timeline.jsonl", {"t": t, "results": res})
        stop.wait(rng.INTERVAL_S)


def cmd_up(a) -> int:
    ws, rs = Path(a.state), Path(a.range_state)
    if (ws / "witness.pid").is_file():
        print("witness already running", file=sys.stderr)
        return 1
    ca_src = rs / "certs" / "ca.crt"
    if not ca_src.is_file() or not (rs / "run.json").is_file():
        print("the range must be up (certs/ca.crt) and a run issued (run.json) first", file=sys.stderr)
        return 2
    ws.mkdir(parents=True, exist_ok=True)
    for f in ("timeline.jsonl", "ready"):
        (ws / f).unlink(missing_ok=True)
    shutil.copyfile(ca_src, ws / "ca.crt")                              # the pinned trust anchor
    log = open(ws / "witness.log", "ab")
    proc = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--state", str(ws), "--range-state", str(rs),
                             "serve"], stdout=log, stderr=log, start_new_session=True)
    (ws / "witness.pid").write_text(str(proc.pid))
    for _ in range(100):
        if (ws / "ready").exists():
            print(f"witness up: pid={proc.pid}")
            return 0
        time.sleep(0.1)
    print("witness did not become ready; see witness.log", file=sys.stderr)
    return 1


def cmd_serve(a) -> int:
    serve(Path(a.state), Path(a.range_state))
    return 0


def cmd_down(a) -> int:
    ws = Path(a.state)
    pid_file = ws / "witness.pid"
    if pid_file.is_file():
        try:
            os.kill(int(pid_file.read_text()), signal.SIGTERM)
        except (OSError, ValueError):
            pass
        pid_file.unlink(missing_ok=True)
    return 0


# ------------------------------------------------------------------ observation
def build_observation(wstate: Path, range_state: Path, stable_s: float = rng.STABLE_S) -> Optional[Dict[str, Any]]:
    """The observation this witness stands behind, from ITS OWN timeline and ITS pinned CA. None = nothing observed."""
    run = _run(wstate, range_state)
    timeline = rng.read_lines(wstate / "timeline.jsonl")
    metrics = compute_witness_metrics(timeline, stable_s=stable_s)
    if metrics is None:
        return None
    # The TLS assertions are checked against a view that holds the PINNED CA and the current ports, never the range's CA.
    view = wstate / "view"
    (view / "certs").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(wstate / "ca.crt", view / "certs" / "ca.crt")
    shutil.copyfile(range_state / "ports.json", view / "ports.json")
    import score as sc
    got = {a["id"]: a["result"] for a in sc.collect_assertions(view, rng.host_for(run["seed"]), stable_s=1)}
    got["health_stable_10s"] = stable_now(timeline, stable_s)           # from the continuous observation, not a 1 s check
    ids = json.loads((HERE / "manifest.json").read_text())
    assertions = [{"id": i, "result": got.get(i, "unknown")} for i in ids["required_assertions"] + ids["hidden_assertions"]]
    tl = wstate / "timeline.jsonl"
    return {"run_id": run["run_id"], "manifest_sha256": run["manifest_sha256"],
            "observed_from": min(r["t"] for r in timeline), "observed_until": time.time(),
            "metrics": metrics, "assertions": assertions,
            "artifacts": {"witness_timeline": hashlib.sha256(tl.read_bytes()).hexdigest(),
                          "pinned_ca": hashlib.sha256((wstate / "ca.crt").read_bytes()).hexdigest()}}


def sign_and_post(api: Any, tenant_id: str, witness_id: str, witness_seed: str, observation: Dict[str, Any]) -> Any:
    sys.path.insert(0, str(REPO))
    from app import cfr                                                    # the signing helper lives with the server
    body = dict(observation)
    body["auth"] = cfr.sign_witness(witness_seed, tenant_id, witness_id, observation)
    return api.post("/cfr/witness", body)


def cmd_observe(a) -> int:
    obs = build_observation(Path(a.state), Path(a.range_state), a.stable_s)
    print(json.dumps(obs, indent=2) if obs else "UNKNOWN: this witness observed no incident (no failed probe)")
    return 0 if obs else 3


def cmd_submit(a) -> int:
    import httpx
    import score as sc
    url, key = os.environ.get("OLA_URL"), os.environ.get("OLA_API_KEY")
    if not url or not key:
        print("OLA_URL and OLA_API_KEY are required", file=sys.stderr)
        return 2
    obs = build_observation(Path(a.state), Path(a.range_state), a.stable_s)
    if obs is None:
        print("UNKNOWN: nothing to submit (no failed probe was observed)", file=sys.stderr)
        return 3
    api = sc.Api(httpx.Client(base_url=url, timeout=30.0, trust_env=False), key)
    r = sign_and_post(api, os.environ["OLA_TENANT_ID"], os.environ["OLA_WITNESS_ID"], os.environ["OLA_WITNESS_SEED"], obs)
    print(r.text)
    return 0 if r.status_code == 200 else 1


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="witness.py")
    p.add_argument("--state", default="state-witness")
    p.add_argument("--range-state", default="state")
    p.add_argument("--stable-s", type=float, default=rng.STABLE_S)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn in (("up", cmd_up), ("serve", cmd_serve), ("down", cmd_down), ("observe", cmd_observe), ("submit", cmd_submit)):
        sub.add_parser(name).set_defaults(fn=fn)
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
