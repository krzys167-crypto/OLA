"""Runner side of Certificate Apocalypse: measure, collect assertions, submit a SIGNED result.

The score is NOT computed here. This script sends metrics and assertion results; the OLA server recomputes the score
and the tier from the registered manifest (POST /cfr/results). A `--preview` score is printed only when the repository
is importable, and is labelled as a preview.

Subcommands
  register  operator: POST the manifest (needs the enrolment token)
  issue     POST /cfr/runs -> state/run.json (run_id, manifest digest, variant, seed)
  submit    metrics + assertions -> signed POST /cfr/results
Environment: OLA_URL, OLA_API_KEY, OLA_ENROLL_TOKEN (register), OLA_RUNNER_ID, OLA_RUNNER_SEED (hex, Ed25519 seed)
HONEST LIMIT: the runner attests the metrics. The signature proves which runner key said so, not that it is true.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
import cfr_range as rng  # noqa: E402

MANIFEST = HERE / "manifest.json"


def collect_assertions(state: Path, host: str, stable_s: float = rng.STABLE_S, timeout: float = 120.0) -> List[Dict[str, str]]:
    """Run assertions.sh. Anything that is not a clean pass/fail/unknown line becomes `unknown`: never a pass."""
    env = {**os.environ, "STATE": str(state), "HOST": host, "STABLE_S": str(int(stable_s))}
    try:
        out = subprocess.run([str(HERE / "assertions.sh")], env=env, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.TimeoutExpired):
        out = ""
    got: Dict[str, str] = {}
    for line in out.splitlines():
        try:
            o = json.loads(line)
        except ValueError:
            continue
        if isinstance(o, dict) and isinstance(o.get("id"), str) and o.get("result") in ("pass", "fail", "unknown"):
            got[o["id"]] = o["result"]
    manifest = json.loads(MANIFEST.read_text())
    ids = manifest["required_assertions"] + manifest["hidden_assertions"]
    return [{"id": a, "result": got.get(a, "unknown")} for a in ids]


def artifact_digests(state: Path) -> Dict[str, str]:
    out = {}
    for name, f in (("timeline", "timeline.jsonl"), ("events", "events.jsonl"), ("ca_crt", "certs/ca.crt")):
        p = state / f
        if p.is_file():
            out[name] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def build_submission(state: Path, stable_s: float = rng.STABLE_S) -> Optional[Dict[str, Any]]:
    run = json.loads((state / "run.json").read_text())
    timeline, events = rng.read_lines(state / "timeline.jsonl"), rng.read_lines(state / "events.jsonl")
    metrics = rng.compute_metrics(timeline, events, stable_s=stable_s)
    if metrics is None:
        return None
    assertions = collect_assertions(state, rng.host_for(run["seed"]), stable_s)
    return {"run_id": run["run_id"], "manifest_sha256": run["manifest_sha256"],
            "started_at": min(r["t"] for r in timeline), "ended_at": time.time(),
            "metrics": metrics, "assertions": assertions, "artifacts": artifact_digests(state)}


class Api:
    """Thin wrapper over an httpx.Client or a Starlette TestClient."""

    def __init__(self, client: Any, api_key: str):
        self.c, self.h = client, {"X-API-Key": api_key}

    def post(self, path: str, body: Dict[str, Any], extra: Optional[Dict[str, str]] = None) -> Any:
        return self.c.post(path, headers={**self.h, **(extra or {})}, json=body)

    def get(self, path: str) -> Any:
        return self.c.get(path, headers=self.h)


def register(api: Api, token: str) -> Dict[str, Any]:
    r = api.post("/cfr/scenarios", {"manifest": json.loads(MANIFEST.read_text())}, {"X-Enroll-Token": token})
    r.raise_for_status()
    return r.json()


def issue(api: Api, state: Path, participant_id: str, runner_id: Optional[str] = None) -> Dict[str, Any]:
    body = {"scenario_id": json.loads(MANIFEST.read_text())["scenario_id"], "participant_id": participant_id}
    if runner_id:
        body["runner_id"] = runner_id            # the only runner allowed to report this run (required in signed mode)
    r = api.post("/cfr/runs", body)
    r.raise_for_status()
    run = r.json()
    state.mkdir(parents=True, exist_ok=True)
    (state / "run.json").write_text(json.dumps(run))
    return run


def submit(api: Api, tenant_id: str, runner_id: str, runner_seed: str, submission: Dict[str, Any]) -> Any:
    sys.path.insert(0, str(REPO))
    from app import cfr                                                    # the signing helper lives with the server
    body = dict(submission)
    body["auth"] = cfr.sign_result(runner_seed, tenant_id, runner_id, submission)
    return api.post("/cfr/results", body)


def preview(submission: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        sys.path.insert(0, str(REPO))
        from app import cfr
        m = cfr.validate_manifest(json.loads(MANIFEST.read_text()))
        sc = cfr.score(m, cfr.validate_metrics(submission["metrics"]))
        v = cfr.judge(m, cfr.validate_assertions(m, submission["assertions"]), sc)
        return {"PREVIEW_not_authoritative": True, "score": sc["score"], "state": v["state"], "tier": v["tier"]}
    except Exception:                                                       # noqa: BLE001 - preview is optional
        return None


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="score.py")
    p.add_argument("--state", default="state")
    p.add_argument("--stable-s", type=float, default=rng.STABLE_S)
    p.add_argument("cmd", choices=["register", "issue", "submit", "preview"])
    p.add_argument("--participant", default=os.environ.get("USER", "participant"))
    p.add_argument("--runner", default=os.environ.get("OLA_RUNNER_ID"),
                   help="runner id the run is bound to (default: $OLA_RUNNER_ID)")
    a = p.parse_args(argv)
    st = Path(a.state)
    if a.cmd == "preview":
        sub = build_submission(st, a.stable_s)
        print(json.dumps({"submission": sub, "preview": preview(sub) if sub else None}, indent=2))
        return 0 if sub else 3
    import httpx
    url, key = os.environ.get("OLA_URL"), os.environ.get("OLA_API_KEY")
    if not url or not key:
        print("OLA_URL and OLA_API_KEY are required", file=sys.stderr)
        return 2
    api = Api(httpx.Client(base_url=url, timeout=30.0, trust_env=False), key)
    if a.cmd == "register":
        print(json.dumps(register(api, os.environ["OLA_ENROLL_TOKEN"])))
        return 0
    if a.cmd == "issue":
        run = issue(api, st, a.participant, a.runner)
        print(json.dumps({k: run[k] for k in ("run_id", "manifest_sha256", "expires_in_s")}))
        return 0
    sub = build_submission(st, a.stable_s)
    if sub is None:
        print("UNKNOWN: nothing to submit (no fault was injected or no probes were recorded)", file=sys.stderr)
        return 3
    r = submit(api, os.environ["OLA_TENANT_ID"], os.environ["OLA_RUNNER_ID"], os.environ["OLA_RUNNER_SEED"], sub)
    print(r.text)
    return 0 if r.status_code == 200 else 1


if __name__ == "__main__":
    sys.exit(main())
