"""Code Forensics Range (CFR) integration: a scenario run becomes tenant evidence that cannot be written by the
participant and is scored by the SERVER, never by the runner.

Flow (all state is derived from the tenant chain)
    register_scenario  operator (enrolment token): manifest with SLO, scoring weights, limits, tiers, required and
                       hidden assertions, fault variants -> `cfr.scenario` (manifest digest pinned in every later record)
    issue_run          caller with the tenant key: picks a per-run fault variant and seed from a server-side HMAC
                       secret; the chain keeps only digests -> `cfr.run` (single use, expires)
    submit_result      a RUNNER principal (role `runner`, Ed25519, app/identity.py) signs the measured metrics and
                       assertion results of exactly that run -> the server validates, recomputes the score and tier
                       and records `cfr.result`
    result / leaderboard   read-only views derived from the chain

Rules (each has a test)
* The runner's own score is never read. Score, components and tier are computed here from the registered manifest.
* An assertion that is missing or `unknown` can never produce a pass: state is FAIL if any required assertion failed,
  UNKNOWN if none failed but some are missing/unknown, PASS only if every required assertion passed. A tier is given
  only on PASS.
* One result per run (lowest chain seq wins a race); a run expires; the result must reference the scenario digest the
  run was issued under; times must be consistent; metrics must be in range; unknown or duplicate assertion ids are
  rejected rather than ignored.
* The result is signed by an enrolled, active runner with a fresh single-use nonce, bound to the exact submission.
* Fail closed: no secret configured -> no run; chain must verify; no record, no result.

HONEST LIMITS
* The runner ATTESTS the metrics. A compromised or lying runner can sign false numbers; this proves which runner key
  signed what, and that the server scored it consistently - not that the measurements are true. Measuring in an
  environment the participant cannot touch is the runner's job.
* The per-run seed is returned to the caller of `issue_run`; if that caller is the participant, the anti-LLM property
  (a per-user mutated fault) is lost. Call it from the runner, not from the participant.
* Hidden assertions are hidden from the participant by keeping their ids out of the participant-facing view; the
  manifest and the chain are visible to every holder of the tenant key.
* The scoring weights here follow the CFR DSL v0 shape (availability, latency, time to recover, blast radius,
  penalties, tiers). They are a transparent, pinned heuristic, not a calibrated one.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from . import identity
from . import pipeline_bridge as pb
from .hashchain import canonical_json, verify_chain

SCHEMA = "ola.cfr/1"
SCENARIO_TYPE, RUN_TYPE, RESULT_TYPE = "cfr.scenario", "cfr.run", "cfr.result"
DEFAULT_RUN_TTL_S = 7200
_ID = re.compile(r"^[A-Za-z0-9_.:@-]{1,64}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_RUN = re.compile(r"^run_[0-9a-f]{24}$")
_ASSERT_RESULTS = ("pass", "fail", "unknown")
TIERS = ("pass", "merit", "elite")


class CfrError(ValueError):
    """Malformed input (HTTP 400)."""


class CfrNotFound(LookupError):
    """HTTP 404."""


class CfrConflict(RuntimeError):
    """The chain state does not allow this (HTTP 409)."""


class CfrUnavailable(RuntimeError):
    """Not configured, or evidence cannot be read/written (HTTP 503)."""


def _sha(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _now() -> float:
    return time.time()


def _num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def _ttl() -> int:
    try:
        return pb._int_env("OLA_CFR_RUN_TTL_S", DEFAULT_RUN_TTL_S)
    except pb.PipelineNotConfigured as exc:
        raise CfrUnavailable(str(exc)) from exc


def _secret() -> bytes:
    raw = os.getenv("OLA_CFR_SEED_SECRET", "")
    if len(raw) < 16:
        raise CfrUnavailable("OLA_CFR_SEED_SECRET (at least 16 characters) is required to issue runs")
    return raw.encode("utf-8")


# ------------------------------------------------------------------ manifest
_LIMIT_KEYS = ("availability_zero", "latency_p95_ms_full", "latency_p95_ms_zero", "mttr_s_full", "mttr_s_zero",
               "blast_radius_full", "blast_radius_zero")
_WEIGHT_KEYS = ("availability", "latency", "time_to_recover", "blast_radius")
_PENALTY_KEYS = ("per_restart", "max_restarts_penalty", "downtime_over_s", "downtime_penalty")


def validate_manifest(m: Any) -> Dict[str, Any]:
    """Return a normalised manifest or raise CfrError. Everything that scoring relies on is checked here."""
    if not isinstance(m, dict):
        raise CfrError("manifest must be an object")
    sid, ver = m.get("scenario_id"), m.get("version")
    if not isinstance(sid, str) or not _ID.match(sid):
        raise CfrError("scenario_id must match [A-Za-z0-9_.:@-]{1,64}")
    if not isinstance(ver, str) or not _ID.match(ver):
        raise CfrError("version must match [A-Za-z0-9_.:@-]{1,64}")
    sc = m.get("scoring")
    if not isinstance(sc, dict):
        raise CfrError("scoring is required")
    w, lim, pen, tiers = sc.get("weights"), sc.get("limits"), sc.get("penalties"), sc.get("tiers")
    for name, block, keys in (("weights", w, _WEIGHT_KEYS), ("limits", lim, _LIMIT_KEYS), ("penalties", pen, _PENALTY_KEYS)):
        if not isinstance(block, dict) or set(block) != set(keys) or not all(_num(v) and v >= 0 for v in block.values()):
            raise CfrError(f"scoring.{name} must have exactly {list(keys)} as non-negative numbers")
    if abs(sum(w.values()) - 1.0) > 1e-9:
        raise CfrError("scoring.weights must sum to 1")
    if not 0 <= lim["availability_zero"] < 1:
        raise CfrError("limits.availability_zero must be in [0, 1)")
    if not lim["latency_p95_ms_full"] < lim["latency_p95_ms_zero"]:
        raise CfrError("limits: latency_p95_ms_full must be below latency_p95_ms_zero")
    if not lim["mttr_s_full"] < lim["mttr_s_zero"]:
        raise CfrError("limits: mttr_s_full must be below mttr_s_zero")
    if not lim["blast_radius_full"] < lim["blast_radius_zero"]:
        raise CfrError("limits: blast_radius_full must be below blast_radius_zero")
    if pen["max_restarts_penalty"] > 1 or pen["downtime_penalty"] > 1:
        raise CfrError("penalties are fractions of the score (at most 1)")
    if not isinstance(tiers, dict) or set(tiers) != set(TIERS) or not all(_num(v) for v in tiers.values()):
        raise CfrError("scoring.tiers must have pass, merit and elite")
    if not 0 < tiers["pass"] < tiers["merit"] < tiers["elite"] <= 1:
        raise CfrError("tiers must satisfy 0 < pass < merit < elite <= 1")
    req, hid = m.get("required_assertions"), m.get("hidden_assertions", [])
    for name, lst in (("required_assertions", req), ("hidden_assertions", hid)):
        if not isinstance(lst, list) or len(lst) > 64 or not all(isinstance(a, str) and _ID.match(a) for a in lst) \
                or len(set(lst)) != len(lst):
            raise CfrError(f"{name} must be a list of up to 64 unique ids")
    if not req:
        raise CfrError("at least one required assertion is needed (nothing to pass otherwise)")
    if set(req) & set(hid):
        raise CfrError("an assertion cannot be both required and hidden")
    var = m.get("variants")
    if not isinstance(var, list) or not 1 <= len(var) <= 64 or not all(isinstance(v, str) and _ID.match(v) for v in var) \
            or len(set(var)) != len(var):
        raise CfrError("variants must be 1-64 unique ids")
    return {"scenario_id": sid, "version": ver, "required_assertions": list(req), "hidden_assertions": list(hid),
            "variants": list(var),
            "scoring": {"weights": dict(w), "limits": dict(lim), "penalties": dict(pen), "tiers": dict(tiers)}}


# ------------------------------------------------------------------ scoring (pure)
def _lin(value: float, full: float, zero: float) -> float:
    """1.0 at `full`, 0.0 at `zero`, linear between, clamped; works for lower-is-better (full < zero)."""
    return max(0.0, min(1.0, (zero - value) / (zero - full)))


def validate_metrics(m: Any) -> Dict[str, Any]:
    if not isinstance(m, dict) or set(m) != {"availability", "latency_p95_ms", "mttr_s", "blast_radius", "restarts",
                                             "downtime_s"}:
        raise CfrError("metrics must have exactly availability, latency_p95_ms, mttr_s, blast_radius, restarts, downtime_s")
    a, lat, mttr, blast, rs, down = (m["availability"], m["latency_p95_ms"], m["mttr_s"], m["blast_radius"],
                                     m["restarts"], m["downtime_s"])
    if not _num(a) or not 0 <= a <= 1:
        raise CfrError("metrics.availability must be a number in [0, 1]")
    if not _num(lat) or not 0 <= lat <= 3.6e6:
        raise CfrError("metrics.latency_p95_ms must be a number in [0, 3.6e6]")
    if mttr is not None and (not _num(mttr) or not 0 <= mttr <= 86400 * 7):
        raise CfrError("metrics.mttr_s must be null (never recovered) or a number in [0, 604800]")
    for name, v in (("blast_radius", blast), ("restarts", rs)):
        if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= 100000:
            raise CfrError(f"metrics.{name} must be an integer in [0, 100000]")
    if not _num(down) or not 0 <= down <= 86400 * 7:
        raise CfrError("metrics.downtime_s must be a number in [0, 604800]")
    return {"availability": float(a), "latency_p95_ms": float(lat), "mttr_s": None if mttr is None else float(mttr),
            "blast_radius": blast, "restarts": rs, "downtime_s": float(down)}


def score(manifest: Dict[str, Any], metrics: Dict[str, Any]) -> Dict[str, Any]:
    sc = manifest["scoring"]
    w, lim, pen = sc["weights"], sc["limits"], sc["penalties"]
    comp = {
        "availability": _lin(metrics["availability"], 1.0, lim["availability_zero"]),
        "latency": _lin(metrics["latency_p95_ms"], lim["latency_p95_ms_full"], lim["latency_p95_ms_zero"]),
        "time_to_recover": 0.0 if metrics["mttr_s"] is None else _lin(metrics["mttr_s"], lim["mttr_s_full"], lim["mttr_s_zero"]),
        "blast_radius": _lin(float(metrics["blast_radius"]), lim["blast_radius_full"], lim["blast_radius_zero"]),
    }
    base = sum(w[k] * comp[k] for k in _WEIGHT_KEYS)
    restart_pen = min(pen["max_restarts_penalty"], pen["per_restart"] * metrics["restarts"])
    down_pen = pen["downtime_penalty"] if metrics["downtime_s"] > pen["downtime_over_s"] else 0.0
    total = max(0.0, min(1.0, base - restart_pen - down_pen))
    return {"score": round(total, 6), "components": {k: round(v, 6) for k, v in comp.items()},
            "penalties": {"restarts": round(restart_pen, 6), "downtime": round(down_pen, 6)}}


def judge(manifest: Dict[str, Any], assertions: Dict[str, str], scored: Dict[str, Any]) -> Dict[str, Any]:
    """PASS only if every required assertion passed; FAIL if any failed; otherwise UNKNOWN (never a silent pass)."""
    req = manifest["required_assertions"]
    results = {a: assertions.get(a, "missing") for a in req}
    hidden = {a: assertions.get(a, "missing") for a in manifest["hidden_assertions"]}
    everything = list(results.values()) + list(hidden.values())
    if any(v == "fail" for v in everything):
        state = "FAIL"
    elif all(v == "pass" for v in everything):
        state = "PASS"
    else:
        state = "UNKNOWN"
    tier = "none"
    if state == "PASS":
        t = manifest["scoring"]["tiers"]
        tier = next((n for n in ("elite", "merit", "pass") if scored["score"] >= t[n]), "none")
    return {"state": state, "tier": tier, "required": results, "hidden": hidden}


def validate_assertions(manifest: Dict[str, Any], raw: Any) -> Dict[str, str]:
    if not isinstance(raw, list) or len(raw) > 128:
        raise CfrError("assertions must be a list of at most 128 {id, result}")
    known = set(manifest["required_assertions"]) | set(manifest["hidden_assertions"])
    out: Dict[str, str] = {}
    for item in raw:
        if not isinstance(item, dict) or set(item) != {"id", "result"} or item["result"] not in _ASSERT_RESULTS \
                or not isinstance(item["id"], str):
            raise CfrError("each assertion must be {id, result} with result pass | fail | unknown")
        if item["id"] not in known:
            raise CfrError(f"unknown assertion id {item['id'][:64]!r}")
        if item["id"] in out:
            raise CfrError(f"duplicate assertion id {item['id'][:64]!r}")
        out[item["id"]] = item["result"]
    return out


# ------------------------------------------------------------------ chain access
def _chain(tenant_id: str) -> List[dict]:
    try:
        chain = pb.load_chain(tenant_id)
    except Exception as exc:                                         # noqa: BLE001 - fail closed
        raise CfrUnavailable(f"evidence could not be read ({type(exc).__name__})") from exc
    ok, why = verify_chain(chain)
    if not ok:
        raise CfrUnavailable(f"the tenant evidence chain does not verify ({why})")
    return chain


def _append(tenant_id: str, rtype: str, payload: dict) -> dict:
    try:
        return pb.append_evidence(tenant_id, rtype, payload)
    except Exception as exc:                                         # noqa: BLE001 - no record, no change
        raise CfrUnavailable(f"the record could not be written ({type(exc).__name__})") from exc


def _records(chain: List[dict]):
    for rec in chain:
        if rec["record_type"] in (SCENARIO_TYPE, RUN_TYPE, RESULT_TYPE):
            try:
                p = json.loads(rec["payload_json"])
            except ValueError:
                continue
            if isinstance(p, dict) and p.get("schema") == SCHEMA:
                yield rec, p


def _scenarios(chain: List[dict]) -> Dict[str, Dict[str, Any]]:
    """scenario_id -> {manifest, manifest_sha256, seq}; the FIRST registration of an id wins (no silent re-scoring)."""
    out: Dict[str, Dict[str, Any]] = {}
    for rec, p in _records(chain):
        if rec["record_type"] == SCENARIO_TYPE:
            m = p.get("manifest")
            try:
                norm = validate_manifest(m)
            except CfrError:
                continue
            if norm["scenario_id"] not in out and p.get("manifest_sha256") == _sha(norm):
                out[norm["scenario_id"]] = {"manifest": norm, "manifest_sha256": p["manifest_sha256"], "seq": rec["seq"]}
    return out


def _runs(chain: List[dict]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for rec, p in _records(chain):
        if rec["record_type"] == RUN_TYPE and isinstance(p.get("run_id"), str):
            out.setdefault(p["run_id"], {**p, "seq": rec["seq"]})
    return out


def _results(chain: List[dict]) -> Dict[str, List[Tuple[dict, dict]]]:
    out: Dict[str, List[Tuple[dict, dict]]] = {}
    for rec, p in _records(chain):
        if rec["record_type"] == RESULT_TYPE and isinstance(p.get("run_id"), str):
            out.setdefault(p["run_id"], []).append((rec, p))
    return out


# ------------------------------------------------------------------ operations
def register_scenario(tenant_id: str, manifest: Any, token: Any = None) -> Dict[str, Any]:
    identity._check_enroll_token(token)
    norm = validate_manifest(manifest)
    chain = _chain(tenant_id)
    if norm["scenario_id"] in _scenarios(chain):
        raise CfrConflict("this scenario id is already registered (register a new id or version instead)")
    digest = _sha(norm)
    rec = _append(tenant_id, SCENARIO_TYPE, {"schema": SCHEMA, "scenario_id": norm["scenario_id"], "manifest": norm,
                                             "manifest_sha256": digest, "registered_at": _now()})
    again = _scenarios(_chain(tenant_id))
    if again.get(norm["scenario_id"], {}).get("seq") != rec["seq"]:
        raise CfrConflict("another registration of this scenario was recorded first")
    return {"scenario_id": norm["scenario_id"], "manifest_sha256": digest, "evidence_seq": rec["seq"]}


def issue_run(tenant_id: str, scenario_id: Any, participant_id: Any) -> Dict[str, Any]:
    if not isinstance(scenario_id, str) or not _ID.match(scenario_id):
        raise CfrError("scenario_id is required")
    if not isinstance(participant_id, str) or not _ID.match(participant_id):
        raise CfrError("participant_id must match [A-Za-z0-9_.:@-]{1,64}")
    secret = _secret()
    ttl = _ttl()
    chain = _chain(tenant_id)
    sc = _scenarios(chain).get(scenario_id)
    if sc is None:
        raise CfrNotFound("no such scenario")
    run_id = "run_" + uuid.uuid4().hex[:24]
    mac = hmac.new(secret, canonical_json({"t": tenant_id, "p": participant_id, "s": scenario_id,
                                           "m": sc["manifest_sha256"], "r": run_id}).encode(), hashlib.sha256).digest()
    variants = sc["manifest"]["variants"]
    variant = variants[int.from_bytes(mac[:8], "big") % len(variants)]
    seed = mac.hex()
    now = _now()
    rec = _append(tenant_id, RUN_TYPE, {"schema": SCHEMA, "run_id": run_id, "scenario_id": scenario_id,
                                        "manifest_sha256": sc["manifest_sha256"], "participant_id": participant_id,
                                        "variant_sha256": hashlib.sha256(variant.encode()).hexdigest(),
                                        "seed_sha256": hashlib.sha256(mac).hexdigest(), "issued_at": now,
                                        "expires_at": now + ttl})
    return {"run_id": run_id, "scenario_id": scenario_id, "manifest_sha256": sc["manifest_sha256"], "variant": variant,
            "seed": seed, "expires_in_s": ttl, "evidence_seq": rec["seq"]}


def result_subject(submission: Dict[str, Any]) -> str:
    """What the runner signs: the whole submission except the signature."""
    return _sha({k: submission.get(k) for k in ("run_id", "manifest_sha256", "started_at", "ended_at", "metrics",
                                                "assertions", "artifacts")})


SUBMISSION_KEYS = frozenset({"run_id", "manifest_sha256", "started_at", "ended_at", "metrics", "assertions", "artifacts"})


def sign_result(seed_hex: str, tenant_id: str, runner_id: str, submission: Dict[str, Any], **kw: Any) -> Dict[str, Any]:
    """Client helper (runner side): the `auth` object for POST /cfr/results."""
    auth = identity.sign_request(seed_hex, tenant_id, "cfr.result", runner_id, result_subject(submission), **kw)
    auth["runner_id"] = runner_id
    return auth


def submit_result(tenant_id: str, submission: Any, auth: Any) -> Dict[str, Any]:
    if not isinstance(submission, dict):
        raise CfrError("the result must be an object")
    extra = sorted(set(submission) - SUBMISSION_KEYS)
    if extra:
        raise CfrError(f"unexpected fields {extra[:5]}: the score and tier are computed by the server, not accepted")
    run_id = submission.get("run_id")
    if not isinstance(run_id, str) or not _RUN.match(run_id):
        raise CfrError("run_id is required")
    chain = _chain(tenant_id)
    # identity first: an unauthenticated caller learns nothing about runs
    runner = _runner_from(auth)
    proof = identity.verify(chain, tenant_id, "cfr.result", runner, "runner", result_subject(submission), auth_body(auth))
    run = _runs(chain).get(run_id)
    if run is None:
        raise CfrNotFound("no such run")
    sc = _scenarios(chain).get(run["scenario_id"])
    if sc is None or sc["manifest_sha256"] != run["manifest_sha256"]:
        raise CfrConflict("the scenario of this run is not registered with the same manifest")
    if submission.get("manifest_sha256") != run["manifest_sha256"]:
        raise CfrError("manifest_sha256 does not match the run")
    manifest = sc["manifest"]
    started, ended = submission.get("started_at"), submission.get("ended_at")
    if not (_num(started) and _num(ended)) or ended < started:
        raise CfrError("started_at and ended_at must be numbers with ended_at >= started_at")
    skew = identity._skew()
    now = _now()
    if started < run["issued_at"] - skew:
        raise CfrError("the run started before it was issued")
    if ended > now + skew:
        raise CfrError("the run ends in the future")
    if now > run["expires_at"] or ended > run["expires_at"] + skew:
        raise CfrConflict("this run has expired")
    metrics = validate_metrics(submission.get("metrics"))
    assertions = validate_assertions(manifest, submission.get("assertions"))
    artifacts = submission.get("artifacts", {})
    if not isinstance(artifacts, dict) or len(artifacts) > 64 or not all(
            isinstance(k, str) and _ID.match(k) and isinstance(v, str) and _SHA.match(v) for k, v in artifacts.items()):
        raise CfrError("artifacts must map up to 64 names to lowercase sha256 hex digests")
    if run_id in _results(chain):
        raise CfrConflict("this run already has a result")
    scored = score(manifest, metrics)
    verdict = judge(manifest, assertions, scored)
    payload = {"schema": SCHEMA, "run_id": run_id, "scenario_id": run["scenario_id"],
               "manifest_sha256": run["manifest_sha256"], "participant_id": run["participant_id"],
               "runner_id": runner, "started_at": float(started), "ended_at": float(ended), "metrics": metrics,
               "assertions": assertions, "artifacts": dict(artifacts), "score": scored["score"],
               "components": scored["components"], "penalties": scored["penalties"], "state": verdict["state"],
               "tier": verdict["tier"], "submission_sha256": result_subject(submission), "recorded_at": now,
               "identity": "verified",
               "auth": {k: proof[k] for k in ("principal_id", "role", "key_sha256", "nonce", "ts", "signature_sha256")},
               "attested_by_runner": True}
    rec = _append(tenant_id, RESULT_TYPE, payload)
    first = min(r["seq"] for r, _ in _results(_chain(tenant_id)).get(run_id, []))     # one result per run
    if first != rec["seq"]:
        raise CfrConflict("another result for this run was recorded first")
    return {**_public(payload), "evidence_seq": rec["seq"]}


def _runner_from(auth: Any) -> str:
    if not isinstance(auth, dict) or not isinstance(auth.get("runner_id"), str) or not _ID.match(auth["runner_id"]):
        raise identity.IdentityDenied("a signed request is required (auth.runner_id, ts, nonce, signature)")
    return auth["runner_id"]


def auth_body(auth: Any) -> Any:
    return {k: v for k, v in auth.items() if k != "runner_id"} if isinstance(auth, dict) else auth


def _public(p: Dict[str, Any]) -> Dict[str, Any]:
    return {"run_id": p["run_id"], "scenario_id": p["scenario_id"], "participant_id": p["participant_id"],
            "runner_id": p["runner_id"], "score": p["score"], "components": p["components"],
            "penalties": p["penalties"], "state": p["state"], "tier": p["tier"],
            "manifest_sha256": p["manifest_sha256"], "attested_by_runner": True,
            "note": "scored by the server from runner-attested metrics; not independently measured"}


def result(tenant_id: str, run_id: Any) -> Dict[str, Any]:
    if not isinstance(run_id, str) or not _RUN.match(run_id):
        raise CfrError("run_id is required")
    chain = _chain(tenant_id)
    run = _runs(chain).get(run_id)
    if run is None:
        raise CfrNotFound("no such run")
    got = _results(chain).get(run_id)
    if not got:
        return {"run_id": run_id, "scenario_id": run["scenario_id"], "state": "PENDING" if _now() <= run["expires_at"]
                else "EXPIRED", "tier": "none"}
    rec, p = min(got, key=lambda x: x[0]["seq"])
    return {**_public(p), "evidence_seq": rec["seq"]}


def leaderboard(tenant_id: str, scenario_id: Any, limit: int = 20) -> Dict[str, Any]:
    if not isinstance(scenario_id, str) or not _ID.match(scenario_id):
        raise CfrError("scenario_id is required")
    chain = _chain(tenant_id)
    if scenario_id not in _scenarios(chain):
        raise CfrNotFound("no such scenario")
    best: Dict[str, Dict[str, Any]] = {}
    for run_id, items in _results(chain).items():
        rec, p = min(items, key=lambda x: x[0]["seq"])
        if p["scenario_id"] != scenario_id or p["state"] != "PASS":      # only PASS enters the board; UNKNOWN never ranks
            continue
        cur = best.get(p["participant_id"])
        if cur is None or (p["score"], -rec["seq"]) > (cur["score"], -cur["evidence_seq"]):
            best[p["participant_id"]] = {"participant_id": p["participant_id"], "score": p["score"], "tier": p["tier"],
                                         "run_id": run_id, "evidence_seq": rec["seq"]}
    rows = sorted(best.values(), key=lambda r: (-r["score"], r["evidence_seq"]))[: max(1, min(100, int(limit)))]
    return {"scenario_id": scenario_id, "ranking": rows,
            "note": "PASS results only, best per participant; scores are server-computed from runner-attested metrics"}
