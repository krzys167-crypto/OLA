#!/usr/bin/env python3
"""Standalone evidence verifier (stdlib only, no package imports).

Can be copied alone and run:  python verify.py <session_dir> [--expected-source-sha SHA]
                                                [--scan-root DIR] [--trusted-key HEX|FILE] [--json]

It re-derives everything from the artifacts on disk:
  SOURCE -> RUNTIME -> ARTIFACT -> HASH -> INDEPENDENT VERIFY

Overall verdicts:
  VERIFIED    integrity ok, recorded gate state reproduced, LIVE runtime observed, gate_state == PASS
  CONSISTENT  integrity ok, outcome reproduced, live runtime observed, but outcome is not PASS, or the
              outcome is PASS under a weak policy (min_quality_score below the default minimum): such a
              PASS is capped here and the reason is reported under `caps` / warnings
  PARTIAL     integrity ok, but runtime is a declared TEST_DOUBLE or absent (no runtime proof)
  FAILED      any inconsistency (tampering, hash mismatch, broken chain, replay, ...)

Authenticity (separate from the verdict above): if the session holds `attestation.json` (Ed25519 over
chain_head + sha256(final.json) + final binding + source_sha + gate_state), the verifier recomputes
that payload from the files on disk and checks the signature.
  PINNED_VALID    valid signature by the key given in --trusted-key
  UNPINNED_VALID  valid signature, but nobody pinned the key: the file vouches for itself (a forger can
                  re-sign with their own key), so authenticity is NOT established
  INVALID         attestation present but wrong (splice, tamper, wrong key, malformed) -> overall FAILED
  NONE            no attestation (with --trusted-key a missing attestation is a FAILURE)
Exit codes: 0 VERIFIED, 1 FAILED, 2 CONSISTENT, 3 PARTIAL, 4 bad --trusted-key.

Limits (honest): a hash chain proves internal consistency, not authenticity. Without a pinned key,
someone who can rewrite the whole session directory consistently can forge it. A pinned signature
proves that the holder of the key attested THESE bytes; it does not prove the model run was honest,
has no freshness/revocation (signed_at is self-asserted), and a stolen key forges everything. Rolling a
directory back to an older, genuinely signed session is not detectable without an external ledger.
`LIVE` means "an endpoint answered the Ollama/OpenAI protocol and said so" — not a hardware
attestation of what computed the text.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

KNOWN_PROVIDERS = ("ollama-local", "ollama-cloud", "openai")
LIVE_KINDS = ("OLLAMA_OBSERVED", "OPENAI_OBSERVED")
ALL_KINDS = LIVE_KINDS + ("TEST_DOUBLE",)
GENESIS = "0" * 64
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
# The default minimum judge score (Policy.min_quality_score defaults to the same value; a test pins both).
DEFAULT_MIN_QUALITY_SCORE = 70
JUDGE_DECISIONS = ("PASS", "REVIEW", "BLOCK")      # least to most severe

REQUIRED_PROVENANCE = (
    "session_id", "run_id", "source_sha", "agent_id", "provider", "model",
    "prompt_hash", "input_hash", "output_hash", "timestamp", "iteration",
    "execution_status", "gate_state",
)
MUST_BE_PRESENT = ("parent_run_id", "model_digest")  # key required, value may be null

# Igor calibration canary: a deliverable that is objectively wrong. A judge that returns PASS for it
# is a rubber stamp and its PASS on real work proves nothing. (Shared with igor.py via import.)
CANARY_TASK = "What is 2 + 2? Answer with the number only."
CANARY_OUTPUT = "5"


# --------------------------------------------------------------------------- hashing
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def canonical_hash(obj: Any) -> str:
    return sha256_hex(canonical_bytes(obj))


def compute_envelope_hash(env: Dict[str, Any]) -> str:
    return canonical_hash({k: v for k, v in env.items() if k != "envelope_hash"})


def compute_binding(env: Dict[str, Any]) -> str:
    """Anti-replay binding: source_sha + run_id + iteration + evidence hashes + chain link."""
    return canonical_hash([
        env.get("source_sha"), env.get("run_id"), env.get("iteration"),
        env.get("input_hash"), env.get("prompt_hash"), env.get("output_hash"),
        env.get("prev_envelope_hash"),
    ])


def compute_final_binding(final: Dict[str, Any]) -> str:
    ar = final.get("anti_replay") or {}
    return canonical_hash([
        final.get("source_sha"), ar.get("final_nonce"), final.get("chain_head"),
        (final.get("evidence") or {}).get("evaluation_hash"),
        final.get("gate_state"), canonical_hash(final.get("policy")),
    ])


def missing_provenance(env: Dict[str, Any]) -> List[str]:
    miss = [k for k in REQUIRED_PROVENANCE if env.get(k) in (None, "")]
    miss += [k for k in MUST_BE_PRESENT if k not in env]
    return miss


# --------------------------------------------------------------------------- numbers
def intlike(x: Any) -> Optional[int]:
    """An int, or a float that is integral (92.0 -> 92). Never a bool, str, None, NaN, inf or 92.5."""
    if isinstance(x, bool):
        return None
    if isinstance(x, int):
        return x
    if isinstance(x, float) and x.is_integer():        # False for NaN and +-inf
        return int(x)
    return None


def judge_score(x: Any) -> Optional[int]:
    """A judge quality score as an int within 0..100, or None. Pipeline parser and verifier both use this."""
    q = intlike(x)
    return q if q is not None and 0 <= q <= 100 else None


# --------------------------------------------------------------------------- the judge's reply
class _DuplicateKey(ValueError):
    pass


def _no_duplicate_keys(pairs: Any) -> Dict[str, Any]:
    """json.loads keeps the LAST of two equal keys; a judge answer with two `decision` values is ambiguous."""
    out: Dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise _DuplicateKey(k)
        out[k] = v
    return out


def parse_judge(text: str) -> Tuple[Optional[Dict[str, Any]], str]:
    """THE parser for a judge's raw reply. The pipeline uses it to build the evaluation and the verifier
    uses the very same function to re-derive it, so the two can never disagree about what a reply says.
    Returns (result, "") or (None, why)."""
    try:
        obj = json.loads(text, object_pairs_hook=_no_duplicate_keys)
    except _DuplicateKey:
        return None, "judge output has a duplicate key"
    except (ValueError, RecursionError):
        return None, "judge output is not valid JSON"
    if not isinstance(obj, dict):
        return None, "judge output is not a JSON object"
    decision = obj.get("decision")
    if not isinstance(decision, str) or decision not in JUDGE_DECISIONS:
        return None, "invalid decision"
    q = judge_score(obj.get("quality_score"))
    if q is None:
        return None, "quality_score must be an integer 0..100"
    for k in ("findings", "required_corrections"):
        v = obj.get(k)
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            return None, f"{k} must be a list of strings"
    if not isinstance(obj.get("reason"), str):
        return None, "reason must be a string"
    res = {k: obj[k] for k in ("decision", "quality_score", "findings", "required_corrections", "reason")}
    res["quality_score"] = q
    return res, ""


# --------------------------------------------------------------------------- "the same model"
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _norm_model(m: Any) -> str:
    s = str(m or "").strip().lower()
    return s[: -len(":latest")] if s.endswith(":latest") else s       # "llama3" and "llama3:latest" are one model


def _norm_host(h: str) -> str:
    h = h.rstrip(".")
    if h == "localhost":
        return "127.0.0.1"
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return h
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip in (ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("::1")):
        return "127.0.0.1"
    return str(ip)


def _norm_endpoint(e: Any) -> Tuple[Any, ...]:
    s = str(e or "").strip().lower()
    try:
        u = urlsplit(s)
        host, port = _norm_host(u.hostname or ""), u.port
    except ValueError:
        return (s.rstrip("/"),)
    return (u.scheme, host, port if port is not None else _DEFAULT_PORTS.get(u.scheme), u.path.rstrip("/"))


def _norm_digest(d: Any) -> str:
    s = d.strip().lower() if isinstance(d, str) else ""
    return s[len("sha256:"):] if s.startswith("sha256:") else s


def same_model(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    """ONE definition of "the same model" for the stage-time independence label and for the verifier's
    recomputation. `a` and `b` carry provider / model / endpoint / model_digest (an envelope, or the same
    keys built from a config). Same weights = equal non-empty digests; otherwise equal provider + model +
    endpoint after normalising case and whitespace, the default ':latest' tag, loopback aliases
    (localhost / 127.0.0.1 / ::1), default ports and a trailing slash."""
    da, db = _norm_digest(a.get("model_digest")), _norm_digest(b.get("model_digest"))
    if da and da == db:
        return True

    def key(e: Dict[str, Any]) -> Tuple[Any, ...]:
        return (str(e.get("provider") or "").strip().lower(), _norm_model(e.get("model")),
                _norm_endpoint(e.get("endpoint")))
    return key(a) == key(b)


# --------------------------------------------------------------------------- inspection
@dataclass
class Facts:
    session_dir: str
    envelopes: List[Dict[str, Any]] = field(default_factory=list)
    failures: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    nina: List[Dict[str, Any]] = field(default_factory=list)
    igor: List[Dict[str, Any]] = field(default_factory=list)
    evals: Dict[str, Optional[Dict[str, Any]]] = field(default_factory=dict)  # igor run_id -> eval
    last_nina: Optional[Dict[str, Any]] = None
    last_igor: Optional[Dict[str, Any]] = None
    igor_eval: Optional[Dict[str, Any]] = None
    canary: List[Dict[str, Any]] = field(default_factory=list)
    canary_evals: Dict[str, Optional[Dict[str, Any]]] = field(default_factory=dict)
    last_canary: Optional[Dict[str, Any]] = None
    canary_eval: Optional[Dict[str, Any]] = None
    runtime_proof: Optional[Dict[str, Any]] = None
    # judge / canary run_id -> the judge's RAW reply exactly as the pipeline parsed it (None if unreadable)
    raw: Dict[str, Optional[str]] = field(default_factory=dict)
    igor_kind: Optional[str] = None      # runtime-proof kind of the judge's generation for the last Nina run
    canary_kind: Optional[str] = None    # ... and of the canary's generation


def _read_artifact(sd: Path, h: Any, label: str, failures: List[str]) -> Optional[bytes]:
    if h is None:
        return None
    if not isinstance(h, str) or not _HEX64.match(h):
        failures.append(f"{label}: malformed artifact hash")
        return None
    p = sd / "artifacts" / h
    if not p.is_file():
        failures.append(f"{label}: artifact {h[:12]}… missing")
        return None
    data = p.read_bytes()
    if sha256_hex(data) != h:
        failures.append(f"{label}: artifact {h[:12]}… content does not match its hash (hash mismatch)")
        return None
    return data


def _sname(sd: Path) -> str:
    """Directory name even when the session was given as `.` or `..`."""
    return sd.name or sd.resolve().name


def _read_json_artifact(sd: Path, h: Any) -> Any:
    """Parsed JSON of a hash-checked artifact, or None (problems are reported by the caller's own read)."""
    data = _read_artifact(sd, h, "", [])
    if data is None:
        return None
    try:
        return json.loads(data.decode("utf-8"))
    except Exception:
        return None


def _read_reply(sd: Path, e: Dict[str, Any]) -> Optional[str]:
    """The judge's raw reply (its stored output artifact) as the exact text the pipeline parsed."""
    if e.get("execution_status") != "EXECUTED":
        return None
    data = _read_artifact(sd, e.get("output_hash"), "", [])
    try:
        return data.decode("utf-8") if data is not None else None
    except UnicodeDecodeError:
        return None


def _proof_kind(sd: Path, e: Optional[Dict[str, Any]]) -> Optional[str]:
    proof = _read_json_artifact(sd, e.get("runtime_proof_hash")) if e is not None else None
    return proof.get("kind") if isinstance(proof, dict) else None


def _correction_link(sd: Path, e: Dict[str, Any]) -> Tuple[Any, Any]:
    """(run_id, evaluation_hash) of the verdict a Nina iteration says it corrects: from its refs, else (for
    sessions written before the refs existed) from its hash-bound input artifact."""
    refs = e.get("refs") if isinstance(e.get("refs"), dict) else {}
    if "correction_of_run_id" in refs or "correction_evaluation_hash" in refs:
        return refs.get("correction_of_run_id"), refs.get("correction_evaluation_hash")
    obj = _read_json_artifact(sd, e.get("input_hash"))
    return (obj.get("previous_run_id"), obj.get("evaluation_hash")) if isinstance(obj, dict) else (None, None)


def _refs(e: Any) -> Dict[str, Any]:
    return e.get("refs") if isinstance(e, dict) and isinstance(e.get("refs"), dict) else {}


_IGOR_GATE = {"PASS": "PASS", "REVIEW": "REVIEW_REQUIRED", "BLOCK": "BLOCKED"}


def inspect_session(session_dir: Any) -> Facts:
    sd = Path(session_dir)
    facts = Facts(session_dir=str(sd))
    f_, w_ = facts.failures, facts.warnings
    env_dir = sd / "envelopes"
    files = sorted(env_dir.glob("*.json")) if env_dir.is_dir() else []
    if not files:
        f_.append("no envelopes found")
    loaded = []
    for p in files:
        try:
            e = json.loads(p.read_text("utf-8"))
        except Exception:
            f_.append(f"{p.name}: unreadable or invalid JSON")
            continue
        if not isinstance(e, dict):
            f_.append(f"{p.name}: envelope is not an object")
            continue
        loaded.append((p, e))
        if p.stat().st_mode & 0o222:
            w_.append(f"{p.name}: file is not read-only")

    prev = GENESIS
    seen_run, seen_bind = set(), set()
    for idx, (p, e) in enumerate(loaded, start=1):
        n = p.name
        if e.get("seq") != idx:
            f_.append(f"{n}: seq {e.get('seq')!r} != expected {idx}")
        if n != f"{idx:04d}_{e.get('run_id')}.json":
            f_.append(f"{n}: filename does not match seq/run_id")
        if compute_envelope_hash(e) != e.get("envelope_hash"):
            f_.append(f"{n}: envelope_hash mismatch (envelope modified)")
        if e.get("prev_envelope_hash") != prev:
            f_.append(f"{n}: hash-chain broken (prev_envelope_hash)")
        prev = e.get("envelope_hash")
        if compute_binding(e) != e.get("binding"):
            f_.append(f"{n}: anti-replay binding mismatch")
        if e.get("run_id") in seen_run:
            f_.append(f"{n}: duplicate run_id (replay)")
        seen_run.add(e.get("run_id"))
        if e.get("binding") in seen_bind:
            f_.append(f"{n}: duplicate binding (replay)")
        seen_bind.add(e.get("binding"))
        if e.get("session_id") != _sname(sd):
            f_.append(f"{n}: session_id {e.get('session_id')!r} != directory name {_sname(sd)!r}")
        for key, label in (("prompt_hash", "prompt"), ("input_hash", "input"), ("output_hash", "output")):
            _read_artifact(sd, e.get(key), f"{n}:{label}", f_)
        refs = e.get("refs") if isinstance(e.get("refs"), dict) else {}
        _read_artifact(sd, e.get("runtime_proof_hash"), f"{n}:runtime_proof", f_)
        facts.envelopes.append(e)

    envs = facts.envelopes
    if len({e.get("source_sha") for e in envs}) > 1:
        f_.append("source_sha differs between envelopes")

    facts.nina = [e for e in envs if e.get("agent_id") == "nina"]
    facts.igor = [e for e in envs if e.get("agent_id") == "igor"]
    facts.canary = [e for e in envs if e.get("agent_id") == "igor-canary"]
    for e in envs:
        if e.get("agent_id") not in ("nina", "igor", "igor-canary"):
            f_.append(f"envelope {e.get('seq')!r}: unknown agent_id {e.get('agent_id')!r}")
    for label, group in (("igor", facts.igor), ("igor-canary", facts.canary)):
        seen_targets: set = set()
        for g in group:
            t = _refs(g).get("verifies_run_id") if isinstance(g.get("refs"), dict) else None
            key = t if isinstance(t, str) else repr(t)
            if key in seen_targets:
                f_.append(f"more than one {label} verdict for nina run {key} (verdict shopping)")
            seen_targets.add(key)
    for k, e in enumerate(facts.nina, start=1):
        if e.get("iteration") != k:
            f_.append(f"nina run {e.get('run_id')}: iteration {e.get('iteration')!r} != {k}")
        expected_parent = None if k == 1 else facts.nina[k - 2].get("run_id")
        if e.get("parent_run_id") != expected_parent:
            f_.append(f"nina iteration {k}: parent_run_id linkage broken")
    by_run = {e.get("run_id"): e for e in envs}
    for g in facts.igor:
        refs = g.get("refs") if isinstance(g.get("refs"), dict) else {}
        target = by_run.get(refs.get("verifies_run_id"))
        if not target or target.get("agent_id") != "nina":
            f_.append(f"igor run {g.get('run_id')}: verifies unknown nina run")
            continue
        if g.get("parent_run_id") != target.get("run_id"):
            f_.append(f"igor run {g.get('run_id')}: parent_run_id != verified nina run")
        if g.get("iteration") != target.get("iteration"):
            f_.append(f"igor run {g.get('run_id')}: iteration mismatch")
        if refs.get("verifies_envelope_hash") != target.get("envelope_hash"):
            f_.append(f"igor run {g.get('run_id')}: evaluated a different envelope than the stored one")
        if g.get("seq", 0) <= target.get("seq", 0):
            f_.append(f"igor run {g.get('run_id')}: recorded before the run it verifies")
        raw = _read_artifact(sd, refs.get("evaluation_hash"), f"igor {g.get('run_id')}:evaluation", f_)
        ev = None
        if raw is not None:
            try:
                ev = json.loads(raw.decode("utf-8"))
            except Exception:
                f_.append(f"igor {g.get('run_id')}: evaluation artifact is not valid JSON")
            if ev is not None and not isinstance(ev, dict):
                f_.append(f"igor {g.get('run_id')}: evaluation artifact is not a JSON object")
                ev = None
        facts.evals[g.get("run_id")] = ev
        facts.raw[g.get("run_id")] = _read_reply(sd, g)

    for c in facts.canary:
        refs = c.get("refs") if isinstance(c.get("refs"), dict) else {}
        target = by_run.get(refs.get("verifies_run_id"))
        label = f"igor-canary run {c.get('run_id')}"
        if not target or target.get("agent_id") != "nina":
            f_.append(f"{label}: references unknown nina run")
            continue
        if c.get("parent_run_id") != target.get("run_id") or c.get("iteration") != target.get("iteration"):
            f_.append(f"{label}: parent/iteration linkage broken")
        if c.get("seq", 0) <= target.get("seq", 0):
            f_.append(f"{label}: recorded before the run it accompanies")
        raw = _read_artifact(sd, refs.get("evaluation_hash"), f"{label}:evaluation", f_)
        cev = None
        if raw is not None:
            try:
                cev = json.loads(raw.decode("utf-8"))
            except Exception:
                f_.append(f"{label}: evaluation artifact is not valid JSON")
            if cev is not None and not isinstance(cev, dict):
                f_.append(f"{label}: evaluation artifact is not a JSON object")
                cev = None
        facts.canary_evals[c.get("run_id")] = cev
        facts.raw[c.get("run_id")] = _read_reply(sd, c)

    # The gate_state each envelope recorded must be the one its own content derives (a label is not evidence).
    for e in facts.nina:
        want = "PENDING" if e.get("execution_status") == "EXECUTED" else "BLOCKED"
        if e.get("gate_state") != want:
            f_.append(f"nina run {e.get('run_id')}: envelope gate_state {e.get('gate_state')!r} != derived {want!r}")
    for g in facts.igor:
        rid = g.get("run_id")
        if rid not in facts.evals:
            continue                                   # linkage problem, already reported
        ev = facts.evals[rid]
        d = ev.get("decision") if ev is not None else None
        want = _IGOR_GATE.get(d) if isinstance(d, str) else None
        if ev is None and _refs(g).get("evaluation_hash") is None:
            want = "BLOCKED"                           # the evaluation could not be persisted
        if want is not None and g.get("gate_state") != want:
            f_.append(f"igor run {rid}: envelope gate_state {g.get('gate_state')!r} != derived {want!r}")
    for c in facts.canary:
        rid = c.get("run_id")
        if rid not in facts.canary_evals:
            continue
        cev = facts.canary_evals[rid]
        if cev is None:
            allowed = {"BLOCKED"} if _refs(c).get("evaluation_hash") is None else None
        elif cev.get("judge_status") != "OK":
            allowed = {"CANARY_UNAVAILABLE"}
        elif cev.get("decision") != "PASS":
            allowed = {"CANARY_REJECTED"}
        else:
            allowed = {"CANARY_ACCEPTED", "CANARY_REJECTED"}    # which one depends on the policy threshold
        if allowed is not None and c.get("gate_state") not in allowed:
            f_.append(f"igor-canary run {rid}: envelope gate_state {c.get('gate_state')!r} != derived "
                      f"{' or '.join(sorted(allowed))!r}")

    # Every iteration before the last was followed by a further one only because Igor judged it non-PASS,
    # and the next iteration says which verdict it corrects.
    verdict_of = {_refs(g)["verifies_run_id"]: g for g in facts.igor
                  if isinstance(_refs(g).get("verifies_run_id"), str)}
    for k in range(len(facts.nina) - 1):
        cur, nxt = facts.nina[k], facts.nina[k + 1]
        g = verdict_of.get(cur.get("run_id"))
        ev = facts.evals.get(g.get("run_id")) if g else None
        if g is None or ev is None or ev.get("decision") not in ("REVIEW", "BLOCK"):
            f_.append(f"nina iteration {k + 1}: iteration {k + 2} was run without a non-PASS Igor verdict on it")
        want_hash = _refs(g).get("evaluation_hash") if g else None
        if want_hash is None or _correction_link(sd, nxt) != (cur.get("run_id"), want_hash):
            f_.append(f"nina iteration {k + 2}: not recorded as a correction of iteration {k + 1} "
                      "(correction refs missing or pointing elsewhere)")

    if facts.nina:
        facts.last_nina = facts.nina[-1]
        proof_raw = _read_artifact(sd, facts.last_nina.get("runtime_proof_hash"), "last nina runtime proof", f_)
        if proof_raw is not None:
            try:
                facts.runtime_proof = json.loads(proof_raw.decode("utf-8"))
            except Exception:
                f_.append("runtime proof artifact is not valid JSON")
        for g in facts.igor:
            if _refs(g).get("verifies_run_id") == facts.last_nina.get("run_id"):
                facts.last_igor = g
        if facts.last_igor is not None:
            facts.igor_eval = facts.evals.get(facts.last_igor.get("run_id"))
        for c in facts.canary:
            if _refs(c).get("verifies_run_id") == facts.last_nina.get("run_id"):
                facts.last_canary = c
        if facts.last_canary is not None:
            facts.canary_eval = facts.canary_evals.get(facts.last_canary.get("run_id"))
        facts.igor_kind = _proof_kind(sd, facts.last_igor)
        facts.canary_kind = _proof_kind(sd, facts.last_canary)
    return facts


# --------------------------------------------------------------------------- gate derivation
def _dedupe(xs: List[str]) -> List[str]:
    out: List[str] = []
    for x in xs:
        if x not in out:
            out.append(x)
    return out


def derive_gate(facts: Facts, policy: Dict[str, Any], end_source_sha: Optional[str]) -> Dict[str, Any]:
    """Pure function: on-disk facts + policy -> gate state. UNKNOWN never becomes PASS."""
    blocked: List[str] = []
    review: List[str] = []
    warnings: List[str] = []
    caps: List[str] = []
    runtime_kind: Optional[str] = None
    nina_status = "NOT_EXECUTED"
    igor_status = "NOT_RUN"

    if facts.failures:
        blocked.append("evidence inconsistent: " + "; ".join(facts.failures[:5]))
    max_it = policy.get("max_iterations")
    if not (isinstance(max_it, int) and not isinstance(max_it, bool) and 1 <= max_it <= 3):
        blocked.append(f"policy max_iterations {max_it!r} is missing or not an integer within 1..3")
    elif len(facts.nina) > max_it:
        blocked.append(f"{len(facts.nina)} Nina iterations exceed the policy maximum of {max_it}")
    min_policy = policy.get("min_quality_score")
    if (policy.get("require_igor_calibration") is False or policy.get("require_model_digest") is False
            or (isinstance(min_policy, int) and not isinstance(min_policy, bool)
                and min_policy < DEFAULT_MIN_QUALITY_SCORE)):
        warnings.append("policy snapshot is weaker than the defaults (calibration, model digest or minimum score relaxed)")
    if isinstance(min_policy, int) and not isinstance(min_policy, bool) and min_policy < DEFAULT_MIN_QUALITY_SCORE:
        caps.append(f"weak policy: min_quality_score {min_policy} is below the default minimum of "
                    f"{DEFAULT_MIN_QUALITY_SCORE}; the result is capped below VERIFIED")
        warnings.append(caps[-1])

    n = facts.last_nina
    if n is None:
        blocked.append("no Nina execution recorded")
    else:
        nina_status = n.get("execution_status") or "UNKNOWN"
        if nina_status != "EXECUTED":
            blocked.append(f"real runtime not executed (status={nina_status})")
        if n.get("provider") not in KNOWN_PROVIDERS:
            blocked.append(f"unknown provider: {n.get('provider')!r}")
        if not n.get("model"):
            blocked.append("model unknown")
        miss = missing_provenance(n)
        if miss:
            blocked.append("provenance incomplete: " + ", ".join(miss))
        if end_source_sha is None:
            blocked.append("final source freeze evidence missing")
        elif end_source_sha != n.get("source_sha"):
            blocked.append("source_sha changed during the run")
        if nina_status == "EXECUTED":
            rp = facts.runtime_proof
            if rp is None:
                blocked.append("runtime proof missing")
            else:
                runtime_kind = rp.get("kind")
                if runtime_kind not in ALL_KINDS:
                    blocked.append("runtime proof has unrecognised kind")
                elif runtime_kind == "TEST_DOUBLE" and not policy.get("allow_test_double"):
                    blocked.append("runtime is a declared TEST_DOUBLE, not accepted by policy")
            if not n.get("model_digest") and policy.get("require_model_digest", True):
                review.append("model digest unavailable (policy requires it)")

    if n is not None and nina_status == "EXECUTED":
        g, ev = facts.last_igor, facts.igor_eval
        if g is None or ev is None:
            blocked.append("Igor verification missing")
        else:
            dec = ev.get("decision")
            meta = ev.get("meta") if isinstance(ev.get("meta"), dict) else {}
            js = meta.get("judge_status")
            reason = ev.get("reason", "")
            # independence is recomputed from the envelopes, never taken from the stored label
            if same_model(g, n):
                meta = dict(meta, independence="SAME_MODEL_SEPARATE_CONTEXT")
            if meta.get("independence") == "SAME_MODEL_SEPARATE_CONTEXT":
                warnings.append("Igor uses the same provider/model as Nina (separate context, weak independence)")
            # an evaluation that claims a usable judge reply must be re-derivable from that reply
            tie = (_judge_tie_problem(facts, g, ev)
                   if dec in JUDGE_DECISIONS and js == "OK" and g.get("execution_status") == "EXECUTED" else None)
            if tie:
                blocked.append(tie)
                igor_status = "UNAVAILABLE"
            elif dec == "PASS":
                q = judge_score(ev.get("quality_score"))
                min_q = policy.get("min_quality_score", DEFAULT_MIN_QUALITY_SCORE)
                crit_fail = [c for c in (ev.get("evidence_checks") or [])
                             if isinstance(c, dict) and c.get("status") == "FAIL" and c.get("critical")]
                if js != "OK" or g.get("execution_status") != "EXECUTED":
                    blocked.append("Igor PASS without an executed judge")
                    igor_status = "UNAVAILABLE"
                elif (q is None or not isinstance(min_q, int) or isinstance(min_q, bool)
                      or not 0 <= min_q <= 100 or q < min_q
                      or ev.get("required_corrections") or crit_fail):
                    blocked.append("Igor PASS is inconsistent with its own evaluation "
                                   "(score below the policy minimum, open corrections, or a failed critical check)")
                    igor_status = "UNAVAILABLE"
                elif _generation_problem(facts.igor_kind, g, policy, "Igor judge"):
                    blocked.append(_generation_problem(facts.igor_kind, g, policy, "Igor judge"))
                    igor_status = "UNAVAILABLE"
                else:
                    igor_status = "VERIFIED"
                    override: Optional[str] = None
                    if (meta.get("independence") == "SAME_MODEL_SEPARATE_CONTEXT"
                            and not policy.get("allow_same_model_igor", False)):
                        review.append("Igor is not independent: same provider/model as Nina "
                                      "(self-verification; policy forbids it)")
                        override = "NOT_INDEPENDENT"
                    if policy.get("require_igor_calibration", True):
                        problem = _canary_problem(facts, g, policy)
                        if problem:
                            review.append(problem)
                            override = override or "UNCALIBRATED"
                    if override:
                        igor_status = override
            elif dec == "REVIEW":
                review.append(f"Igor REVIEW: {reason}")
                igor_status = "REVIEW"
            elif dec == "BLOCK":
                blocked.append(f"Igor BLOCK: {reason}")
                igor_status = "UNAVAILABLE" if js in ("TIMEOUT", "UNAVAILABLE", "INVALID_OUTPUT") else "BLOCKED"
            else:
                blocked.append("Igor returned an invalid decision")
                igor_status = "UNAVAILABLE"

    state = "BLOCKED" if blocked else ("REVIEW_REQUIRED" if review else "PASS")
    if igor_status in ("VERIFIED", "NOT_INDEPENDENT", "UNCALIBRATED") and "TEST_DOUBLE" in (facts.igor_kind, facts.canary_kind):
        runtime_kind = "TEST_DOUBLE"        # a declared double anywhere in the verifying chain: never LIVE evidence
    if igor_status == "VERIFIED" and runtime_kind == "TEST_DOUBLE":
        igor_status = "PASS_UNATTESTED"
    evidence_class = "LIVE_RUNTIME_OBSERVED" if runtime_kind in LIVE_KINDS else (
        "TEST_DOUBLE" if runtime_kind == "TEST_DOUBLE" else "NONE")
    return {
        "state": state, "reasons": _dedupe(blocked + review), "warnings": _dedupe(warnings),
        "igor_status": igor_status, "nina_status": nina_status,
        "runtime_kind": runtime_kind, "evidence_class": evidence_class, "caps": _dedupe(caps),
    }


def _generation_problem(kind: Optional[str], env: Dict[str, Any], policy: Dict[str, Any], who: str) -> Optional[str]:
    """The runtime-proof / provenance rules Nina's generation must pass, applied to a judge or canary
    generation: known provider and model, complete provenance, a recognised proof kind, and a declared
    TEST_DOUBLE only where the policy explicitly allows it (the same opt-in Nina has)."""
    if env.get("provider") not in KNOWN_PROVIDERS:
        return f"{who}: unknown provider {env.get('provider')!r}"
    if not env.get("model"):
        return f"{who}: model unknown"
    miss = missing_provenance(env)
    if miss:
        return f"{who}: provenance incomplete: " + ", ".join(miss)
    if kind not in ALL_KINDS:
        return f"{who}: runtime proof missing or of an unrecognised kind"
    if kind == "TEST_DOUBLE" and not policy.get("allow_test_double"):
        return f"{who}: ran on a declared TEST_DOUBLE, not accepted by policy"
    return None


def _judge_tie_problem(facts: Facts, g: Dict[str, Any], ev: Dict[str, Any]) -> Optional[str]:
    """None unless the stored evaluation is DEFINITELY inconsistent with the judge's raw reply. The raw
    reply is re-parsed with the pipeline's own `parse_judge`. The pipeline may only make the evaluation
    stricter than the reply (PASS with open corrections or a low score -> REVIEW, failed critical check ->
    BLOCK), so a stricter decision is never flagged; a less strict one, another score, or corrections that
    do not start with the reply's own always are."""
    raw = facts.raw.get(g.get("run_id"))
    if raw is None:
        return "Igor evaluation cannot be tied to the judge's raw reply (reply artifact missing or unreadable)"
    judged, why = parse_judge(raw)
    if judged is None:
        return f"Igor evaluation claims a usable judge reply, but the recorded raw reply is not one ({why})"
    if JUDGE_DECISIONS.index(ev["decision"]) < JUDGE_DECISIONS.index(judged["decision"]):
        return "Igor evaluation is less strict than the judge's raw reply (decision mismatch)"
    if judge_score(ev.get("quality_score")) != judged["quality_score"]:
        return "Igor evaluation quality_score does not match the judge's raw reply"
    corrections, said = ev.get("required_corrections"), judged["required_corrections"]
    if not isinstance(corrections, list) or corrections[:len(said)] != said:
        return "Igor evaluation required_corrections do not match the judge's raw reply"
    return None


def _canary_problem(facts: Facts, igor_env: Dict[str, Any], policy: Dict[str, Any]) -> Optional[str]:
    """None only if the SAME judge demonstrably rejected the known-wrong canary. Re-derived from
    raw decision/score/status, never from the stored `verdict` label."""
    c, ev = facts.last_canary, facts.canary_eval
    if c is None or ev is None:
        return "Igor calibration missing: no known-wrong canary was judged"
    if ev.get("task") != CANARY_TASK or ev.get("output") != CANARY_OUTPUT:
        return "Igor calibration invalid: canary content was altered"
    ident = ("provider", "model", "model_digest", "endpoint")
    if tuple(c.get(k) for k in ident) != tuple(igor_env.get(k) for k in ident):
        return "Igor calibration invalid: canary was judged by a different model than the verdict"
    if c.get("execution_status") != "EXECUTED" or ev.get("judge_status") != "OK":
        return "Igor calibration unavailable: canary judge did not return a usable verdict"
    gen = _generation_problem(facts.canary_kind, c, policy, "canary judge")
    if gen:
        return "Igor calibration invalid: " + gen
    raw = facts.raw.get(c.get("run_id"))
    said, why = parse_judge(raw) if raw is not None else (None, "reply artifact missing")
    q = judge_score(ev.get("quality_score"))
    if said is None or said["decision"] != ev.get("decision") or said["quality_score"] != q:
        return "Igor calibration invalid: the canary evaluation does not match the judge's recorded raw reply"
    accepted = ev.get("decision") == "PASS" and (
        q is None or q >= policy.get("min_quality_score", DEFAULT_MIN_QUALITY_SCORE))
    if accepted:
        return ("Igor failed calibration: it PASSed a known-wrong answer (2 + 2 = 5); "
                "its PASS is not evidence of correctness")
    return None


def summarize_runs(facts: Facts) -> List[Dict[str, Any]]:
    out = []
    for e in facts.nina:
        igor = None
        for g in facts.igor:
            if _refs(g).get("verifies_run_id") == e.get("run_id"):
                igor = g
        ev = facts.evals.get(igor.get("run_id")) if igor else None
        out.append({
            "iteration": e.get("iteration"), "nina_run_id": e.get("run_id"),
            "nina_status": e.get("execution_status"),
            "igor_run_id": igor.get("run_id") if igor else None,
            "igor_decision": ev.get("decision") if ev else None,
        })
    return out


# --------------------------------------------------------------------------- attestation (Ed25519)
# Verify-only Ed25519 (RFC 8032) embedded so this file stays standalone. Same algorithm as
# ola_pipeline/ed25519.py; tests assert that both agree with each other and with `cryptography`.
_EP = 2 ** 255 - 19
_EL = 2 ** 252 + 27742317777372353535851937790883648493
_ED = -121665 * pow(121666, _EP - 2, _EP) % _EP
_ESQRT = pow(2, (_EP - 1) // 4, _EP)


def _einv(x: int) -> int:
    return pow(x, _EP - 2, _EP)


def _erecover(y: int, sign: int) -> Optional[int]:
    if y >= _EP:
        return None
    x2 = (y * y - 1) * _einv(_ED * y * y + 1) % _EP
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_EP + 3) // 8, _EP)
    if (x * x - x2) % _EP != 0:
        x = x * _ESQRT % _EP
    if (x * x - x2) % _EP != 0:
        return None
    if (x & 1) != sign:
        x = _EP - x
    return x


_EGY = 4 * _einv(5) % _EP
_EGX = _erecover(_EGY, 0)
_EG = (_EGX, _EGY, 1, _EGX * _EGY % _EP)


def _eadd(p: Any, q: Any) -> Any:
    a = (p[1] - p[0]) * (q[1] - q[0]) % _EP
    b = (p[1] + p[0]) * (q[1] + q[0]) % _EP
    c = 2 * p[3] * q[3] * _ED % _EP
    d = 2 * p[2] * q[2] % _EP
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _EP, g * h % _EP, f * g % _EP, e * h % _EP)


def _emul(s: int, p: Any) -> Any:
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _eadd(q, p)
        p = _eadd(p, p)
        s >>= 1
    return q


def _edecompress(b: bytes) -> Optional[Any]:
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _erecover(y, sign)
    return None if x is None else (x, y, 1, x * y % _EP)


def ed25519_verify(pub: bytes, message: bytes, signature: bytes) -> bool:
    """Strict RFC 8032 verification (rejects S >= L and non-canonical point encodings)."""
    if len(pub) != 32 or len(signature) != 64:
        return False
    a_pt, r_pt = _edecompress(pub), _edecompress(signature[:32])
    if a_pt is None or r_pt is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _EL:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + pub + message).digest(), "little") % _EL
    lhs, rhs = _emul(s, _EG), _eadd(r_pt, _emul(h, a_pt))
    return ((lhs[0] * rhs[2] - rhs[0] * lhs[2]) % _EP == 0
            and (lhs[1] * rhs[2] - rhs[1] * lhs[2]) % _EP == 0)


ATT_SCHEMA = "ola.attestation/1"
ATT_PAYLOAD_SCHEMA = "ola.attestation.payload/1"
ATT_DOMAIN = b"ola.attestation/1\n"  # domain separation: a signature over anything else never verifies here
_HEX128 = re.compile(r"^[0-9a-f]{128}$")


def attestation_payload(session_id: str, chain_head: Optional[str], final_bytes: bytes,
                        final: Dict[str, Any], public_key_hex: str, signed_at: str) -> Dict[str, Any]:
    """Single source of truth for what is signed. The signer and the verifier both call this."""
    ar = final.get("anti_replay") if isinstance(final.get("anti_replay"), dict) else {}
    return {
        "schema": ATT_PAYLOAD_SCHEMA, "session_id": session_id, "chain_head": chain_head,
        "final_sha256": sha256_hex(final_bytes), "final_binding": ar.get("binding"),
        "source_sha": final.get("source_sha"), "gate_state": final.get("gate_state"),
        "public_key": public_key_hex, "signed_at": signed_at,
    }


def attestation_message(payload: Dict[str, Any]) -> bytes:
    return ATT_DOMAIN + canonical_bytes(payload)


def check_attestation(sd: Path, facts: "Facts", final: Optional[Dict[str, Any]],
                      trusted_key: Optional[bytes]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"authenticity": "NONE", "failures": [], "warnings": [], "info": {}}
    ap = sd / "attestation.json"
    if not ap.is_file():
        if trusted_key is not None:
            out["failures"].append("attestation required (--trusted-key given) but attestation.json is missing")
        return out

    def bad(msg: str) -> Dict[str, Any]:
        out["authenticity"] = "INVALID"
        out["failures"].append("attestation: " + msg)
        return out

    if final is None:
        return bad("cannot be checked without a readable final.json")
    try:
        att = json.loads(ap.read_text("utf-8"))
    except Exception:
        return bad("attestation.json is unreadable or not valid JSON")
    if not isinstance(att, dict) or att.get("schema") != ATT_SCHEMA or att.get("algorithm") != "Ed25519":
        return bad("unsupported schema or algorithm")
    pk_hex, sig_hex, payload = att.get("public_key"), att.get("signature"), att.get("payload")
    if not (isinstance(pk_hex, str) and _HEX64.match(pk_hex)):
        return bad("malformed public_key")
    if not (isinstance(sig_hex, str) and _HEX128.match(sig_hex)):
        return bad("malformed signature")
    if not isinstance(payload, dict) or not isinstance(payload.get("signed_at"), str) or not payload["signed_at"]:
        return bad("malformed payload")
    pub = bytes.fromhex(pk_hex)
    key_id = sha256_hex(pub)
    out["info"] = {"key_id": key_id, "public_key": pk_hex, "signed_at": payload["signed_at"],
                   "signer_impl": att.get("signer_impl")}
    if att.get("key_id") != key_id:
        return bad("key_id does not match public_key")
    final_bytes = (sd / "final.json").read_bytes()
    chain_head = facts.envelopes[-1].get("envelope_hash") if facts.envelopes else None
    expected = attestation_payload(_sname(sd), chain_head, final_bytes, final, pk_hex, payload["signed_at"])
    if canonical_bytes(payload) != canonical_bytes(expected):
        diff = sorted(k for k in set(payload) | set(expected) if payload.get(k) != expected.get(k))
        return bad("signed payload does not match the session on disk (differs: " + ", ".join(diff) + ")")
    if not ed25519_verify(pub, attestation_message(payload), bytes.fromhex(sig_hex)):
        return bad("signature is invalid")
    if trusted_key is None:
        out["authenticity"] = "UNPINNED_VALID"
        out["warnings"].append("attestation signature is valid but the signing key is NOT pinned "
                               "(--trusted-key): authenticity is not established")
    elif trusted_key == pub:
        out["authenticity"] = "PINNED_VALID"
    else:
        return bad("signed by a different key than the pinned --trusted-key (key_id " + key_id[:16] + "…)")
    return out


# --------------------------------------------------------------------------- full verification
def verify_session(session_dir: Any, *, expected_source_sha: Optional[str] = None,
                   scan_root: Optional[Any] = None, trusted_key: Optional[bytes] = None) -> Dict[str, Any]:
    if trusted_key is not None and (not isinstance(trusted_key, (bytes, bytearray)) or len(trusted_key) != 32):
        raise ValueError("trusted_key must be exactly 32 bytes (raw Ed25519 public key)")
    trusted_key = bytes(trusted_key) if trusted_key is not None else None
    try:
        return _verify_session(session_dir, expected_source_sha=expected_source_sha, scan_root=scan_root,
                               trusted_key=trusted_key)
    except Exception as e:     # malformed-but-parseable evidence is a verdict (FAILED), never an exception
        sd = Path(session_dir)
        return {"overall": "FAILED", "outcome": None, "runtime_kind": None, "recomputed": None,
                "failures": [f"verifier could not process the session: {type(e).__name__}"],
                "warnings": [], "caps": [], "session": _sname(sd), "authenticity": "NONE", "attestation": None}


def _verify_session(session_dir: Any, *, expected_source_sha: Optional[str] = None,
                    scan_root: Optional[Any] = None, trusted_key: Optional[bytes] = None) -> Dict[str, Any]:
    sd = Path(session_dir)
    facts = inspect_session(sd)
    failures = list(facts.failures)
    warnings = list(facts.warnings)
    recomputed: Optional[Dict[str, Any]] = None
    final: Optional[Dict[str, Any]] = None

    fp = sd / "final.json"
    if not fp.is_file():
        failures.append("final.json missing (session incomplete)")
    else:
        try:
            final = json.loads(fp.read_text("utf-8"))
            if not isinstance(final, dict):
                failures.append("final.json is not a JSON object")
                final = None
        except Exception:
            failures.append("final.json unreadable or invalid JSON")
    if final is not None:
        policy = final.get("policy") if isinstance(final.get("policy"), dict) else {}
        if not policy:
            failures.append("final.json has no policy snapshot")
        recomputed = derive_gate(facts, policy, final.get("source_sha_end"))
        n, g = facts.last_nina, facts.last_igor
        ev = final.get("evidence") or {}
        checks = [
            ("gate_state", final.get("gate_state"), recomputed["state"]),
            ("igor_status", final.get("igor_status"), recomputed["igor_status"]),
            ("nina_status", final.get("nina_status"), recomputed["nina_status"]),
            ("gate_reasons", final.get("gate_reasons"), recomputed["reasons"]),
            ("evidence_class", final.get("evidence_class"), recomputed["evidence_class"]),
            ("runs", final.get("runs"), summarize_runs(facts)),
            ("iterations", final.get("iterations"), len(facts.nina)),
            ("chain_head", final.get("chain_head"), facts.envelopes[-1].get("envelope_hash") if facts.envelopes else None),
            ("run_id", final.get("run_id"), n.get("run_id") if n else None),
            ("source_sha", final.get("source_sha"), n.get("source_sha") if n else None),
            ("provider", final.get("provider"), n.get("provider") if n else None),
            ("model", final.get("model"), n.get("model") if n else None),
            ("model_digest", final.get("model_digest"), n.get("model_digest") if n else None),
            ("evidence.input_hash", ev.get("input_hash"), n.get("input_hash") if n else None),
            ("evidence.output_hash", ev.get("output_hash"), n.get("output_hash") if n else None),
            ("evidence.evaluation_hash", ev.get("evaluation_hash"),
             _refs(g).get("evaluation_hash") if g else None),
        ]
        for name, claimed, derived in checks:
            if claimed != derived:
                failures.append(f"final.json {name} does not match the artifacts (claimed != derived)")
        if compute_final_binding(final) != (final.get("anti_replay") or {}).get("binding"):
            failures.append("final.json anti-replay binding mismatch")
        warnings += [w for w in recomputed["warnings"] if w not in warnings]
        if expected_source_sha is not None and final.get("source_sha") != expected_source_sha:
            failures.append("source_sha differs from the expected one (stale or foreign artifact)")

    att = check_attestation(sd, facts, final, trusted_key)
    failures += att["failures"]
    warnings += [w for w in att["warnings"] if w not in warnings]

    if scan_root is not None:
        root = Path(scan_root)
        if not root.is_dir():
            failures.append("scan root is not a directory")
        mine_runs = {e.get("run_id") for e in facts.envelopes}
        mine_bind = {e.get("binding") for e in facts.envelopes}
        others = sorted(p for p in root.iterdir() if p.is_dir() and p.name not in ("_run_index", "_binding_index")) \
            if root.is_dir() else []
        for other in others:
            if other.resolve() == sd.resolve():
                continue
            other_envs = other / "envelopes"
            for p in sorted(other_envs.glob("*.json")) if other_envs.is_dir() else []:
                try:
                    e = json.loads(p.read_text("utf-8"))
                except Exception:
                    continue
                if e.get("run_id") in mine_runs or e.get("binding") in mine_bind:
                    failures.append(f"run_id/binding also present in session {other.name} (replayed artifact)")
                    break

    runtime_kind = recomputed["runtime_kind"] if recomputed else None
    outcome = final.get("gate_state") if final else None
    caps = list(recomputed["caps"]) if recomputed else []
    if failures:
        overall = "FAILED"
    elif runtime_kind not in LIVE_KINDS:
        overall = "PARTIAL"
    elif outcome == "PASS":
        overall = "CONSISTENT" if caps else "VERIFIED"      # a PASS under a weak policy is never the top tier
    else:
        overall = "CONSISTENT"
    return {
        "overall": overall, "outcome": outcome, "runtime_kind": runtime_kind,
        "recomputed": recomputed, "failures": failures, "warnings": warnings, "caps": caps,
        "session": _sname(sd), "authenticity": att["authenticity"], "attestation": att["info"],
    }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Independent verification of an OLA evidence session")
    ap.add_argument("session_dir")
    ap.add_argument("--expected-source-sha")
    ap.add_argument("--scan-root")
    ap.add_argument("--trusted-key", help="Ed25519 public key (64 hex chars) or a file containing it")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    trusted: Optional[bytes] = None
    if a.trusted_key is not None:
        raw = a.trusted_key.strip()
        if not _HEX64.match(raw.lower()):
            try:
                raw = Path(a.trusted_key).read_text("utf-8").split()[0].lower()
            except (OSError, IndexError, UnicodeDecodeError):
                raw = ""
        if not _HEX64.match(raw.lower()):
            print("BLOCKED: --trusted-key must be 64 hex characters or a readable file containing them", file=sys.stderr)
            return 4
        trusted = bytes.fromhex(raw.lower())
    rep = verify_session(a.session_dir, expected_source_sha=a.expected_source_sha, scan_root=a.scan_root,
                         trusted_key=trusted)
    if a.json:
        print(json.dumps(rep, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        print(f"overall={rep['overall']} outcome={rep['outcome']} runtime={rep['runtime_kind']}")
        kid = (rep["attestation"] or {}).get("key_id")
        print(f"authenticity={rep['authenticity']}" + (f" key_id={kid[:16]}…" if kid else ""))
        for x in rep["failures"]:
            print("  FAIL:", x)
        for x in rep["warnings"]:
            print("  warn:", x)
    return {"VERIFIED": 0, "FAILED": 1, "CONSISTENT": 2, "PARTIAL": 3}[rep["overall"]]


if __name__ == "__main__":
    sys.exit(main())
