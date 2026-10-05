"""Bridge: evidence-driven pipeline (``ola_pipeline``) <-> OLA tenant evidence chain.

Closes NINA -> OLLAMA -> EVIDENCE -> IGOR -> GATE -> REPLAY on top of the primitives OLA already has
(EvidenceRecord + per-tenant hash chain, NinaOrchestrator, NinaIgorChain, HumanGate, replay,
decision report). None of those components is modified.

What this module adds
* ANCHOR  - after a pipeline session is written to its (file) vault, ONE record `pipeline.anchor` is
            appended to the tenant's append-only chain. It carries the session's `chain_head`, the
            SHA-256 of `final.json` and a summary of every envelope. Rewriting the session directory
            afterwards - even consistently, which the vault's own hash chain cannot detect - no longer
            matches the anchor.
* VERIFY  - `verify_anchor` re-derives everything from disk (standalone verifier) AND from the tenant
            chain, then maps the result to OLA's vocabulary. It never trusts a status written by the
            run that produced it.
* MAP     - pipeline PASS / REVIEW_REQUIRED / BLOCKED  ->  OLA VERIFIED / UNKNOWN / BLOCK.
            Unrecognised values are BLOCK. UNKNOWN is never promoted.
* RUN     - tenant-scoped end-to-end run that ends in the existing NinaIgorChain + HumanGate.

HONEST LIMITS (also in docs/pipeline-bridge.md)
* The anchor lives in the same database as every other OLA record. Someone who can rewrite BOTH the
  vault directory and the SQLite file (and recompute the chain) is not detected; the DB-level
  append-only triggers only stop SQL UPDATE/DELETE. An external anchor (another system, a timestamp
  authority) is not implemented.
* A model judging a model is still a model; PASS means "process evidence is intact and the judge
  rejected a known-wrong canary", not "the answer is correct".
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import os
import re
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from ola_pipeline import Pipeline, PipelineConfig, verify_session
from ola_pipeline.errors import ConfigError, SigningError
from ola_pipeline.hashing import canonical_bytes
from ola_pipeline.igor import build_messages, judge_prompt_fingerprint
from ola_pipeline.verify import inspect_session

from .database import SessionLocal
from .decision_report import build_decision_report
from .hashchain import GENESIS_HASH, canonical_json, compute_record_hash, verify_chain
from .human_gate import ReviewDecision
from .models import EvidenceRecord
from .nina import NinaOrchestrator, NinaTask
from .nina_igor import NinaIgorChain
from .replay import build_replay

ANCHOR_TYPE = "pipeline.anchor"
ANCHOR_SCHEMA = "ola.pipeline-anchor/1"

_TENANT_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_SESSION_RE = re.compile(r"^ses_[0-9a-f]{24}$")
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


class PipelineNotConfigured(RuntimeError):
    """The pipeline cannot run safely with the current configuration (fail closed, HTTP 503)."""


class PipelineBusy(RuntimeError):
    """Too many pipeline runs in flight in this process (HTTP 429): shed load instead of queueing
    unbounded, cost-bearing model calls."""


_active_runs = 0
_active_lock = threading.Lock()


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise PipelineNotConfigured(f"{name} must be a positive integer") from None
    if value < 1:
        raise PipelineNotConfigured(f"{name} must be a positive integer")
    return value


@contextmanager
def _run_slot():
    """At most OLA_PIPELINE_MAX_CONCURRENCY runs per process (default 4). An invalid value is an
    error, never 'unlimited'. The slot is released on every exit path, including exceptions."""
    global _active_runs
    limit = _int_env("OLA_PIPELINE_MAX_CONCURRENCY", 4)
    with _active_lock:
        if _active_runs >= limit:
            raise PipelineBusy(f"pipeline is busy ({limit} runs already in flight)")
        _active_runs += 1
    try:
        yield
    finally:
        with _active_lock:
            _active_runs -= 1


# ------------------------------------------------------------------ small helpers
def _check_tenant(tenant_id: Any) -> str:
    # tenant_id becomes a directory name: allow-list it, never sanitise it.
    if not isinstance(tenant_id, str) or not _TENANT_RE.match(tenant_id):
        raise ValueError("invalid tenant_id")
    return tenant_id


def _check_session(session_id: Any) -> str:
    if not isinstance(session_id, str) or not _SESSION_RE.match(session_id):
        raise ValueError("invalid session_id")
    return session_id


def vault_base() -> Path:
    return Path(os.getenv("OLA_PIPELINE_VAULT_DIR", "./ola_pipeline_evidence"))


def trusted_key_from_env() -> Optional[bytes]:
    """OLA_PIPELINE_TRUSTED_KEY = 64 hex chars or a file holding them. A malformed pin is an ERROR,
    never silently ignored (ignoring it would downgrade PINNED_VALID to UNPINNED)."""
    raw = os.getenv("OLA_PIPELINE_TRUSTED_KEY", "").strip()
    if not raw:
        return None
    if not _HEX64.match(raw):
        try:
            parts = Path(raw).read_text("utf-8").split()
            raw = parts[0] if parts else ""
        except (OSError, UnicodeDecodeError):
            raw = ""
    if not _HEX64.match(raw):
        raise PipelineNotConfigured("OLA_PIPELINE_TRUSTED_KEY must be 64 hex characters or a readable file holding them")
    return bytes.fromhex(raw)


def _session_dir(tenant_id: str, session_id: str, base: Optional[Path]) -> Path:
    return (Path(base) if base is not None else vault_base()) / _check_tenant(tenant_id) / _check_session(session_id)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ------------------------------------------------------------------ tenant chain access
def load_chain(tenant_id: str) -> list[dict]:
    _check_tenant(tenant_id)
    with SessionLocal() as db:
        rows = db.scalars(
            select(EvidenceRecord).where(EvidenceRecord.tenant_id == tenant_id).order_by(EvidenceRecord.seq.asc())
        ).all()
    return [
        {"id": r.id, "tenant_id": r.tenant_id, "seq": r.seq, "record_type": r.record_type,
         "prev_hash": r.prev_hash, "record_hash": r.record_hash, "payload_json": r.payload_json}
        for r in rows
    ]


def append_evidence(tenant_id: str, record_type: str, payload: dict, *, attempts: int = 8) -> dict:
    """Append one record to the tenant chain. Same hashing as app.main.append_record; additionally
    retries when a concurrent writer took the same (tenant_id, seq) - the UNIQUE constraint makes that
    a clean IntegrityError instead of a fork."""
    _check_tenant(tenant_id)
    payload_json = canonical_json(payload)
    for _ in range(attempts):
        with SessionLocal() as db:
            last = db.scalar(
                select(EvidenceRecord).where(EvidenceRecord.tenant_id == tenant_id)
                .order_by(EvidenceRecord.seq.desc())
            )
            seq = 0 if last is None else last.seq + 1
            prev_hash = GENESIS_HASH if last is None else last.record_hash
            record = EvidenceRecord(
                id=str(uuid.uuid4()), tenant_id=tenant_id, seq=seq, record_type=record_type,
                payload_json=payload_json, prev_hash=prev_hash,
                record_hash=compute_record_hash(tenant_id, seq, prev_hash, payload_json),
            )
            db.add(record)
            try:
                db.commit()
            except IntegrityError:
                db.rollback()
                continue
            return {"id": record.id, "tenant_id": record.tenant_id, "seq": record.seq,
                    "record_hash": record.record_hash}
    raise RuntimeError("evidence append failed: sequence contention")


# ------------------------------------------------------------------ state mapping
def map_states(gate_state: Any, verifier_overall: Any) -> tuple[str, str]:
    """Pipeline vocabulary -> OLA IGOR vocabulary (VERIFIED / UNKNOWN / BLOCK)."""
    if verifier_overall == "FAILED":
        return "BLOCK", "independent verifier found inconsistencies in the session"
    if gate_state == "PASS":
        if verifier_overall == "VERIFIED":
            return "VERIFIED", "gate PASS re-derived by the independent verifier"
        return "UNKNOWN", f"gate says PASS but the verifier result is {verifier_overall}"
    if gate_state == "REVIEW_REQUIRED":
        return "UNKNOWN", "gate requires review (judge not calibrated, not independent or evidence incomplete)"
    if gate_state == "BLOCKED":
        return "BLOCK", "gate blocked the result"
    return "BLOCK", "unrecognised gate state"


# ------------------------------------------------------------------ judge qualification (opt-in)
# A PASS only means something if the judge that issued it has a measured error rate. scripts/judge_eval.py measures
# how often a judge accepts a WRONG answer on a labelled set; this block lets an operator require such a measurement
# before a PASS may become VERIFIED. Off unless OLA_JUDGE_QUALIFICATION_FILE is set: behaviour is then unchanged
# (and every result says so: state NOT_CONFIGURED). When on, anything that cannot be confirmed is NOT_QUALIFIED,
# which downgrades VERIFIED to UNKNOWN (never to BLOCK, never to anything better).
# Two-sided on purpose: a judge that rejects EVERYTHING has 0 false accepts and would pass a one-sided test
# (measured: qwen2.5:7b, 0/72 false accepts and 0/67 correct answers accepted). It must also accept correct answers.
QUALIFICATION_SCHEMA = "ola.judge-eval/1"


@dataclasses.dataclass(frozen=True)
class QualificationPolicy:
    path: Path
    dataset_sha256: str      # the labelled set the measurement must have been made on (pinned by the operator)
    max_false_accept: float  # largest allowed UPPER 95% Wilson bound of "wrong answers accepted"
    min_wrong_items: int     # smallest allowed number of wrong answers in the measurement
    min_correct_accept: float = 0.5   # smallest allowed LOWER 95% Wilson bound of "correct answers accepted"
    min_correct_items: int = 20       # smallest allowed number of correct answers in the measurement


def _float_env(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        raise PipelineNotConfigured(f"{name} must be a number in (0, 1]") from None
    if not 0.0 < value <= 1.0:
        raise PipelineNotConfigured(f"{name} must be a number in (0, 1]")
    return value


def qualification_policy_from_env() -> Optional[QualificationPolicy]:
    raw = os.environ.get("OLA_JUDGE_QUALIFICATION_FILE", "").strip()
    if not raw:
        return None
    pin = os.environ.get("OLA_JUDGE_QUALIFICATION_DATASET_SHA256", "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", pin):
        # a qualification measured on an arbitrary set would prove nothing: the set must be pinned
        raise PipelineNotConfigured("OLA_JUDGE_QUALIFICATION_DATASET_SHA256 must be the 64-hex SHA-256 of the labelled set "
                                    "when OLA_JUDGE_QUALIFICATION_FILE is set")
    return QualificationPolicy(Path(raw), pin, _float_env("OLA_JUDGE_MAX_FALSE_ACCEPT", 0.15),
                               _int_env("OLA_JUDGE_QUALIFICATION_MIN_WRONG", 20),
                               _float_env("OLA_JUDGE_MIN_CORRECT_ACCEPT", 0.5),
                               _int_env("OLA_JUDGE_QUALIFICATION_MIN_CORRECT", 20))


def _wilson_upper(k: int, n: int, z: float = 1.96) -> float:
    """Upper end of the Wilson score interval for k/n (recomputed here, never read from the file)."""
    p = k / n
    d = 1 + z * z / n
    return min(1.0, (p + z * z / (2 * n) + z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / d)


def _wilson_lower(k: int, n: int, z: float = 1.96) -> float:
    """Lower end of the Wilson score interval for k/n (recomputed here, never read from the file)."""
    p = k / n
    d = 1 + z * z / n
    return max(0.0, (p + z * z / (2 * n) - z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / d)


def session_judge_fingerprint(session_dir: Path, judge_env: dict, final: Optional[dict]) -> tuple:
    """(fingerprint, why_not): the identity of the judge AS IT ACTUALLY RAN in this session.

    A measurement says something about a judge only if it was made with the same prompt template, the same quality
    requirements and the same acceptance threshold. The requirements are read from the stored judge input and the
    threshold from final.json (both sealed by the anchor). The template is proven too: the prompt rebuilt from the
    stored input must hash to the stored prompt artifact, so a session produced by another template cannot borrow
    the measurement of this one. Anything missing or inconsistent -> (None, reason)."""
    try:
        def artifact(h: Any) -> bytes:
            if not isinstance(h, str) or not _HEX64.fullmatch(h):
                raise ValueError("malformed artifact hash")
            data = (Path(session_dir) / "artifacts" / h).read_bytes()
            if hashlib.sha256(data).hexdigest() != h:
                raise ValueError("artifact does not match its hash")
            return data
        inp = json.loads(artifact(judge_env.get("input_hash")).decode("utf-8"))
        reqs = inp["quality_requirements"]
        if not (isinstance(reqs, list) and reqs and all(isinstance(r, str) for r in reqs)):
            return None, "stored judge input has no usable quality requirements"
        threshold = final["policy"]["min_quality_score"]
        if not (isinstance(threshold, int) and not isinstance(threshold, bool) and 0 <= threshold <= 100):
            return None, "final.json has no usable min_quality_score"
        rebuilt = canonical_bytes(build_messages(inp["task"], inp["nina_output"], inp["evidence_checks"], tuple(reqs)))
        if hashlib.sha256(rebuilt).hexdigest() != judge_env.get("prompt_hash"):
            return None, "the stored judge prompt is not what the current prompt template produces"
        return judge_prompt_fingerprint(tuple(reqs), threshold), ""
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None, "the judge prompt of this session cannot be reconstructed from its stored artifacts"


def judge_qualification(judge_env: Optional[dict], policy: Optional[QualificationPolicy],
                        session_dir: Optional[Path] = None, final: Optional[dict] = None,
                        prompt_fingerprint: Optional[str] = None) -> dict:
    """Is THIS judge (provider, model, model digest) measured good enough? Fail closed on every doubt."""
    if policy is None:
        return {"state": "NOT_CONFIGURED",
                "reason": "judge accuracy is not measured: no qualification is configured"}

    def no(reason: str, **evidence: Any) -> dict:
        return {"state": "NOT_QUALIFIED", "reason": reason, **evidence}

    try:
        raw = policy.path.read_bytes()
        doc = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError):
        return no("qualification file is missing or not valid JSON")
    file_sha = hashlib.sha256(raw).hexdigest()
    try:
        meta = doc["meta"]
        fa = doc["summary"]["false_accept"]
        k, n = fa["k"], fa["n"]
        ca = doc["summary"]["correct_accepted"]
        ck, cn = ca["k"], ca["n"]
        if doc.get("schema") != QUALIFICATION_SCHEMA:
            return no("qualification file has an unknown schema", file_sha256=file_sha)
        if doc.get("dataset_sha256") != policy.dataset_sha256:
            return no("measured on a different labelled set than the pinned one", file_sha256=file_sha)
        if meta.get("runtime_kind") != "OLLAMA_OBSERVED":
            return no(f"measurement is not from an observed runtime (runtime_kind={meta.get('runtime_kind')!r})",
                      file_sha256=file_sha)
        if not isinstance(judge_env, dict):
            return no("the session has no judge envelope", file_sha256=file_sha)
        digest = meta.get("model_digest")
        if (doc.get("provider"), doc.get("model")) != (judge_env.get("provider"), judge_env.get("model")):
            return no("measured judge differs from the judge that decided this session", file_sha256=file_sha)
        if not digest or digest != judge_env.get("model_digest"):
            return no("model digest of the measurement is missing or differs from the judge's digest",
                      file_sha256=file_sha)
        # prompt_fingerprint: a caller that BUILDS the judge prompt itself (ambient IGOR) states which one it used;
        # a caller that only inspects a finished session lets the bridge reconstruct it from the stored artifacts.
        if prompt_fingerprint is not None:
            session_fp, why = prompt_fingerprint, ""
        elif session_dir is not None:
            session_fp, why = session_judge_fingerprint(session_dir, judge_env, final)
        else:
            session_fp, why = None, "no session directory to reconstruct the judge prompt from"
        if session_fp is None:
            return no(why, file_sha256=file_sha)
        if doc.get("judge_prompt_sha256") != session_fp:
            return no("measured with a different judge prompt, quality requirements or threshold than this session "
                      "used (judge_prompt_sha256 is missing or differs)", file_sha256=file_sha,
                      session_judge_prompt_sha256=session_fp)
        if not (isinstance(k, int) and isinstance(n, int) and not isinstance(k, bool) and not isinstance(n, bool)
                and 0 <= k <= n):
            return no("malformed false-accept counts", file_sha256=file_sha)
        if not (isinstance(ck, int) and isinstance(cn, int) and not isinstance(ck, bool) and not isinstance(cn, bool)
                and 0 <= ck <= cn):
            return no("malformed correct-accepted counts", file_sha256=file_sha)
        if doc["summary"].get("verdicts_obtained", 0) <= 0:
            return no("the measurement obtained no verdict at all", file_sha256=file_sha)
    except (KeyError, TypeError, AttributeError):
        return no("qualification file is malformed (a two-sided measurement needs summary.correct_accepted)")
    evidence = {"file_sha256": file_sha, "model": doc["model"], "model_digest": digest,
                "judge_prompt_sha256": session_fp,
                "false_accept": {"k": k, "n": n}, "max_allowed_upper95": policy.max_false_accept,
                "correct_accepted": {"k": ck, "n": cn}, "min_required_lower95": policy.min_correct_accept,
                "dataset_sha256": policy.dataset_sha256}
    if n < policy.min_wrong_items:
        return no(f"too few wrong answers in the measurement ({n} < {policy.min_wrong_items})", **evidence)
    upper = _wilson_upper(k, n)
    evidence["upper95"] = round(upper, 4)
    if upper > policy.max_false_accept:
        return no(f"judge accepted {k}/{n} wrong answers: upper 95% bound {upper:.0%} exceeds the allowed "
                  f"{policy.max_false_accept:.0%}", **evidence)
    if cn < policy.min_correct_items:
        return no(f"too few correct answers in the measurement ({cn} < {policy.min_correct_items})", **evidence)
    lower = _wilson_lower(ck, cn)
    evidence["correct_lower95"] = round(lower, 4)
    if lower < policy.min_correct_accept:
        return no(f"judge accepted only {ck}/{cn} correct answers: lower 95% bound {lower:.0%} is below the required "
                  f"{policy.min_correct_accept:.0%} (a judge that rejects everything judges nothing)", **evidence)
    return {"state": "QUALIFIED", "reason": f"judge accepted {k}/{n} wrong answers (upper 95% bound {upper:.0%}) "
                                            f"and {ck}/{cn} correct answers (lower 95% bound {lower:.0%})",
            **evidence}


# ------------------------------------------------------------------ anchor
def _envelope_summary(env: dict) -> dict:
    return {
        "envelope_run_id": env.get("run_id"), "parent_run_id": env.get("parent_run_id"),
        "agent_id": env.get("agent_id"), "iteration": env.get("iteration"),
        "execution_status": env.get("execution_status"), "gate_state": env.get("gate_state"),
        "input_hash": env.get("input_hash"), "output_hash": env.get("output_hash"),
        "envelope_hash": env.get("envelope_hash"),
    }


def anchor_session(tenant_id: str, session_dir: Path) -> dict:
    """Append ONE `pipeline.anchor` record (atomic: a single chain record per session)."""
    _check_tenant(tenant_id)
    sd = Path(session_dir)
    final_path = sd / "final.json"
    if not final_path.is_file():
        raise ValueError("cannot anchor a session without final.json")
    final = json.loads(final_path.read_text("utf-8"))
    facts = inspect_session(sd)
    if not facts.envelopes:
        raise ValueError("cannot anchor a session without envelopes")
    att_path = sd / "attestation.json"
    att = json.loads(att_path.read_text("utf-8")) if att_path.is_file() else None
    payload = {
        "schema": ANCHOR_SCHEMA,
        "run_id": final.get("run_id") or sd.name,
        "session_id": sd.name,
        "chain_head": facts.envelopes[-1].get("envelope_hash"),
        "final_sha256": _sha256_file(final_path),
        "gate_state": final.get("gate_state"),
        "igor_status": final.get("igor_status"),
        "nina_status": final.get("nina_status"),
        "evidence_class": final.get("evidence_class"),
        "source_sha": final.get("source_sha"),
        "provider": final.get("provider"), "model": final.get("model"), "model_digest": final.get("model_digest"),
        "iterations": final.get("iterations"),
        "signed": att is not None,
        "key_id": att.get("key_id") if att else None,
        "envelopes": [_envelope_summary(e) for e in facts.envelopes],
        "status": "ANCHORED",
    }
    rec = append_evidence(tenant_id, ANCHOR_TYPE, payload)
    return {**rec, "payload": payload}


def _anchors_for(records: list[dict], session_id: str) -> list[dict]:
    found = []
    for r in records:
        if r["record_type"] != ANCHOR_TYPE:
            continue
        try:
            p = json.loads(r["payload_json"])
        except json.JSONDecodeError:
            continue
        if isinstance(p, dict) and p.get("session_id") == session_id:
            found.append(r)
    return found


# ------------------------------------------------------------------ independent verification
def verify_anchor(tenant_id: str, session_id: str, *, base: Optional[Path] = None,
                  trusted_key: Optional[bytes] = None, session_dir: Optional[Path] = None) -> dict:
    """Re-derive the verdict from (a) the session directory with the standalone verifier and (b) the
    tenant's hash chain. The anchor is compared with what is on disk NOW."""
    _check_tenant(tenant_id)
    _check_session(session_id)
    sd = Path(session_dir) if session_dir is not None else _session_dir(tenant_id, session_id, base)
    if sd.name != session_id:
        raise ValueError("session_dir does not belong to session_id")
    checks: Dict[str, Any] = {}
    if not sd.is_dir():
        return {"status": "UNKNOWN", "reason": "session not found in this tenant's vault", "checks": checks}

    report = verify_session(sd, trusted_key=trusted_key)
    verifier = {"overall": report["overall"], "authenticity": report["authenticity"],
                "failures": report["failures"], "warnings": report["warnings"]}
    checks["session_internal"] = report["overall"] != "FAILED"

    records = load_chain(tenant_id)
    chain_ok, chain_reason = verify_chain(records)
    checks["tenant_chain"] = chain_ok
    if not chain_ok:
        return {"status": "BLOCK", "reason": f"tenant evidence chain invalid: {chain_reason}",
                "checks": checks, "verifier": verifier}

    anchors = _anchors_for(records, session_id)
    checks["anchored"] = len(anchors) == 1
    if not anchors:
        return {"status": "UNKNOWN", "reason": "session is not anchored in the tenant evidence chain",
                "checks": checks, "verifier": verifier}
    if len(anchors) > 1:
        return {"status": "BLOCK", "reason": "session anchored more than once (replayed anchor)",
                "checks": checks, "verifier": verifier}
    anchor = json.loads(anchors[0]["payload_json"])

    final_path = sd / "final.json"
    facts = inspect_session(sd)
    disk_head = facts.envelopes[-1].get("envelope_hash") if facts.envelopes else None
    disk_final = _sha256_file(final_path) if final_path.is_file() else None
    disk_envs = [_envelope_summary(e) for e in facts.envelopes]
    checks["chain_head_matches_anchor"] = bool(disk_head) and disk_head == anchor.get("chain_head")
    checks["final_matches_anchor"] = bool(disk_final) and disk_final == anchor.get("final_sha256")
    checks["envelopes_match_anchor"] = disk_envs == anchor.get("envelopes")
    for name, why in (("chain_head_matches_anchor", "chain_head differs from the anchored value"),
                      ("final_matches_anchor", "final.json differs from the anchored hash"),
                      ("envelopes_match_anchor", "envelopes differ from the anchored summary")):
        if not checks[name]:
            return {"status": "BLOCK", "reason": f"session was changed after anchoring: {why}",
                    "checks": checks, "verifier": verifier, "anchor_record_id": anchors[0]["id"]}

    # (gate_state needs no separate comparison: it is read from final.json, whose SHA-256 is anchored.)
    disk_gate = report.get("outcome")
    status, reason = map_states(disk_gate, report["overall"])
    qualification = judge_qualification(facts.igor[-1] if facts.igor else None, qualification_policy_from_env(), sd,
                                      json.loads(final_path.read_text("utf-8")) if final_path.is_file() else None)
    if status == "VERIFIED" and qualification["state"] == "NOT_QUALIFIED":
        status, reason = "UNKNOWN", f"gate PASS but the judge is not qualified: {qualification['reason']}"
    return {"status": status, "reason": reason, "checks": checks, "verifier": verifier,
            "judge_qualification": qualification,
            "anchor_record_id": anchors[0]["id"], "run_id": anchor.get("run_id"), "gate_state": disk_gate,
            "chain_head": disk_head}


# ------------------------------------------------------------------ replay (descriptive, never re-executes)
# app.replay.verify_replay (upstream) verifies RAW agent.* evidence records of /nina-run. A pipeline session is not
# written as agent.* records: it is one sealed `pipeline.anchor` record that holds the envelope summary. So this replay
# is verified here: the tenant chain must be intact, the anchor unique, and the rebuilt events must match the anchored
# envelopes one-to-one (order, run id, agent). It is a consistency check of what was sealed, not a re-execution.
def replay_from_anchor(tenant_id: str, session_id: str) -> dict:
    """Rebuild the ordered event list from the SEALED anchor record with the existing build_replay."""
    records = load_chain(tenant_id)
    anchors = _anchors_for(records, session_id)
    if len(anchors) != 1:
        return {"events": [], "verification": {"status": "UNKNOWN", "reason": "no unique anchor", "event_count": 0}}
    p = json.loads(anchors[0]["payload_json"])
    envelopes = p.get("envelopes") or []
    synthetic = []
    for i, e in enumerate(envelopes):
        synthetic.append({
            "tenant_id": tenant_id, "seq": i, "record_type": f"pipeline.{e.get('agent_id')}",
            "payload_json": canonical_json({
                "run_id": p.get("run_id"), "input_digest": e.get("input_hash"), "tool": e.get("agent_id"),
                "status": e.get("execution_status") or None,
            }),
        })
    events = build_replay(synthetic)
    base = {"event_count": len(events), "run_id": p.get("run_id"), "tenant_id": tenant_id}
    chain_ok, why = verify_chain(records)
    if not chain_ok:
        return {"events": events, "verification": {"status": "BLOCK", "reason": f"tenant chain broken: {why}", **base}}
    if not events:
        return {"events": events, "verification": {"status": "UNKNOWN", "reason": "anchor holds no envelopes", **base}}
    for i, (ev, env) in enumerate(zip(events, envelopes)):
        if ev["seq"] != i or ev["run_id"] != p.get("run_id") or ev["tool"] != env.get("agent_id"):
            return {"events": events, "verification": {"status": "BLOCK", "reason": "replay does not match the anchor", **base}}
    return {"events": events, "verification": {"status": "VERIFIED",
            "reason": "tenant chain intact; anchored envelopes replayed in order", **base,
            "anchor_record_id": anchors[0]["id"], "tip_hash": records[-1]["record_hash"]}}


# ------------------------------------------------------------------ end-to-end run
def build_config(tenant_id: str, base: Optional[Path] = None) -> PipelineConfig:
    try:
        cfg = PipelineConfig.from_env()
    except ConfigError as exc:
        raise PipelineNotConfigured(str(exc)) from exc
    root = (Path(base) if base is not None else vault_base()) / _check_tenant(tenant_id)
    return dataclasses.replace(cfg, vault_root=root)


def run_pipeline(tenant_id: str, task: Any, review: ReviewDecision, *, requested_tools=(),
                 cfg: Optional[PipelineConfig] = None, base: Optional[Path] = None,
                 trusted_key: Optional[bytes] = None, source_fn=None) -> dict:
    _check_tenant(tenant_id)
    nina_task = NinaTask.create(tenant_id, task, list(requested_tools))      # ValueError on empty task
    max_chars = _int_env("OLA_PIPELINE_MAX_TASK_CHARS", 8000)
    if len(nina_task.task) > max_chars:
        raise ValueError(f"task is too long (max {max_chars} characters)")
    plan = NinaOrchestrator().plan(nina_task)
    if plan.status != "ALLOW":                                               # unknown tool -> nothing runs
        return {
            "task_id": nina_task.task_id, "nina": {"status": plan.status, "reason": plan.reason},
            "igor": {"status": "UNKNOWN", "reason": "execution did not start"},
            "pipeline": {"status": "NOT_CREATED"}, "replay": [],
            "replay_verification": {"status": "UNKNOWN", "reason": "execution did not start"},
            "human_gate": {"status": "BLOCK", "reason": "NINA blocked execution"}, "status": "BLOCK",
        }

    cfg = cfg or build_config(tenant_id, base)
    if trusted_key is None:
        trusted_key = trusted_key_from_env()
    qualification_policy_from_env()          # a bad qualification setting is a 503 BEFORE any model is called
    pipe = Pipeline(cfg, **({"source_fn": source_fn} if source_fn else {}))
    signing_failed: Optional[str] = None
    try:
        with _run_slot():
            run = pipe.run(nina_task.task)
    except SigningError as exc:
        # The session exists and is evidence of what happened; it just is not signed. Anchor it,
        # but the terminal decision below is forced to BLOCK.
        if getattr(exc, "run", None) is None:
            raise
        run, signing_failed = exc.run, str(exc)

    session_id = run.session_dir.name
    anchored = anchor_session(tenant_id, run.session_dir)
    verification = verify_anchor(tenant_id, session_id, session_dir=run.session_dir, trusted_key=trusted_key)
    final = run.final

    raw_nina = final.get("nina_status")
    live = final.get("evidence_class") == "LIVE_RUNTIME_OBSERVED"
    if raw_nina == "EXECUTED":
        # a real run against a live runtime, and the anchored session is not contradicted
        nina_status = "VERIFIED" if (live and verification["status"] != "BLOCK") else "UNKNOWN"
    else:
        nina_status = str(raw_nina) if raw_nina else "UNKNOWN"             # never executed -> finalize() blocks
    igor_status = verification["status"]
    if signing_failed:
        terminal = {"status": "BLOCK", "reason": f"signing requested but failed: {signing_failed}"}
    else:
        terminal = NinaIgorChain.finalize(nina_status, igor_status, review)

    replay = replay_from_anchor(tenant_id, session_id)
    run_id = anchored["payload"]["run_id"]
    nina_summary = {"status": nina_status, "decision": plan.reason, "provider": final.get("provider"),
                    "model": final.get("model"), "model_digest": final.get("model_digest"),
                    "evidence_class": final.get("evidence_class"), "iterations": final.get("iterations")}
    igor_summary = {"status": igor_status, "reason": verification["reason"], "checks": verification["checks"],
                    "pipeline_igor_status": final.get("igor_status"), "gate_state": final.get("gate_state"),
                    "gate_reasons": final.get("gate_reasons"),
                    "judge_qualification": verification.get("judge_qualification")}
    report = build_decision_report(
        task_id=nina_task.task_id, run_id=run_id, task=nina_task.task, nina=nina_summary, igor=igor_summary,
        replay={"status": replay["verification"]["status"], "events": replay["events"],
                "verification": replay["verification"]},
        human_gate=terminal, evidence_ids=[anchored["id"]], human_approved=review.approved,
        human_actor=review.actor, human_reason=review.reason,
    )
    return {
        "task_id": nina_task.task_id, "run_id": run_id, "session_id": session_id,
        "nina": nina_summary, "igor": igor_summary,
        "pipeline": {
            "status": "ANCHORED", "anchor_record_id": anchored["id"], "chain_head": verification.get("chain_head"),
            "signed": anchored["payload"]["signed"],
            "authenticity": verification.get("verifier", {}).get("authenticity"),
            "verifier_overall": verification.get("verifier", {}).get("overall"),
        },
        "replay": replay["events"], "replay_verification": replay["verification"],
        "human_gate": terminal, "policy": report["policy"], "decision_report": report,
        "status": terminal["status"],
    }
