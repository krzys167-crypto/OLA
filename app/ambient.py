"""Ambient NINA/IGOR: an independent judge that works in the ecosystem without being a visible step.

NINA produces (the chat model, the agent runtime). IGOR - a second model in a separate context - looks at
what NINA produced and records a verdict in the tenant evidence chain. The caller of /chat or /agent-run
does not have to do anything and, unless the operator chooses ``enforce``, does not see anything.

    OLA_AMBIENT_IGOR=off      (default) nothing happens, no model is called, no record is written.
    OLA_AMBIENT_IGOR=shadow   the response is returned untouched and IGOR judges AFTER it, in the background.
                              The verdict is an `igor.shadow` record. It can never block, delay or change a
                              response; a judge failure is itself recorded (verdict ERROR / NO_VERDICT).
    OLA_AMBIENT_IGOR=enforce  the answer is withheld (status BLOCK) unless IGOR accepted it AND the judge is
                              QUALIFIED by a measurement (OLA_JUDGE_QUALIFICATION_*, see docs/pipeline-bridge.md).
                              The verdict is an `igor.ambient` record. Every doubt is BLOCK.

Invariants (each one has a test)
* An unknown value of OLA_AMBIENT_IGOR is an error (HTTP 503), never "off". `enforce` without a judge model or
  without a qualification is an error (503) raised BEFORE the answering model is called.
* The ambient layer can only downgrade. It never turns a non-VERIFIED upstream status into VERIFIED.
* Records carry SHA-256 digests of the task and the output, never the text itself.
* No judge verdict is accepted from a TEST_DOUBLE runtime, from the model that wrote the answer (unless
  OLA_ALLOW_SAME_MODEL_IGOR=1), or from a judge whose measured false-accept bound is too high.

HONEST LIMITS
* The judge is a model. A QUALIFIED judge has a measured, bounded false-accept rate on ONE labelled set; it is
  not a proof that an answer is correct, and the numbers do not transfer to other domains.
* The task and the answer are sent to the judge. With the default local Ollama they stay on the host; with a
  hosted OLA_IGOR_PROVIDER they leave it.
* `shadow` measures; only `enforce` protects, and it costs one extra judge call (latency) per request.
"""
from __future__ import annotations

import hashlib
import logging
import os
from typing import Any, Dict, Optional

from ola_pipeline import PipelineConfig
from ola_pipeline.errors import ConfigError, OlaPipelineError
from ola_pipeline.igor import Igor, parse_judge
from ola_pipeline.providers import build_provider

from . import pipeline_bridge as pb
from .hashchain import canonical_json

log = logging.getLogger("ola.ambient")

MODES = ("off", "shadow", "enforce")
SCHEMA = "ola.ambient-igor/1"
SHADOW_TYPE = "igor.shadow"
ENFORCE_TYPE = "igor.ambient"
SURFACES = ("chat", "agent-run")

ACCEPT, REJECT, NO_VERDICT = "ACCEPT", "REJECT", "NO_VERDICT"
UNQUALIFIED, SELF_JUDGE, TOO_LONG, BUSY, ERROR = "UNQUALIFIED", "SELF_JUDGE", "TOO_LONG", "BUSY", "ERROR"


class AmbientConfigError(RuntimeError):
    """OLA_AMBIENT_IGOR (or what `enforce` needs) is not usable: surfaced as HTTP 503, never ignored."""


def mode() -> str:
    raw = os.environ.get("OLA_AMBIENT_IGOR", "").strip().lower()
    if not raw:
        return "off"
    if raw not in MODES:
        raise AmbientConfigError(f"OLA_AMBIENT_IGOR must be one of {', '.join(MODES)} (got {raw!r})")
    return raw


def _max_chars() -> int:
    try:
        return pb._int_env("OLA_AMBIENT_MAX_CHARS", 8000)
    except pb.PipelineNotConfigured as exc:
        raise AmbientConfigError(str(exc)) from exc


def _judge_setup():
    try:
        cfg = PipelineConfig.from_env()
        cfg.policy.validate()
        # No fallback to the pipeline's NINA model: the ambient judge must be chosen on purpose.
        if not os.environ.get("OLA_IGOR_MODEL", "").strip():
            raise ConfigError("OLA_IGOR_MODEL is not configured (no default judge by design)")
        build_provider(cfg.igor)          # unknown provider / missing model / missing URL surface here
    except OlaPipelineError as exc:
        raise AmbientConfigError(f"IGOR judge is not configured: {exc}") from exc
    return cfg


def preflight() -> None:
    """Everything `enforce` needs, checked before the answering model is called."""
    _max_chars()
    _judge_setup()
    try:
        policy = pb.qualification_policy_from_env()
    except pb.PipelineNotConfigured as exc:
        raise AmbientConfigError(str(exc)) from exc
    if policy is None:
        raise AmbientConfigError("OLA_AMBIENT_IGOR=enforce requires a judge qualification "
                                 "(OLA_JUDGE_QUALIFICATION_FILE and OLA_JUDGE_QUALIFICATION_DATASET_SHA256)")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _clip(text: Any, n: int = 200) -> str:
    return str(text)[:n]


def decide(text: str, min_quality_score: int) -> tuple[str, str]:
    """Same acceptance rule as Igor.verify and scripts/judge_eval.classify (a test pins the equality)."""
    judged, err = parse_judge(text or "")
    if judged is None:
        return NO_VERDICT, _clip(err)
    if judged["decision"] == "PASS" and not judged["required_corrections"] \
            and judged["quality_score"] >= min_quality_score:
        return ACCEPT, ""
    return REJECT, ""


def _judge(task: str, output: str, cfg, produced_by: Optional[str]) -> Dict[str, Any]:
    j: Dict[str, Any] = {"verdict": NO_VERDICT, "detail": "", "quality_score": None,
                         "judge": {"provider": cfg.igor.provider, "model": cfg.igor.model, "model_digest": None,
                                   "runtime_kind": None,
                                   "same_model_as_producer": bool(produced_by) and produced_by == cfg.igor.model}}
    try:
        with pb._run_slot():
            gen = build_provider(cfg.igor).execute(
                Igor(cfg.igor, cfg.nina, cfg.policy, cfg.quality_requirements)._messages(task, output, []), json_mode=True)
    except pb.PipelineBusy:
        j["verdict"], j["detail"] = BUSY, "judge is busy"
        return j
    except OlaPipelineError as exc:
        j["detail"] = _clip(f"{type(exc).__name__}: {exc}")
        return j
    j["judge"]["model_digest"] = gen.model_digest
    j["judge"]["runtime_kind"] = (gen.runtime_proof or {}).get("kind")
    j["verdict"], j["detail"] = decide(gen.text, cfg.policy.min_quality_score)
    judged, _ = parse_judge(gen.text or "")
    if judged is not None:
        j["quality_score"] = judged["quality_score"]
    return j


def _record(tenant_id: str, rtype: str, surface: str, md: str, task: str, output: str, j: Dict[str, Any],
            **extra: Any) -> dict:
    payload = {"schema": SCHEMA, "mode": md, "surface": surface, "task_digest": _sha(task),
               "output_digest": _sha(output), **{k: j[k] for k in ("verdict", "detail", "quality_score", "judge")},
               **extra}
    return pb.append_evidence(tenant_id, rtype, payload)


def _evaluate(task: str, output: str, produced_by: Optional[str]) -> tuple[Dict[str, Any], Any]:
    cfg = _judge_setup()
    if len(task) + len(output) > _max_chars():
        return {"verdict": TOO_LONG, "detail": f"task+output exceed OLA_AMBIENT_MAX_CHARS ({_max_chars()})",
                "quality_score": None, "judge": {"provider": cfg.igor.provider, "model": cfg.igor.model,
                                                 "model_digest": None, "runtime_kind": None,
                                                 "same_model_as_producer": False}}, cfg
    return _judge(task, output, cfg, produced_by), cfg


# ------------------------------------------------------------------ shadow
def shadow(tenant_id: str, surface: str, task: str, output: str, produced_by: Optional[str] = None) -> None:
    """Runs after the response is sent. Must not raise: a failure is recorded, then logged."""
    try:
        try:
            j, _ = _evaluate(task, output, produced_by)
        except Exception as exc:                                   # noqa: BLE001 - recorded, not hidden
            j = {"verdict": ERROR, "detail": _clip(f"{type(exc).__name__}: {exc}"), "quality_score": None, "judge": {}}
        _record(tenant_id, SHADOW_TYPE, surface, "shadow", task, output, j, enforced=False)
    except Exception:                                              # noqa: BLE001 - shadow never affects a request
        log.exception("ambient IGOR (shadow) could not record a verdict")


# ------------------------------------------------------------------ enforce
def enforce(tenant_id: str, surface: str, task: str, output: str, produced_by: Optional[str] = None) -> dict:
    """Returns {"allow": bool, "reason": str, "verdict": str, "evidence_seq": int|None}. Fail closed."""
    j, cfg = _evaluate(task, output, produced_by)
    if j["verdict"] == BUSY:
        raise pb.PipelineBusy("ambient IGOR judge is busy")
    qualification: Dict[str, Any] = {"state": "NOT_CHECKED"}
    reason = ""
    if j["verdict"] == ACCEPT:
        if j["judge"]["runtime_kind"] != "OLLAMA_OBSERVED":
            j["verdict"], reason = UNQUALIFIED, f"judge runtime is not observed (kind={j['judge']['runtime_kind']!r})"
        elif j["judge"]["same_model_as_producer"] and not cfg.policy.allow_same_model_igor:
            j["verdict"], reason = SELF_JUDGE, "the judge is the model that wrote the answer"
        else:
            try:
                qualification = pb.judge_qualification(
                    {"provider": j["judge"]["provider"], "model": j["judge"]["model"],
                     "model_digest": j["judge"]["model_digest"]}, pb.qualification_policy_from_env())
            except pb.PipelineNotConfigured as exc:
                raise AmbientConfigError(str(exc)) from exc
            if qualification["state"] != "QUALIFIED":
                j["verdict"], reason = UNQUALIFIED, f"judge is not qualified: {qualification['reason']}"
    elif j["verdict"] == REJECT:
        reason = "the judge rejected the answer"
    elif j["verdict"] == TOO_LONG:
        reason = j["detail"]
    else:
        reason = f"the judge gave no usable verdict ({j['detail'] or 'no detail'})"
    allow = j["verdict"] == ACCEPT
    try:
        rec = _record(tenant_id, ENFORCE_TYPE, surface, "enforce", task, output, j, enforced=True,
                      allowed=allow, qualification={k: v for k, v in qualification.items() if k != "reason"}
                      | ({"reason": _clip(qualification["reason"])} if "reason" in qualification else {}))
    except Exception as exc:                                       # noqa: BLE001 - an unrecorded decision is not allowed
        log.exception("ambient IGOR (enforce) could not record its verdict")
        return {"allow": False, "verdict": ERROR, "evidence_seq": None,
                "reason": f"the verdict could not be recorded ({type(exc).__name__})"}
    return {"allow": allow, "verdict": j["verdict"], "reason": reason, "evidence_seq": rec["seq"]}


def blocked_response(decision: dict) -> dict:
    """What the caller gets instead of the withheld answer (the answer itself is never echoed)."""
    return {"status": "BLOCK", "reason": f"IGOR did not confirm the answer: {decision['reason']}",
            "ambient": {"mode": "enforce", "verdict": decision["verdict"], "evidence_seq": decision["evidence_seq"]}}


def agent_output_text(result: dict) -> str:
    return canonical_json({"final_result": result.get("final_result"), "status": result.get("status")})
