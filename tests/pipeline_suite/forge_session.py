"""Builds sessions by hand through the real EvidenceVault (what a party able to write the vault could do).

A forged session is built the way the pipeline would have written it: the judge's raw reply mirrors its
evaluation, every envelope carries the gate_state its content derives, and the judge has its own digest
(equal digests would mean the same weights). Tests that need a deviation pass it explicitly
(`reply=`, `gate=`, `proof=`, `digest=`, `model=`, `provider=`, `endpoint=`, `status=` per judge/canary).
"""
import json
import secrets
from dataclasses import asdict
from pathlib import Path

from ola_pipeline import verify as V
from ola_pipeline.config import Policy
from ola_pipeline.hashing import canonical_bytes
from ola_pipeline.vault import EvidenceVault

SHA = "a" * 40
DIG = "d" * 64           # Nina's model digest
IGOR_DIG = "c" * 64      # the judge's: a different model has a different digest


def env(vault, sid, agent, it, parent, *, out=b"answer", refs=None, status="EXECUTED", gate="PENDING",
        provider="ollama-local", model="nina-m", digest=DIG, proof=None, endpoint=None, input_obj=None):
    run_id = "run_" + secrets.token_hex(8)
    inp = vault.put_artifact(canonical_bytes(input_obj or {"task": "t", "agent": agent, "n": secrets.token_hex(4)}))
    pr = vault.put_artifact(canonical_bytes([{"m": secrets.token_hex(4)}]))
    oh = vault.put_artifact(out) if status == "EXECUTED" else None
    ph = vault.put_artifact(canonical_bytes(proof or {"kind": "OLLAMA_OBSERVED"})) if status == "EXECUTED" else None
    e = {"schema_version": "ola.envelope/1", "session_id": sid, "run_id": run_id, "parent_run_id": parent,
         "source_sha": SHA, "source_sha_kind": "git-clean", "agent_id": agent, "provider": provider,
         "model": model, "model_digest": digest, "prompt_hash": pr, "input_hash": inp, "output_hash": oh,
         "timestamp": "2026-10-05T00:00:00.000+00:00", "iteration": it, "execution_status": status,
         "gate_state": gate, "endpoint": endpoint or ("http://x" if model == "nina-m" else "http://y"),
         "runtime_kind": (proof or {"kind": "OLLAMA_OBSERVED"}).get("kind"),
         "runtime_proof_hash": ph, "detail": "", "refs": refs or {}}
    return vault.append_envelope(e)


def judge_eval(vault, decision="PASS", score=92, corrections=(), js="OK", checks=None, independence="DIFFERENT_MODEL"):
    ev = {"decision": decision, "quality_score": score, "findings": [], "required_corrections": list(corrections),
          "evidence_checks": checks or [], "reason": "ok",
          "meta": {"judge_status": js, "correctable": False, "independence": independence}}
    return vault.put_artifact(canonical_bytes(ev))


def canary_verdict(decision, score, js):
    if js != "OK":
        return "UNAVAILABLE"
    int_score = isinstance(score, int) and not isinstance(score, bool)
    return "ACCEPTED" if decision == "PASS" and (not int_score or score >= 70) else "REJECTED"


def canary_eval(vault, decision="BLOCK", score=5, js="OK"):
    ev = {"canary": True, "task": V.CANARY_TASK, "output": V.CANARY_OUTPUT, "judge_status": js,
          "decision": decision, "quality_score": score, "verdict": canary_verdict(decision, score, js),
          "expected": "anything but PASS"}
    return vault.put_artifact(canonical_bytes(ev))


def reply(decision="PASS", score=92, corrections=(), reason="ok") -> bytes:
    """What a judge answered; the pipeline stores exactly this and derives the evaluation from it."""
    return json.dumps({"decision": decision, "quality_score": score, "findings": [],
                       "required_corrections": list(corrections), "reason": reason}).encode()


_IGOR_GATE = {"PASS": "PASS", "REVIEW": "REVIEW_REQUIRED", "BLOCK": "BLOCKED"}
_CANARY_GATE = {"UNAVAILABLE": "CANARY_UNAVAILABLE", "ACCEPTED": "CANARY_ACCEPTED", "REJECTED": "CANARY_REJECTED"}
_ENV_KEYS = ("reply", "gate", "proof", "digest", "model", "provider", "endpoint", "status")


def _split(kw):
    kw = dict(kw)
    return {k: kw.pop(k) for k in _ENV_KEYS if k in kw}, kw


def igor_env(vault, sid, n, kw, *, iteration, model="igor-m"):
    """One judge envelope for Nina run `n`; kw = judge_eval kwargs plus the envelope overrides in _ENV_KEYS."""
    over, kw = _split(kw)
    decision, js = kw.get("decision", "PASS"), kw.get("js", "OK")
    ev_hash = judge_eval(vault, **kw)
    out = over.pop("reply", reply(decision, kw.get("score", 92), kw.get("corrections", ())) if js == "OK"
                   else b"not a verdict")
    gate = over.pop("gate", _IGOR_GATE.get(decision, "BLOCKED"))
    over.setdefault("model", model)
    over.setdefault("digest", IGOR_DIG)
    e = env(vault, sid, "igor", iteration, n["run_id"], out=out, gate=gate,
            refs={"verifies_run_id": n["run_id"], "verifies_envelope_hash": n["envelope_hash"],
                  "evaluation_hash": ev_hash}, **over)
    return e, ev_hash


def canary_env(vault, sid, n, kw, *, iteration, model="igor-m"):
    over, kw = _split(kw)
    decision, score, js = kw.get("decision", "BLOCK"), kw.get("score", 5), kw.get("js", "OK")
    ev_hash = canary_eval(vault, **kw)
    out = over.pop("reply", reply(decision, score) if js == "OK" else b"not a verdict")
    gate = over.pop("gate", _CANARY_GATE[canary_verdict(decision, score, js)])
    over.setdefault("model", model)
    over.setdefault("digest", IGOR_DIG)
    return env(vault, sid, "igor-canary", iteration, n["run_id"], out=out, gate=gate,
               refs={"verifies_run_id": n["run_id"], "evaluation_hash": ev_hash}, **over)


def finalize(vault, policy):
    facts = V.inspect_session(vault.dir)
    pol = dict(policy) if isinstance(policy, dict) else asdict(policy)     # a dict forges a policy Policy() refuses
    d = V.derive_gate(facts, pol, SHA)
    n, g = facts.last_nina, facts.last_igor
    final = {"schema_version": "ola.final/1", "session_id": vault.session_id,
             "run_id": n["run_id"] if n else None, "source_sha": n["source_sha"] if n else SHA,
             "source_sha_kind": "git-clean", "source_sha_end": SHA,
             "provider": n["provider"] if n else None, "model": n["model"] if n else None,
             "model_digest": n.get("model_digest") if n else None, "iterations": len(facts.nina),
             "nina_status": d["nina_status"], "igor_status": d["igor_status"], "gate_state": d["state"],
             "gate_reasons": d["reasons"], "warnings": d["warnings"], "evidence_class": d["evidence_class"],
             "evidence": {"input_hash": n["input_hash"] if n else None,
                          "output_hash": n["output_hash"] if n else None,
                          "evaluation_hash": (g.get("refs") or {}).get("evaluation_hash") if g else None},
             "runs": V.summarize_runs(facts),
             "chain_head": facts.envelopes[-1]["envelope_hash"] if facts.envelopes else None,
             "policy": pol, "anti_replay": {"final_nonce": secrets.token_hex(16), "binding": ""}}
    final["anti_replay"]["binding"] = V.compute_final_binding(final)
    vault.write_final(final)
    return final


def session(root, *, policy=None, nina_n=1, igors=None, canaries=None, extra=None, igor_model="igor-m",
            chain=True, earlier=None, nina_gate="PENDING"):
    """igors / canaries: lists of kwargs for judge_eval / canary_eval (one envelope each) plus per-envelope
    overrides (see the module docstring). policy: a Policy, or a dict for a snapshot Policy() would refuse.

    nina_n > 1 builds the iteration chain the pipeline writes: a verdict (`earlier`, REVIEW by default) on every
    iteration before the last and correction refs on the next one. chain=False writes neither (a bare re-roll),
    "no-refs" / "wrong-refs" keep the verdicts but drop / misdirect the correction refs, "input-only" drops the refs
    but names the verdict in the (hash-bound) input artifact, as sessions written before the refs existed do."""
    policy = policy or Policy()
    sid = "ses_" + secrets.token_hex(6)
    v = EvidenceVault(Path(root), sid)
    parent, n, link = None, None, {}
    link_input = None
    for it in range(1, nina_n + 1):
        n = env(v, sid, "nina", it, parent, refs=link, gate=nina_gate, input_obj=link_input)
        parent = n["run_id"]
        if chain and it < nina_n:
            _, ev_hash = igor_env(v, sid, n, earlier or {"decision": "REVIEW", "score": 40, "corrections": ["fix it"]},
                                  iteration=it, model=igor_model)
            link = {"correction_of_run_id": n["run_id"], "correction_evaluation_hash": ev_hash}
            link_input = None
            if chain == "no-refs":
                link = {}
            elif chain == "wrong-refs":
                link["correction_evaluation_hash"] = "0" * 64
            elif chain == "input-only":
                link_input = {"task": "t", "previous_run_id": n["run_id"], "evaluation_hash": ev_hash}
                link = {}
    for kw in (igors if igors is not None else [{}]):
        igor_env(v, sid, n, kw, iteration=nina_n, model=igor_model)
    for kw in (canaries if canaries is not None else [{}]):
        canary_env(v, sid, n, kw, iteration=nina_n, model=igor_model)
    if extra:
        extra(v, sid, n)
    return v, finalize(v, policy)
