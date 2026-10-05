"""Builds sessions by hand through the real EvidenceVault (what a party able to write the vault could do)."""
import secrets
from dataclasses import asdict
from pathlib import Path

from ola_pipeline import verify as V
from ola_pipeline.config import Policy
from ola_pipeline.hashing import canonical_bytes
from ola_pipeline.vault import EvidenceVault

SHA = "a" * 40
DIG = "d" * 64


def env(vault, sid, agent, it, parent, *, out=b"answer", refs=None, status="EXECUTED", gate="PENDING",
        provider="ollama-local", model="nina-m", digest=DIG, proof=None):
    run_id = "run_" + secrets.token_hex(8)
    inp = vault.put_artifact(canonical_bytes({"task": "t", "agent": agent, "n": secrets.token_hex(4)}))
    pr = vault.put_artifact(canonical_bytes([{"m": secrets.token_hex(4)}]))
    oh = vault.put_artifact(out) if status == "EXECUTED" else None
    ph = vault.put_artifact(canonical_bytes(proof or {"kind": "OLLAMA_OBSERVED"})) if status == "EXECUTED" else None
    e = {"schema_version": "ola.envelope/1", "session_id": sid, "run_id": run_id, "parent_run_id": parent,
         "source_sha": SHA, "source_sha_kind": "git-clean", "agent_id": agent, "provider": provider,
         "model": model, "model_digest": digest, "prompt_hash": pr, "input_hash": inp, "output_hash": oh,
         "timestamp": "2026-10-05T00:00:00.000+00:00", "iteration": it, "execution_status": status,
         "gate_state": gate, "endpoint": "http://x" if model == "nina-m" else "http://y",
         "runtime_kind": (proof or {"kind": "OLLAMA_OBSERVED"}).get("kind"),
         "runtime_proof_hash": ph, "detail": "", "refs": refs or {}}
    return vault.append_envelope(e)


def judge_eval(vault, decision="PASS", score=92, corrections=(), js="OK", checks=None, independence="DIFFERENT_MODEL"):
    ev = {"decision": decision, "quality_score": score, "findings": [], "required_corrections": list(corrections),
          "evidence_checks": checks or [], "reason": "ok",
          "meta": {"judge_status": js, "correctable": False, "independence": independence}}
    return vault.put_artifact(canonical_bytes(ev))


def canary_eval(vault, decision="BLOCK", score=5, js="OK"):
    ev = {"canary": True, "task": V.CANARY_TASK, "output": V.CANARY_OUTPUT, "judge_status": js,
          "decision": decision, "quality_score": score, "verdict": "x", "expected": "anything but PASS"}
    return vault.put_artifact(canonical_bytes(ev))


def finalize(vault, policy):
    facts = V.inspect_session(vault.dir)
    pol = asdict(policy)
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


def session(root, *, policy=None, nina_n=1, igors=None, canaries=None, extra=None, igor_model="igor-m"):
    """igors / canaries: lists of kwargs for judge_eval / canary_eval (one envelope each)."""
    policy = policy or Policy()
    sid = "ses_" + secrets.token_hex(6)
    v = EvidenceVault(Path(root), sid)
    parent, n = None, None
    for it in range(1, nina_n + 1):
        n = env(v, sid, "nina", it, parent)
        parent = n["run_id"]
    for kw in (igors if igors is not None else [{}]):
        env(v, sid, "igor", nina_n, n["run_id"], out=b"igor-out", model=igor_model, gate="PASS",
            refs={"verifies_run_id": n["run_id"], "verifies_envelope_hash": n["envelope_hash"],
                  "evaluation_hash": judge_eval(v, **kw)})
    for kw in (canaries if canaries is not None else [{}]):
        env(v, sid, "igor-canary", nina_n, n["run_id"], out=b"c-out", model=igor_model,
            refs={"verifies_run_id": n["run_id"], "evaluation_hash": canary_eval(v, **kw)})
    if extra:
        extra(v, sid, n)
    return v, finalize(v, policy)
