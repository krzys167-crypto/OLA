"""NINA -> OLLAMA -> EVIDENCE -> IGOR -> GATE -> REPLAY (max 3 iterations)."""
from __future__ import annotations

import secrets
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from . import attest, verify
from .config import PipelineConfig
from .hashing import sha256_hex
from .errors import ConfigError, SigningError
from .igor import Igor
from .nina import Nina
from .redact import contains_secret
from .source import RunIdFactory, SourceAnchor, freeze_source, mint_final_nonce
from .stage import run_stage
from .vault import EvidenceVault


@dataclass
class PipelineRun:
    final: Dict[str, Any]
    session_dir: Path
    attestation: Optional[Dict[str, Any]] = None  # None = not signed (no signing key configured)


class Pipeline:
    def __init__(self, cfg: PipelineConfig, *, source_fn: Callable[[], SourceAnchor] = freeze_source):
        cfg.policy.validate()
        self.cfg = cfg
        self.source_fn = source_fn

    def run(self, task: str) -> PipelineRun:
        if not isinstance(task, str):
            raise ConfigError("task must be a string")
        try:
            task.encode("utf-8")           # a lone surrogate cannot be stored: refuse before any session exists
        except UnicodeEncodeError:
            raise ConfigError("task is not valid UTF-8 text (lone surrogate)") from None
        cfg = self.cfg
        anchor = self.source_fn()  # 1. freeze source BEFORE any run id exists
        session_id = "ses_" + secrets.token_hex(12)
        vault = EvidenceVault(cfg.vault_root, session_id)
        ids = RunIdFactory(anchor)
        nina = Nina(cfg.nina)
        igor = Igor(cfg.igor, cfg.nina, cfg.policy, cfg.quality_requirements)

        if contains_secret(task, cfg.nina.known_secrets() + cfg.igor.known_secrets()):
            run_stage(vault=vault, anchor=anchor, session_id=session_id, run_id=ids.new(),
                      parent_run_id=None, agent_id=nina.agent_id, iteration=1, cfg=cfg.nina,
                      messages=[], input_obj={"task": "[REDACTED: probable secret, not persisted]"},
                      skip_reason="task rejected: contains a probable secret; nothing was sent or stored")
        else:
            parent: Optional[str] = None
            correction: Optional[Dict[str, Any]] = None
            for it in range(1, cfg.policy.max_iterations + 1):
                n = nina.execute(vault=vault, anchor=anchor, session_id=session_id, run_id=ids.new(),
                                 parent_run_id=parent, iteration=it, task=task, correction=correction)
                if n.status != "EXECUTED":
                    break  # no real execution -> nothing to verify -> Gate blocks
                g = igor.verify(vault=vault, anchor=anchor, session_id=session_id, run_id=ids.new(),
                                task=task, nina_env=n.envelope, nina_output=n.output_text, iteration=it)
                if g.decision == "PASS" and cfg.policy.require_igor_calibration:
                    igor.calibrate(vault=vault, anchor=anchor, session_id=session_id, run_id=ids.new(),
                                   nina_env=n.envelope, iteration=it)
                if g.decision == "PASS" or not g.correctable or it == cfg.policy.max_iterations:
                    break
                correction = {
                    "previous_run_id": n.envelope["run_id"], "previous_output": n.output_text,
                    "previous_output_hash": n.envelope["output_hash"],
                    "required_corrections": g.required_corrections, "evaluation_hash": g.evaluation_hash,
                }
                parent = n.envelope["run_id"]

        end_anchor = self.source_fn()  # 2. re-freeze source at the end
        policy = asdict(cfg.policy)
        facts = verify.inspect_session(vault.dir)
        d = verify.derive_gate(facts, policy, end_anchor.sha)
        nonce = mint_final_nonce(end_anchor)  # 3. only now: final nonce
        n_env, g_env = facts.last_nina, facts.last_igor
        final: Dict[str, Any] = {
            "schema_version": "ola.final/1",
            "session_id": session_id,
            "run_id": n_env["run_id"] if n_env else None,
            "source_sha": n_env["source_sha"] if n_env else anchor.sha,
            "source_sha_kind": anchor.kind,
            "source_sha_end": end_anchor.sha,
            "provider": n_env["provider"] if n_env else None,
            "model": n_env["model"] if n_env else None,
            "model_digest": n_env.get("model_digest") if n_env else None,
            "iterations": len(facts.nina),
            "nina_status": d["nina_status"],
            "igor_status": d["igor_status"],
            "gate_state": d["state"],
            "gate_reasons": d["reasons"],
            "warnings": d["warnings"],
            "evidence_class": d["evidence_class"],
            "evidence": {
                "input_hash": n_env["input_hash"] if n_env else None,
                "output_hash": n_env["output_hash"] if n_env else None,
                "evaluation_hash": (g_env.get("refs") or {}).get("evaluation_hash") if g_env else None,
            },
            "runs": verify.summarize_runs(facts),
            "chain_head": facts.envelopes[-1]["envelope_hash"] if facts.envelopes else None,
            "policy": policy,
            "anti_replay": {"final_nonce": nonce, "binding": ""},
        }
        final["anti_replay"]["binding"] = verify.compute_final_binding(final)
        vault.write_final(final)
        run = PipelineRun(final, vault.dir)
        if cfg.signing_key_file is not None:
            try:  # signing was requested: failing to sign must never look like success
                run.attestation = attest.sign_session(vault.dir, cfg.signing_key_file, vault_root=cfg.vault_root)
            except SigningError as e:
                e.run = run
                raise
        return run
