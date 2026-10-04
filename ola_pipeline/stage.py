"""One LLM stage = one Evidence Envelope. Every failure becomes a recorded, blocked envelope."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from .config import ProviderConfig
from .errors import (ConfigError, ModelUnresolved, ProviderError, ProviderTimeout,
                     ProviderUnavailable, SecretDetected, UnknownProviderError)
from .hashing import canonical_bytes
from .providers import build_provider
from .redact import scrub
from .source import SourceAnchor
from .vault import EvidenceVault


@dataclass
class StageResult:
    envelope: Dict[str, Any]
    output_text: Optional[str]
    status: str
    detail: str


# finalize(status, text, detail) -> {"refs": {...}, "gate_state": "..."}  (both optional)
Finalize = Callable[[str, Optional[str], str], Dict[str, Any]]


def run_stage(*, vault: EvidenceVault, anchor: SourceAnchor, session_id: str, run_id: str,
              parent_run_id: Optional[str], agent_id: str, iteration: int, cfg: ProviderConfig,
              messages: List[Dict[str, str]], input_obj: Any, json_mode: bool = False,
              skip_reason: Optional[str] = None, finalize: Optional[Finalize] = None,
              refs: Optional[Dict[str, Any]] = None) -> StageResult:
    input_hash = vault.put_artifact(canonical_bytes(input_obj))
    prompt_hash = None if skip_reason else vault.put_artifact(canonical_bytes(messages))
    known = cfg.known_secrets()
    status, detail = "EXECUTED", ""
    text: Optional[str] = None
    proof: Optional[Dict[str, Any]] = None
    digest: Optional[str] = None

    if skip_reason:
        status, detail = "NOT_EXECUTED", skip_reason
    else:
        try:
            gen = build_provider(cfg).execute(messages, json_mode=json_mode)
            if any(len(k) >= 8 and k in gen.text for k in known):
                raise SecretDetected("output contained a configured secret; not persisted")
            if not gen.text.strip():
                raise ProviderError("empty output")
            text, proof, digest = gen.text, gen.runtime_proof, gen.model_digest
        except UnknownProviderError as e:
            status, detail = "PROVIDER_UNKNOWN", str(e)
        except ConfigError as e:
            status, detail = "CONFIG_ERROR", str(e)
        except ProviderUnavailable as e:
            status, detail = "PROVIDER_UNAVAILABLE", str(e)
        except ModelUnresolved as e:
            status, detail = "MODEL_UNRESOLVED", str(e)
        except ProviderTimeout as e:
            status, detail = "TIMEOUT", str(e)
        except (ProviderError, SecretDetected) as e:
            status, detail = "ERROR", str(e)
        except Exception as e:  # fail closed on anything unexpected
            status, detail = "ERROR", f"{type(e).__name__}: {e}"

    output_hash = proof_hash = None
    if status == "EXECUTED":
        output_hash = vault.put_artifact(text.encode("utf-8"))
        proof_hash = vault.put_artifact(canonical_bytes(proof))

    gate_state = "PENDING" if status == "EXECUTED" else "BLOCKED"
    all_refs: Dict[str, Any] = dict(refs or {})
    if finalize is not None:
        extra = finalize(status, text, detail) or {}
        all_refs.update(extra.get("refs", {}))
        gate_state = extra.get("gate_state", gate_state)

    env = {
        "schema_version": "ola.envelope/1",
        "session_id": session_id, "run_id": run_id, "parent_run_id": parent_run_id,
        "source_sha": anchor.sha, "source_sha_kind": anchor.kind,
        "agent_id": agent_id, "provider": cfg.provider, "model": cfg.model,
        "model_digest": digest,
        "prompt_hash": prompt_hash, "input_hash": input_hash, "output_hash": output_hash,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "iteration": iteration, "execution_status": status, "gate_state": gate_state,
        "endpoint": cfg.public_endpoint(),
        "runtime_kind": proof.get("kind") if proof else None,
        "runtime_proof_hash": proof_hash,
        "detail": scrub(detail, known)[:500],
        "refs": all_refs,
    }
    env = vault.append_envelope(env)
    return StageResult(env, text, status, detail)
