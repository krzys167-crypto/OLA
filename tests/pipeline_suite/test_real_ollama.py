"""LIVE tests — run only against a real Ollama. Otherwise SKIPPED, i.e. the result is UNKNOWN.

    OLA_TEST_MODEL=<model you have pulled> pytest tests/test_real_ollama.py -rs
    (optional) OLA_OLLAMA_URL=http://localhost:11434   OLA_TEST_IGOR_MODEL=<second model>
    (reasoning models, e.g. qwen3) OLA_TEST_THINK=0   OLA_TEST_MAX_TOKENS=96
"""
import json
import os
import urllib.request

import pytest

from ola_pipeline import Pipeline, Policy, verify_session
from ola_pipeline.config import PipelineConfig, ProviderConfig

URL = os.environ.get("OLA_OLLAMA_URL", "http://localhost:11434")
MODEL = os.environ.get("OLA_TEST_MODEL", "")


def _live():
    try:
        with urllib.request.urlopen(URL + "/api/version", timeout=2) as r:
            v = json.loads(r.read()).get("version", "")
        return bool(v) and "test-double" not in v
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not (_live() and MODEL),
    reason=f"no live Ollama at {URL} and/or OLA_TEST_MODEL unset -> real runtime result is UNKNOWN",
)


def _cfg(tmp_path, model, **policy_kw):
    igor_model = os.environ.get("OLA_TEST_IGOR_MODEL", MODEL)
    think = {"0": False, "1": True}.get(os.environ.get("OLA_TEST_THINK", ""))
    mt = os.environ.get("OLA_TEST_MAX_TOKENS")
    return PipelineConfig(
        nina=ProviderConfig("ollama-local", model, base_url=URL, timeout_s=600, seed=1, think=think,
                            max_tokens=int(mt) if mt else None),
        igor=ProviderConfig("ollama-local", igor_model, base_url=URL, timeout_s=600, temperature=0.0,
                            seed=1, think=think, max_tokens=400 if mt else None),
        policy=Policy(**policy_kw),  # strict defaults: no test doubles, digest + calibration + independence
        vault_root=tmp_path / "vault",
    )


def test_real_ollama_executes_and_evidence_verifies(tmp_path):
    r = Pipeline(_cfg(tmp_path, MODEL)).run("State the capital of France in one sentence.")
    f = r.final
    assert f["nina_status"] == "EXECUTED" and f["evidence_class"] == "LIVE_RUNTIME_OBSERVED"
    assert f["model_digest"], "live Ollama must expose a model digest via /api/tags"
    rep = verify_session(r.session_dir)
    assert rep["failures"] == []
    assert rep["overall"] in ("VERIFIED", "CONSISTENT")  # PASS depends on Igor's judgement, not asserted
    print("LIVE RESULT:", f["gate_state"], f["igor_status"], f["run_id"])


def test_real_ollama_unknown_model_fails_closed(tmp_path):
    r = Pipeline(_cfg(tmp_path, "definitely-not-a-pulled-model:0")).run("anything")
    assert r.final["nina_status"] == "MODEL_UNRESOLVED" and r.final["gate_state"] == "BLOCKED"


def test_real_ollama_pass_implies_igor_rejected_the_canary(tmp_path):
    """Property that must hold for ANY model quality: a PASS is only possible if the judge, on the
    same endpoint/model, rejected the known-wrong canary. Same-model self-verification is opted in
    here only so the property is exercised with a single pulled model."""
    r = Pipeline(_cfg(tmp_path, MODEL, allow_same_model_igor=True)).run(
        "State the capital of France in one sentence.")
    f = r.final
    canary = [json.loads(p.read_text()) for p in sorted((r.session_dir / "envelopes").glob("*.json"))
              if json.loads(p.read_text())["agent_id"] == "igor-canary"]
    print("LIVE RESULT:", f["gate_state"], f["igor_status"], [c["gate_state"] for c in canary])
    if f["gate_state"] == "PASS":
        assert canary and canary[-1]["gate_state"] == "CANARY_REJECTED"
    assert verify_session(r.session_dir)["failures"] == []
