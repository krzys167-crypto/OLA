"""LIVE bridge test - only against a real Ollama. Otherwise SKIPPED, i.e. the real-runtime result is UNKNOWN.

    OLA_TEST_MODEL=<pulled model> python -m pytest tests/test_pipeline_bridge_live.py -rs -s
    (optional) OLA_OLLAMA_URL=http://localhost:11434  OLA_TEST_IGOR_MODEL=<second model>
    (optional) OLA_TEST_IGOR_THINK=0|1|""   judge reasoning flag; empty = not sent (non-reasoning judge)
    (reasoning models, e.g. qwen3) OLA_TEST_THINK=0  OLA_TEST_MAX_TOKENS=96

The Gate's PASS depends on the judge, so the test does NOT assert PASS. It asserts the invariants that
must hold for ANY real outcome: live evidence class, model digest, anchoring, independent re-verification,
and that nothing short of VERIFIED+human approval ever ends VERIFIED.
"""
import hashlib
import json
import os
import urllib.request
import uuid

import pytest
from fastapi.testclient import TestClient

from app import pipeline_bridge as pb
from app.database import SessionLocal
from app.hashchain import verify_chain
from app.main import app
from app.models import ApiKey, Tenant

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


def test_live_pipeline_run_is_anchored_and_reverifiable(monkeypatch, tmp_path):
    igor_model = os.environ.get("OLA_TEST_IGOR_MODEL", MODEL)
    monkeypatch.setenv("OLA_PIPELINE_VAULT_DIR", str(tmp_path / "vaults"))
    monkeypatch.setenv("OLA_NINA_PROVIDER", "ollama-local")
    monkeypatch.setenv("OLA_NINA_MODEL", MODEL)
    monkeypatch.setenv("OLA_NINA_BASE_URL", URL)
    monkeypatch.setenv("OLA_IGOR_MODEL", igor_model)
    monkeypatch.setenv("OLA_NINA_TIMEOUT_S", "600")
    monkeypatch.setenv("OLA_IGOR_TIMEOUT_S", "600")
    monkeypatch.setenv("OLA_NINA_SEED", "1")
    monkeypatch.setenv("OLA_IGOR_SEED", "1")
    if igor_model == MODEL:                                    # one model available: explicit, visible opt-in
        monkeypatch.setenv("OLA_ALLOW_SAME_MODEL_IGOR", "1")
    nina_think = os.environ.get("OLA_TEST_THINK")
    igor_think = os.environ.get("OLA_TEST_IGOR_THINK", nina_think)   # "" = do not send `think` (non-reasoning judge)
    if nina_think in ("0", "1"):
        monkeypatch.setenv("OLA_NINA_THINK", nina_think)
    if igor_think in ("0", "1"):
        monkeypatch.setenv("OLA_IGOR_THINK", igor_think)
    if os.environ.get("OLA_TEST_MAX_TOKENS"):
        monkeypatch.setenv("OLA_NINA_MAX_TOKENS", os.environ["OLA_TEST_MAX_TOKENS"])
        monkeypatch.setenv("OLA_IGOR_MAX_TOKENS", "400")

    tenant, key = str(uuid.uuid4()), "live-" + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(Tenant(id=tenant, name="live"))
        db.add(ApiKey(id=str(uuid.uuid4()), tenant_id=tenant, key_hash=hashlib.sha256(key.encode()).hexdigest()))
        db.commit()

    client = TestClient(app)
    r = client.post("/pipeline-run", headers={"X-API-Key": key}, json={
        "task": "State the capital of France in one sentence.",
        "human_approved": True, "human_actor": "live-test", "human_reason": "approved after verification"})
    assert r.status_code == 200, r.text
    b = r.json()
    print("LIVE RESULT:", b["status"], "| nina", MODEL, "| judge", igor_model,
          "(independent)" if igor_model != MODEL else "(SAME MODEL, opt-in)",
          "| gate", b["igor"]["gate_state"], "| igor", b["igor"]["status"],
          "| session", b["session_id"], "| head", b["pipeline"]["chain_head"],
          "| reasons", b["igor"]["gate_reasons"])

    assert b["nina"]["evidence_class"] == "LIVE_RUNTIME_OBSERVED"
    assert b["nina"]["model_digest"], "live Ollama must expose a model digest"
    assert b["pipeline"]["status"] == "ANCHORED"
    if igor_model != MODEL:                                    # a different judge must never be reported as non-independent
        assert "not independent" not in " ".join(map(str, b["igor"]["gate_reasons"])).lower()
    assert verify_chain(pb.load_chain(tenant))[0]
    if b["igor"]["status"] != "VERIFIED":                      # e.g. judge failed calibration -> UNKNOWN
        assert b["status"] == "BLOCK"
    else:
        assert b["status"] == "VERIFIED" and b["igor"]["gate_state"] == "PASS"

    again = client.get(f"/pipeline-session/{b['session_id']}", headers={"X-API-Key": key}).json()
    assert again["verification"]["status"] == b["igor"]["status"]
    assert again["verification"]["chain_head"] == b["pipeline"]["chain_head"]
    assert again["replay_verification"]["status"] == "PASS"
