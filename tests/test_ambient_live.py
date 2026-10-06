"""LIVE ambient NINA/IGOR - only against a real Ollama judge. Otherwise SKIPPED, i.e. the real-runtime result is UNKNOWN.

    OLA_TEST_IGOR_MODEL=<pulled judge> [OLA_TEST_IGOR_THINK=0|1] python -m pytest tests/test_ambient_live.py -rs -s

The answering model is a stub (the real /chat needs OPENAI_API_KEY); the JUDGE is real. A judge is not stable,
so nothing here asserts that it accepts the right answer or rejects the wrong one - that is measured by
scripts/judge_eval.py. What must hold for ANY real verdict is asserted: a verdict is recorded with an observed
runtime and a model digest, shadow never changes a response, enforce lets an answer through iff the verdict is
ACCEPT, and a withheld answer is never echoed. The observed verdicts are printed as `LIVE RESULT:` lines.

The qualification file used for `enforce` is a TEST FIXTURE carrying the judge's real digest: it exercises the
plumbing, it is NOT a measurement of this judge.
"""
import json
import os
import sys
import urllib.request
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pipeline_bridge import make_tenant, require_qualification, write_qualification  # noqa: E402

from app import pipeline_bridge as pb  # noqa: E402
from app.hashchain import verify_chain  # noqa: E402
from app.main import app  # noqa: E402

URL = os.environ.get("OLA_OLLAMA_URL", "http://localhost:11434")
JUDGE = os.environ.get("OLA_TEST_IGOR_MODEL", "")
RIGHT = ("What is the capital of France?", "The capital of France is Paris.")
WRONG = ("What is the capital of France?", "The capital of France is Berlin.")


def _get(path):
    with urllib.request.urlopen(URL + path, timeout=5) as r:
        return json.loads(r.read())


def _live():
    try:
        v = _get("/api/version").get("version", "")
        return bool(v) and "test-double" not in v
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not (_live() and JUDGE),
    reason=f"no live Ollama at {URL} and/or OLA_TEST_IGOR_MODEL unset -> real runtime result is UNKNOWN",
)


@pytest.fixture
def live(monkeypatch):
    for k in list(os.environ):
        if k.startswith("OLA_") and k not in ("OLA_EG_DB_PATH", "OLA_RUNTIME_COMMIT") and not k.startswith("OLA_TEST_") \
                and k != "OLA_OLLAMA_URL":
            monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("OLA_NINA_PROVIDER", "ollama-local")
    monkeypatch.setenv("OLA_NINA_MODEL", "stub-answerer")
    monkeypatch.setenv("OLA_NINA_BASE_URL", URL)
    monkeypatch.setenv("OLA_IGOR_MODEL", JUDGE)
    monkeypatch.setenv("OLA_IGOR_TIMEOUT_S", "600")
    monkeypatch.setenv("OLA_IGOR_SEED", "1")
    think = os.environ.get("OLA_TEST_IGOR_THINK", "")
    if think in ("0", "1"):
        monkeypatch.setenv("OLA_IGOR_THINK", think)
    state = {"answer": None}

    def fake_chat(tenant_id, messages):
        return {"status": "VERIFIED", "message": state["answer"], "model": "stub-answerer"}

    monkeypatch.setattr("app.main.chat", fake_chat)
    return monkeypatch, state


def _digest():
    hit = next(m for m in _get("/api/tags")["models"] if JUDGE in (m.get("name"), m.get("model")))
    return hit["digest"]


def _chat(key, q):
    return TestClient(app).post("/chat", headers={"X-API-Key": key}, json={"messages": [{"role": "user", "content": q}]})


def _records(tenant, rtype):
    return [json.loads(r["payload_json"]) | {"_seq": r["seq"]} for r in pb.load_chain(tenant) if r["record_type"] == rtype]


def test_live_shadow_records_real_verdicts_and_never_touches_the_response(live):
    mp, state = live
    mp.setenv("OLA_AMBIENT_IGOR", "shadow")
    tenant, key = make_tenant()
    seen = {}
    for name, (q, a) in (("right", RIGHT), ("wrong", WRONG)):
        state["answer"] = a
        r = _chat(key, q)
        assert r.status_code == 200 and r.json() == {"status": "UNKNOWN", "verification": "NOT_JUDGED", "message": a, "model": "stub-answerer"}
    recs = _records(tenant, "igor.shadow")
    assert len(recs) == 2, recs
    for name, rec in zip(("right", "wrong"), recs):
        j = rec["judge"]
        assert rec["enforced"] is False and rec["surface"] == "chat"
        assert rec["verdict"] in ("ACCEPT", "REJECT", "NO_VERDICT"), rec     # ERROR/BUSY/TOO_LONG would mean the setup is wrong
        if rec["verdict"] != "NO_VERDICT":
            assert j["runtime_kind"] == "OLLAMA_OBSERVED" and j["model_digest"], rec
        seen[name] = rec["verdict"]
    ok, why = verify_chain(pb.load_chain(tenant))
    assert ok, why
    print(f"\nLIVE RESULT: ambient shadow judge={JUDGE} right={seen['right']} wrong={seen['wrong']}")


def test_live_enforce_lets_an_answer_through_iff_the_real_verdict_is_ACCEPT(live):
    mp, state = live
    mp.setenv("OLA_AMBIENT_IGOR", "enforce")
    tmp = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / f"ambient-live-{os.getpid()}"
    tmp.mkdir(parents=True, exist_ok=True)
    require_qualification(mp, write_qualification(tmp, k=0, n=26, model=JUDGE, digest=_digest()))
    tenant, key = make_tenant()
    out = {}
    for name, (q, a) in (("right", RIGHT), ("wrong", WRONG)):
        state["answer"] = a
        r = _chat(key, q)
        assert r.status_code == 200, r.text
        body = r.json()
        rec = _records(tenant, "igor.ambient")[-1]
        assert rec["enforced"] is True, rec
        if rec["verdict"] == "ACCEPT":
            assert rec["qualification"]["state"] == "QUALIFIED", rec
            assert body["status"] == "VERIFIED" and body["message"] == a and rec["allowed"] is True
        else:
            assert body["status"] == "BLOCK" and a not in r.text and rec["allowed"] is False, (body, rec)
            assert body["ambient"]["verdict"] == rec["verdict"]
        out[name] = rec["verdict"]
    print(f"\nLIVE RESULT: ambient enforce judge={JUDGE} right={out['right']} wrong={out['wrong']} "
          f"(qualification is a test fixture, not a measurement)")
