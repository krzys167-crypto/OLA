"""Ambient NINA/IGOR (OLA_AMBIENT_IGOR=off|shadow|enforce) on /chat and /agent-run.

Runs against a TEST DOUBLE of the Ollama HTTP API (`fake.version = "0.99.0"` makes it look like a non-declared
endpoint so the runtime is labelled OLLAMA_OBSERVED - this exercises the logic, it is not runtime proof) and a
stub of the answering model (the real /chat needs OPENAI_API_KEY). Nothing here proves a real judge is accurate:
that is what the qualification measurement is for.
"""
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent / "pipeline_suite"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from fake_ollama import FakeOllama  # noqa: E402
from pipeline_helpers import igor_json  # noqa: E402
from test_pipeline_bridge import make_tenant, require_qualification, write_qualification  # noqa: E402

from app import ambient, pipeline_bridge as pb  # noqa: E402
from app.hashchain import verify_chain  # noqa: E402
from app.main import app  # noqa: E402

QUESTION = "What is the capital of France?"
ANSWER = "Paris is the capital of France."
CHAT_MODEL = "gpt-stub"


@pytest.fixture
def fake():
    f = FakeOllama().start()
    f.add_model("igor-test")
    f.version = "0.99.0"
    f.script("igor-test", igor_json("PASS", 92))
    yield f
    f.stop()


@pytest.fixture
def env(monkeypatch, fake):
    for k in list(os.environ):
        if k.startswith("OLA_") and k not in ("OLA_EG_DB_PATH", "OLA_RUNTIME_COMMIT"):
            monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("OLA_NINA_PROVIDER", "ollama-local")
    monkeypatch.setenv("OLA_NINA_MODEL", CHAT_MODEL)
    monkeypatch.setenv("OLA_NINA_BASE_URL", fake.url)
    monkeypatch.setenv("OLA_IGOR_MODEL", "igor-test")
    monkeypatch.setenv("OLA_IGOR_TIMEOUT_S", "10")
    return monkeypatch


@pytest.fixture
def answering(env):
    """Stub of the model that answers /chat; counts calls so tests can prove it was (not) called."""
    state = {"calls": 0, "response": {"status": "VERIFIED", "message": ANSWER, "model": CHAT_MODEL}}

    def fake_chat(tenant_id, messages):
        state["calls"] += 1
        return dict(state["response"])

    env.setattr("app.main.chat", fake_chat)
    return state


def unjudged(answering):
    """Without an enforce-mode ACCEPT by a qualified independent judge, /chat reports UNKNOWN, never VERIFIED."""
    return dict(answering["response"], status="UNKNOWN", verification="NOT_JUDGED")


def chat(key, content=QUESTION):
    return TestClient(app).post("/chat", headers={"X-API-Key": key},
                                json={"messages": [{"role": "user", "content": content}]})


def agent(key, task="calculate 2 + 2"):
    return TestClient(app).post("/agent-run", headers={"X-API-Key": key}, json={"task": task})


def records(tenant, *types):
    return [r for r in pb.load_chain(tenant) if r["record_type"] in (types or ("igor.shadow", "igor.ambient"))]


def payload(rec):
    return json.loads(rec["payload_json"])


def qualified(env, tmp_path):
    require_qualification(env, write_qualification(tmp_path, k=0, n=26))


def judge_calls(fake):
    return fake.calls.get("igor-test", 0)


# ------------------------------------------------------------------ off (default)
def test_off_is_the_default_and_does_nothing(env, fake, answering):
    tenant, key = make_tenant()
    r = chat(key)
    assert r.status_code == 200 and r.json() == unjudged(answering)
    assert judge_calls(fake) == 0 and records(tenant) == []


def test_explicit_off_does_nothing(env, fake, answering):
    env.setenv("OLA_AMBIENT_IGOR", "off")
    tenant, key = make_tenant()
    assert chat(key).json() == unjudged(answering)
    assert judge_calls(fake) == 0 and records(tenant) == []


@pytest.mark.parametrize("value", ["on", "true", "1", "shadow2", "enforced", "block"])
def test_an_unknown_mode_is_a_503_and_never_silently_off(env, fake, answering, value):
    env.setenv("OLA_AMBIENT_IGOR", value)
    tenant, key = make_tenant()
    for call in (chat, agent):
        r = call(key)
        assert r.status_code == 503 and "OLA_AMBIENT_IGOR" in r.json()["detail"], r.text
    assert answering["calls"] == 0 and judge_calls(fake) == 0, "no model may be called under a bad setting"
    assert records(tenant) == []


# ------------------------------------------------------------------ shadow
def test_shadow_records_a_verdict_and_leaves_the_response_untouched(env, fake, answering):
    env.setenv("OLA_AMBIENT_IGOR", "shadow")
    tenant, key = make_tenant()
    r = chat(key)
    assert r.status_code == 200 and r.json() == unjudged(answering), "shadow must not change the answer, and must not call it VERIFIED"
    (rec,) = records(tenant)
    p = payload(rec)
    assert rec["record_type"] == "igor.shadow" and p["mode"] == "shadow" and p["surface"] == "chat"
    assert p["verdict"] == "ACCEPT" and p["enforced"] is False and p["quality_score"] == 92
    assert p["judge"]["model"] == "igor-test" and p["judge"]["runtime_kind"] == "OLLAMA_OBSERVED"
    assert p["judge"]["model_digest"], "the judge's digest is part of the evidence"
    assert judge_calls(fake) == 1
    ok, why = verify_chain(pb.load_chain(tenant))
    assert ok, why


def test_shadow_records_digests_never_the_text(env, fake, answering):
    env.setenv("OLA_AMBIENT_IGOR", "shadow")
    tenant, key = make_tenant()
    chat(key)
    raw = records(tenant)[0]["payload_json"]
    assert QUESTION not in raw and ANSWER not in raw and "Paris" not in raw
    import hashlib
    assert payload(records(tenant)[0])["output_digest"] == hashlib.sha256(ANSWER.encode()).hexdigest()
    assert payload(records(tenant)[0])["task_digest"] == hashlib.sha256(QUESTION.encode()).hexdigest()


def test_the_judge_actually_sees_the_task_and_the_answer(env, fake, answering):
    env.setenv("OLA_AMBIENT_IGOR", "shadow")
    _, key = make_tenant()
    chat(key)
    sent = json.dumps(fake.messages["igor-test"])
    assert QUESTION in sent and ANSWER in sent


def test_shadow_never_blocks_even_when_the_judge_rejects(env, fake, answering):
    env.setenv("OLA_AMBIENT_IGOR", "shadow")
    fake.script("igor-test", igor_json("BLOCK", 10, corrections=["wrong"]))
    tenant, key = make_tenant()
    r = chat(key)
    assert r.json() == unjudged(answering)
    assert payload(records(tenant)[0])["verdict"] == "REJECT"


def test_shadow_survives_an_unreachable_judge_and_says_so_in_evidence(env, fake, answering):
    env.setenv("OLA_AMBIENT_IGOR", "shadow")
    env.setenv("OLA_NINA_BASE_URL", "http://127.0.0.1:1")
    tenant, key = make_tenant()
    r = chat(key)
    assert r.status_code == 200 and r.json() == unjudged(answering)
    p = payload(records(tenant)[0])
    assert p["verdict"] == "NO_VERDICT" and p["detail"], p


def test_shadow_with_an_unusable_judge_config_records_ERROR_instead_of_hiding_it(env, fake, answering):
    env.setenv("OLA_AMBIENT_IGOR", "shadow")
    env.delenv("OLA_IGOR_MODEL")
    tenant, key = make_tenant()
    r = chat(key)
    assert r.status_code == 200 and r.json() == unjudged(answering)
    p = payload(records(tenant)[0])
    assert p["verdict"] == "ERROR" and "OLA_IGOR_MODEL" in p["detail"]


def test_shadow_unparsable_judge_output_is_no_verdict_not_accept(env, fake, answering):
    env.setenv("OLA_AMBIENT_IGOR", "shadow")
    fake.script("igor-test", "PASS, looks fine")
    tenant, key = make_tenant()
    chat(key)
    assert payload(records(tenant)[0])["verdict"] == "NO_VERDICT"


@pytest.mark.parametrize("upstream", [
    {"status": "BLOCK", "reason": "OPENAI_API_KEY is not configured"},
    # the real upstream shape when the key is missing: BLOCK *with* a message text
    {"status": "BLOCK", "reason": "OPENAI_API_KEY is not configured", "message": "NINA conversational LLM access is not configured yet."},
])
def test_nothing_is_judged_when_the_upstream_answer_is_not_VERIFIED(env, fake, answering, upstream):
    env.setenv("OLA_AMBIENT_IGOR", "shadow")
    answering["response"] = upstream
    tenant, key = make_tenant()
    assert chat(key).json() == answering["response"]
    assert judge_calls(fake) == 0 and records(tenant) == []


def test_shadow_on_agent_run(env, fake, answering):
    env.setenv("OLA_AMBIENT_IGOR", "shadow")
    tenant, key = make_tenant()
    r = agent(key)
    assert r.status_code == 200 and r.json()["status"] == "VERIFIED"
    p = payload(records(tenant)[0])
    assert p["surface"] == "agent-run" and p["verdict"] == "ACCEPT"
    ok, why = verify_chain(pb.load_chain(tenant))
    assert ok, why


def test_shadow_too_long_is_recorded_and_not_judged(env, fake, answering):
    env.setenv("OLA_AMBIENT_IGOR", "shadow")
    env.setenv("OLA_AMBIENT_MAX_CHARS", "20")
    tenant, key = make_tenant()
    chat(key)
    assert payload(records(tenant)[0])["verdict"] == "TOO_LONG" and judge_calls(fake) == 0


# ------------------------------------------------------------------ enforce
def test_enforce_without_a_qualification_is_a_503_before_any_model_is_called(env, fake, answering):
    env.setenv("OLA_AMBIENT_IGOR", "enforce")
    tenant, key = make_tenant()
    r = chat(key)
    assert r.status_code == 503 and "qualification" in r.json()["detail"], r.text
    assert answering["calls"] == 0 and judge_calls(fake) == 0 and records(tenant) == []


def test_enforce_without_a_judge_model_is_a_503(env, fake, answering, tmp_path):
    env.setenv("OLA_AMBIENT_IGOR", "enforce")
    qualified(env, tmp_path)
    env.delenv("OLA_IGOR_MODEL")
    _, key = make_tenant()
    r = chat(key)
    assert r.status_code == 503 and "OLA_IGOR_MODEL" in r.json()["detail"]
    assert answering["calls"] == 0


def test_enforce_with_a_bad_qualification_pin_is_a_503(env, fake, answering, tmp_path):
    env.setenv("OLA_AMBIENT_IGOR", "enforce")
    require_qualification(env, write_qualification(tmp_path), pin="not-a-sha")
    _, key = make_tenant()
    assert chat(key).status_code == 503 and answering["calls"] == 0


def test_enforce_passes_an_accepted_answer_from_a_qualified_judge(env, fake, answering, tmp_path):
    env.setenv("OLA_AMBIENT_IGOR", "enforce")
    qualified(env, tmp_path)
    tenant, key = make_tenant()
    r = chat(key)
    assert r.status_code == 200
    assert r.json() == dict(answering["response"], verification="INDEPENDENT_JUDGE_ACCEPTED")
    (rec,) = records(tenant)
    p = payload(rec)
    assert rec["record_type"] == "igor.ambient" and p["allowed"] is True and p["enforced"] is True
    assert p["qualification"]["state"] == "QUALIFIED" and p["verdict"] == "ACCEPT"
    assert str(tmp_path) not in rec["payload_json"], "the server path of the qualification file must not leak"


def test_enforce_withholds_a_rejected_answer(env, fake, answering, tmp_path):
    env.setenv("OLA_AMBIENT_IGOR", "enforce")
    qualified(env, tmp_path)
    fake.script("igor-test", igor_json("BLOCK", 20, corrections=["wrong"]))
    tenant, key = make_tenant()
    r = chat(key)
    b = r.json()
    assert r.status_code == 200 and b["status"] == "BLOCK" and b["ambient"]["verdict"] == "REJECT", b
    assert "message" not in b and ANSWER not in r.text, "the withheld answer must not be echoed"
    assert "IGOR" in b["reason"]
    p = payload(records(tenant)[0])
    assert p["allowed"] is False and b["ambient"]["evidence_seq"] == records(tenant)[0]["seq"]


def test_enforce_low_score_is_rejected_even_when_the_judge_says_PASS(env, fake, answering, tmp_path):
    env.setenv("OLA_AMBIENT_IGOR", "enforce")
    qualified(env, tmp_path)
    fake.script("igor-test", igor_json("PASS", 40))
    _, key = make_tenant()
    assert chat(key).json()["status"] == "BLOCK"


def test_enforce_open_corrections_are_rejected_even_when_the_judge_says_PASS(env, fake, answering, tmp_path):
    env.setenv("OLA_AMBIENT_IGOR", "enforce")
    qualified(env, tmp_path)
    fake.script("igor-test", igor_json("PASS", 95, corrections=["fix the date"]))
    _, key = make_tenant()
    assert chat(key).json()["status"] == "BLOCK"


def test_enforce_no_usable_verdict_is_BLOCK(env, fake, answering, tmp_path):
    env.setenv("OLA_AMBIENT_IGOR", "enforce")
    qualified(env, tmp_path)
    fake.script("igor-test", "not json at all")
    tenant, key = make_tenant()
    b = chat(key).json()
    assert b["status"] == "BLOCK" and b["ambient"]["verdict"] == "NO_VERDICT", b
    assert payload(records(tenant)[0])["allowed"] is False


def test_enforce_unreachable_judge_is_BLOCK_and_still_evidence(env, fake, answering, tmp_path):
    env.setenv("OLA_AMBIENT_IGOR", "enforce")
    qualified(env, tmp_path)
    env.setenv("OLA_NINA_BASE_URL", "http://127.0.0.1:1")
    tenant, key = make_tenant()
    b = chat(key).json()
    assert b["status"] == "BLOCK" and b["ambient"]["verdict"] == "NO_VERDICT", b
    assert len(records(tenant)) == 1


@pytest.mark.parametrize("k,n", [(10, 26), (3, 40), (0, 5)])
def test_enforce_an_unqualified_judge_blocks_even_a_PASS(env, fake, answering, tmp_path, k, n):
    env.setenv("OLA_AMBIENT_IGOR", "enforce")
    require_qualification(env, write_qualification(tmp_path, k=k, n=n))
    tenant, key = make_tenant()
    b = chat(key).json()
    assert b["status"] == "BLOCK" and b["ambient"]["verdict"] == "UNQUALIFIED", b
    assert payload(records(tenant)[0])["qualification"]["state"] == "NOT_QUALIFIED"


def test_enforce_a_judge_with_another_digest_is_not_qualified(env, fake, answering, tmp_path):
    env.setenv("OLA_AMBIENT_IGOR", "enforce")
    qualified(env, tmp_path)
    fake.add_model("igor-test", digest="0" * 64)           # the model behind the name changed after the measurement
    _, key = make_tenant()
    assert chat(key).json()["ambient"]["verdict"] == "UNQUALIFIED"


def test_enforce_rejects_a_test_double_runtime(env, fake, answering, tmp_path):
    env.setenv("OLA_AMBIENT_IGOR", "enforce")
    qualified(env, tmp_path)
    fake.version = "0.0.0-test-double"
    _, key = make_tenant()
    b = chat(key).json()
    assert b["status"] == "BLOCK" and b["ambient"]["verdict"] == "UNQUALIFIED", b


def test_enforce_the_model_that_wrote_the_answer_cannot_judge_it(env, fake, answering, tmp_path):
    env.setenv("OLA_AMBIENT_IGOR", "enforce")
    qualified(env, tmp_path)
    answering["response"]["model"] = "igor-test"
    _, key = make_tenant()
    assert chat(key).json()["ambient"]["verdict"] == "SELF_JUDGE"
    env.setenv("OLA_ALLOW_SAME_MODEL_IGOR", "1")           # explicit, visible opt-in
    assert chat(key).json()["status"] == "VERIFIED"


@pytest.mark.parametrize("spelling", ["IGOR-TEST", "  igor-test  ", "igor-test:latest", "Igor-Test:LATEST"])
def test_enforce_the_same_model_under_another_spelling_is_still_the_same_model(env, fake, answering, tmp_path, spelling):
    """The producer name arrives as the model reported by the answering service. A plain string comparison made
    "IGOR-TEST" or "igor-test:latest" an independent judge of "igor-test" - which the verifier (one definition of the same
    model) does not accept."""
    env.setenv("OLA_AMBIENT_IGOR", "enforce")
    qualified(env, tmp_path)
    answering["response"]["model"] = spelling
    _, key = make_tenant()
    assert chat(key).json()["ambient"]["verdict"] == "SELF_JUDGE"


@pytest.mark.parametrize("other", ["igor-test:2b", "igor-test-2", "igor", "", None])
def test_enforce_a_differently_named_model_is_not_a_self_judge(env, fake, answering, tmp_path, other):
    env.setenv("OLA_AMBIENT_IGOR", "enforce")
    qualified(env, tmp_path)
    answering["response"]["model"] = other
    _, key = make_tenant()
    b = chat(key).json()
    assert b["status"] == "VERIFIED" and "ambient" not in b, b                 # an accepted answer carries no ambient block


def test_enforce_too_long_is_BLOCK_without_calling_the_judge(env, fake, answering, tmp_path):
    env.setenv("OLA_AMBIENT_IGOR", "enforce")
    env.setenv("OLA_AMBIENT_MAX_CHARS", "20")
    qualified(env, tmp_path)
    _, key = make_tenant()
    assert chat(key).json()["ambient"]["verdict"] == "TOO_LONG" and judge_calls(fake) == 0


def test_enforce_can_only_downgrade_never_promote(env, fake, answering, tmp_path):
    env.setenv("OLA_AMBIENT_IGOR", "enforce")
    qualified(env, tmp_path)
    answering["response"] = {"status": "BLOCK", "reason": "LLM request failed: URLError"}
    tenant, key = make_tenant()
    assert chat(key).json() == answering["response"]
    assert judge_calls(fake) == 0 and records(tenant) == []


def test_enforce_busy_judge_sheds_load_with_429(env, fake, answering, tmp_path):
    env.setenv("OLA_AMBIENT_IGOR", "enforce")
    env.setenv("OLA_PIPELINE_MAX_CONCURRENCY", "1")
    qualified(env, tmp_path)
    _, key = make_tenant()
    with pb._active_lock:
        pb._active_runs += 1
    try:
        r = chat(key)
    finally:
        with pb._active_lock:
            pb._active_runs -= 1
    assert r.status_code == 429 and judge_calls(fake) == 0


def test_enforce_on_agent_run_accept_and_reject(env, fake, answering, tmp_path):
    env.setenv("OLA_AMBIENT_IGOR", "enforce")
    qualified(env, tmp_path)
    tenant, key = make_tenant()
    ok = agent(key)
    assert ok.status_code == 200 and ok.json()["status"] == "VERIFIED" and "execution" in ok.json()
    fake.script("igor-test", igor_json("BLOCK", 5, corrections=["wrong"]))
    bad = agent(key).json()
    assert bad["status"] == "BLOCK" and "execution" not in bad and bad["ambient"]["verdict"] == "REJECT", bad
    assert [payload(r)["allowed"] for r in records(tenant)] == [True, False]


def test_a_failed_evidence_write_blocks_in_enforce(env, fake, answering, tmp_path):
    env.setenv("OLA_AMBIENT_IGOR", "enforce")
    qualified(env, tmp_path)

    def boom(*a, **k):
        raise RuntimeError("disk full")

    env.setattr(pb, "append_evidence", boom)
    _, key = make_tenant()
    b = chat(key).json()
    assert b["status"] == "BLOCK" and b["ambient"]["verdict"] == "ERROR" and ANSWER not in json.dumps(b), b


# ------------------------------------------------------------------ cross-cutting
def test_records_are_tenant_scoped_and_the_chain_stays_valid(env, fake, answering, tmp_path):
    env.setenv("OLA_AMBIENT_IGOR", "shadow")
    t1, k1 = make_tenant()
    t2, k2 = make_tenant()
    chat(k1)
    chat(k1)
    chat(k2)
    assert len(records(t1)) == 2 and len(records(t2)) == 1
    for t in (t1, t2):
        ok, why = verify_chain(pb.load_chain(t))
        assert ok, why


def test_the_acceptance_rule_equals_scripts_judge_eval_classify():
    spec = importlib.util.spec_from_file_location("judge_eval", Path(__file__).resolve().parents[1] / "scripts" / "judge_eval.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["judge_eval"] = mod
    spec.loader.exec_module(mod)
    samples = [igor_json("PASS", 92), igor_json("PASS", 69), igor_json("PASS", 70), igor_json("PASS", 95, corrections=["x"]),
               igor_json("BLOCK", 99), igor_json("REVIEW", 80), "", "nope", "{}", "[]", '{"decision": "PASS"}']
    for text in samples:
        assert ambient.decide(text, 70)[0] == mod.classify(text, 70)[0], text


def test_names_nina_and_igor_are_preserved_in_the_record_types():
    assert ambient.SHADOW_TYPE == "igor.shadow" and ambient.ENFORCE_TYPE == "igor.ambient"
