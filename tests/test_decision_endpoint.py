"""/decision-evaluate: off by default, bounded, advisory, recorded as evidence. And the hardened Jev contract."""
import hashlib
import math
import uuid

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app import pipeline_bridge as pb
from app.database import SessionLocal
from app.decision_fabric import DecisionFabric, DecisionPolicy, JevProvider
from app.hashchain import verify_chain
from app.main import app
from app.models import ApiKey, Tenant

client = TestClient(app)

QUESTIONS = {"route": {"type": "choice", "instructions": "route?", "criteria": {"allow": "a", "review": "r"}},
             "needs_human": {"type": "noul", "instructions": "human?"}}


def good_body(**over):
    ans = {"route": {"type": "choice", "choice": "review", "probabilities": {"allow": 0.1, "review": 0.9}, "confidence": 0.9},
           "needs_human": {"type": "noul", "noul": 0.9}}
    ans.update(over)
    return {"model": "jev-1.13.0", "answers": ans, "usage": {"input_tokens": 5, "output_tokens": 1}}


class Fake:
    name = "fake"

    def __init__(self, body=None, exc=None):
        self.body, self.exc, self.calls = body if body is not None else good_body(), exc, 0

    def evaluate(self, *, state, questions, model):
        self.calls += 1
        if self.exc:
            raise self.exc
        return {"body": self.body, "request_id": "r1"}


def tenant():
    tid, key = str(uuid.uuid4()), "jv-" + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(Tenant(id=tid, name="jv"))
        db.add(ApiKey(id=str(uuid.uuid4()), tenant_id=tid, key_hash=hashlib.sha256(key.encode()).hexdigest()))
        db.commit()
    return tid, key


def types(tid):
    return [r["record_type"] for r in pb.load_chain(tid)]


def post(key, **kw):
    return client.post("/decision-evaluate", json={"state": {"facts": ["x"]}, "questions": QUESTIONS, **kw},
                       headers={"x-api-key": key})


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.delenv("OLA_JEV", raising=False)
    monkeypatch.delenv("OLA_PIPELINE_MAX_CONCURRENCY", raising=False)


def use(monkeypatch, provider):
    monkeypatch.setattr(main, "DecisionFabric", lambda: DecisionFabric(provider))
    return provider


def test_off_by_default_and_never_calls_the_provider(monkeypatch):
    p = use(monkeypatch, Fake())
    _, key = tenant()
    r = post(key)
    assert r.status_code == 503 and "third-party" in r.json()["detail"]
    monkeypatch.setenv("OLA_JEV", "off")
    assert post(key).status_code == 503
    assert p.calls == 0


def test_invalid_mode_is_an_error_not_on(monkeypatch):
    p = use(monkeypatch, Fake())
    _, key = tenant()
    monkeypatch.setenv("OLA_JEV", "yes")
    r = post(key)
    assert r.status_code == 503 and p.calls == 0 and "OLA_JEV must be" in r.json()["detail"]


def test_requires_api_key(monkeypatch):
    monkeypatch.setenv("OLA_JEV", "on")
    use(monkeypatch, Fake())
    assert client.post("/decision-evaluate", json={"state": "x", "questions": QUESTIONS}).status_code in (401, 403, 422)


def test_on_returns_advisory_and_records_chained_evidence(monkeypatch):
    monkeypatch.setenv("OLA_JEV", "on")
    use(monkeypatch, Fake())
    tid, key = tenant()
    r = post(key)
    assert r.status_code == 200
    d = r.json()
    assert d["advisory_only"] is True and d["status"] == "READY" and d["classifications"] == {"route": "ACCEPT", "needs_human": "YES"}
    assert "VERIFIED" not in str(d).upper().replace("VERIFIED_", "")
    assert types(tid) == ["decision.fabric"]
    ok, _ = verify_chain(pb.load_chain(tid))
    assert ok is True


def test_contract_failure_is_recorded_as_blocked_not_as_an_answer(monkeypatch):
    monkeypatch.setenv("OLA_JEV", "on")
    use(monkeypatch, Fake(exc=RuntimeError("boom")))
    tid, key = tenant()
    d = post(key).json()
    assert d["status"] == "BLOCK" and d["answers"] == {} and d["classifications"] == {}
    assert types(tid) == ["decision.fabric_blocked"]


def test_busy_returns_429_with_retry_after_and_does_not_call_the_provider(monkeypatch):
    monkeypatch.setenv("OLA_JEV", "on")
    monkeypatch.setenv("OLA_PIPELINE_MAX_CONCURRENCY", "1")
    p = use(monkeypatch, Fake())
    _, key = tenant()
    with pb._run_slot():
        r = post(key)
    assert r.status_code == 429 and r.headers["retry-after"] == "5" and p.calls == 0
    assert post(key).status_code == 200            # slot was released


def test_invalid_concurrency_config_is_503(monkeypatch):
    monkeypatch.setenv("OLA_JEV", "on")
    monkeypatch.setenv("OLA_PIPELINE_MAX_CONCURRENCY", "0")
    p = use(monkeypatch, Fake())
    _, key = tenant()
    assert post(key).status_code == 503 and p.calls == 0


def test_bad_bodies_are_400(monkeypatch):
    monkeypatch.setenv("OLA_JEV", "on")
    use(monkeypatch, Fake())
    _, key = tenant()
    h = {"x-api-key": key}
    assert client.post("/decision-evaluate", json={"questions": QUESTIONS}, headers=h).status_code == 400
    assert client.post("/decision-evaluate", json={"state": "x", "questions": {}}, headers=h).status_code == 400


def test_tenants_are_isolated(monkeypatch):
    monkeypatch.setenv("OLA_JEV", "on")
    use(monkeypatch, Fake())
    t1, k1 = tenant()
    t2, _ = tenant()
    post(k1)
    assert types(t1) == ["decision.fabric"] and types(t2) == []


# ---- contract hardening -------------------------------------------------------------------------------------

def run_contract(body):
    return DecisionFabric(Fake(body)).evaluate(state={"a": 1}, questions=QUESTIONS)


@pytest.mark.parametrize("mutate", [
    lambda a: a["route"].update(confidence=True),
    lambda a: a["route"].update(confidence=float("nan")),
    lambda a: a["route"].update(confidence=1.5),
    lambda a: a["route"].update(probabilities={"allow": 0.9, "review": 0.9}),
    lambda a: a["route"].update(probabilities={"allow": -0.1, "review": 1.1}),
    lambda a: a["route"].update(probabilities={"allow": True, "review": 0}),
    lambda a: a["route"].update(choice="block"),
    lambda a: a["needs_human"].update(noul=True),
    lambda a: a["needs_human"].update(noul=2),
    lambda a: a["needs_human"].update(noul=float("inf")),
    lambda a: a.pop("needs_human"),
    lambda a: a.update(extra={"type": "noul", "noul": 0.5}),
])
def test_malformed_answers_are_blocked(mutate):
    body = good_body()
    mutate(body["answers"])
    r = run_contract(body)
    assert r.status == "BLOCK" and r.answers == {}


def test_valid_body_is_ready():
    assert run_contract(good_body()).status == "READY"


def test_probability_sum_tolerance_edges():
    ok = good_body(route={"type": "choice", "choice": "review", "probabilities": {"allow": 0.11, "review": 0.90}, "confidence": 0.9})
    bad = good_body(route={"type": "choice", "choice": "review", "probabilities": {"allow": 0.15, "review": 0.90}, "confidence": 0.9})
    assert run_contract(ok).status == "READY" and run_contract(bad).status == "BLOCK"


def test_size_limits_are_enforced_before_the_provider_is_called():
    p = Fake()
    f = DecisionFabric(p)
    assert f.evaluate(state="x" * 70000, questions=QUESTIONS).status == "BLOCK"
    many = {f"q{i}": {"type": "noul", "instructions": "x"} for i in range(33)}
    assert f.evaluate(state="x", questions=many).status == "BLOCK"
    assert f.evaluate(state="x", questions={"n" * 65: {"type": "noul", "instructions": "x"}}).status == "BLOCK"
    assert p.calls == 0
    edge = {f"q{i}": {"type": "noul", "instructions": "x"} for i in range(32)}
    f.evaluate(state="x", questions=edge)
    assert p.calls == 1                               # 32 questions and a 64-char name are within the limit
    f.evaluate(state="x", questions={"n" * 64: {"type": "noul", "instructions": "x"}})
    assert p.calls == 2


def test_policy_blocks_invalid_confidence_instead_of_accepting():
    pol = DecisionPolicy()
    assert pol.classify({"type": "choice", "confidence": True}) == "BLOCK"
    assert pol.classify({"type": "choice", "confidence": float("nan")}) == "BLOCK"
    assert pol.classify({"type": "noul", "noul": "0.9"}) == "BLOCK"
    assert pol.classify({"type": "choice", "confidence": 0.69}) == "REVIEW"
    assert pol.classify({"type": "choice", "confidence": 0.70}) == "ACCEPT"
    assert pol.classify({"type": "noul", "noul": 0.5}) == "REVIEW"


def test_oversized_provider_response_is_rejected():
    import httpx
    big = httpx.Response(200, content=b'{"x":"' + b"a" * (1024 * 1024) + b'"}',
                         request=httpx.Request("POST", "https://api.typesafe.ai/v1/systemone"))
    class C:
        def post(self, *a, **k): return big
    with pytest.raises(ValueError):
        JevProvider(api_key="k", client=C()).evaluate(state="s", questions=QUESTIONS, model="m")


def test_provider_without_key_raises_and_fabric_blocks(monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    r = DecisionFabric(JevProvider()).evaluate(state="s", questions=QUESTIONS)
    assert r.status == "BLOCK"
