"""Pipeline bridge: ola_pipeline sessions anchored in the OLA tenant evidence chain.

Runs against a TEST DOUBLE of the Ollama HTTP API (protocol + gate logic only). Real-runtime evidence
comes from tests/test_pipeline_bridge_live.py, which is SKIPPED (= UNKNOWN) without a live Ollama.
`fake.version = "0.99.0"` makes the double look like a non-declared endpoint so the pipeline records
OLLAMA_OBSERVED - this exercises the VERIFIED branch of the logic, it is not runtime proof.
"""
import hashlib
import json
import os
import shutil
import sys
import threading
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent / "pipeline_suite"))
from fake_ollama import FakeOllama  # noqa: E402
from pipeline_helpers import igor_json  # noqa: E402

from app import pipeline_bridge as pb  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.hashchain import verify_chain  # noqa: E402
from app.main import app  # noqa: E402
from app.models import ApiKey, Tenant  # noqa: E402
from app.human_gate import ReviewDecision  # noqa: E402
from ola_pipeline import Pipeline, attest  # noqa: E402
from ola_pipeline.config import DEFAULT_REQUIREMENTS  # noqa: E402
from ola_pipeline.igor import judge_prompt_fingerprint  # noqa: E402

TASK = "State the capital of France in one sentence."
HUMAN = {"human_approved": True, "human_actor": "reviewer-1", "human_reason": "checked"}


@pytest.fixture
def fake():
    f = FakeOllama().start()
    f.add_model("nina-test")
    f.add_model("igor-test")
    f.version = "0.99.0"                       # non-declared endpoint -> OLLAMA_OBSERVED (logic only)
    f.script("nina-test", "Paris is the capital of France.")
    f.script("igor-test", igor_json("PASS", 92))
    yield f
    f.stop()


@pytest.fixture
def env(monkeypatch, tmp_path, fake):
    for k in list(os.environ):
        if k.startswith("OLA_") and k not in ("OLA_EG_DB_PATH", "OLA_RUNTIME_COMMIT"):
            monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("OLA_PIPELINE_VAULT_DIR", str(tmp_path / "vaults"))
    monkeypatch.setenv("OLA_NINA_PROVIDER", "ollama-local")
    monkeypatch.setenv("OLA_NINA_MODEL", "nina-test")
    monkeypatch.setenv("OLA_NINA_BASE_URL", fake.url)
    monkeypatch.setenv("OLA_IGOR_MODEL", "igor-test")
    monkeypatch.setenv("OLA_NINA_TIMEOUT_S", "10")
    monkeypatch.setenv("OLA_IGOR_TIMEOUT_S", "10")
    return monkeypatch


def make_tenant():
    tenant_id, key = str(uuid.uuid4()), "pb-" + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="pb"))
        db.add(ApiKey(id=str(uuid.uuid4()), tenant_id=tenant_id, key_hash=hashlib.sha256(key.encode()).hexdigest()))
        db.commit()
    return tenant_id, key


def post(key, **body):
    body.setdefault("task", TASK)
    return TestClient(app).post("/pipeline-run", headers={"X-API-Key": key}, json=body)


def anchors(tenant_id):
    return [r for r in pb.load_chain(tenant_id) if r["record_type"] == pb.ANCHOR_TYPE]


def session_dir(env, tenant_id, session_id):
    return Path(os.environ["OLA_PIPELINE_VAULT_DIR"]) / tenant_id / session_id


# ------------------------------------------------------------------ happy path
def test_full_chain_is_verified_and_anchored(env, fake):
    tenant, key = make_tenant()
    r = post(key, **HUMAN)
    assert r.status_code == 200, r.text
    b = r.json()
    assert b["nina"]["status"] == "VERIFIED" and b["igor"]["status"] == "VERIFIED", b
    assert b["human_gate"]["status"] == "VERIFIED" and b["status"] == "VERIFIED"
    assert b["pipeline"]["status"] == "ANCHORED" and b["pipeline"]["verifier_overall"] == "VERIFIED"
    assert b["replay_verification"]["status"] == "VERIFIED" and len(b["replay"]) == 3   # nina + igor + canary
    assert b["decision_report"]["policy"]["status"] == "VERIFIED"
    assert len(anchors(tenant)) == 1
    ok, why = verify_chain(pb.load_chain(tenant))
    assert ok, why
    assert str(os.environ["OLA_PIPELINE_VAULT_DIR"]) not in json.dumps(b)           # no server paths leak


def test_human_approval_is_required_even_when_everything_verifies(env):
    _, key = make_tenant()
    b = post(key).json()                                  # no human_* fields
    assert b["igor"]["status"] == "VERIFIED" and b["status"] == "BLOCK", b
    b = post(key, human_approved=False, human_actor="r", human_reason="no").json()
    assert b["status"] == "BLOCK"


def test_review_required_maps_to_unknown_and_never_verifies(env, fake):
    fake.canary_mode = "accept"                           # judge accepts a known-wrong answer
    tenant, key = make_tenant()
    b = post(key, **HUMAN).json()
    assert b["igor"]["pipeline_igor_status"] != "VERIFIED"
    assert b["igor"]["gate_state"] == "REVIEW_REQUIRED" and b["igor"]["status"] == "UNKNOWN", b
    assert b["status"] == "BLOCK" and "UNKNOWN" in b["human_gate"]["reason"], b       # human cannot promote UNKNOWN
    assert len(anchors(tenant)) == 1                       # the refusal is itself evidence


# ------------------------------------------------------------------ fail closed
def test_unreachable_ollama_fails_closed_but_is_still_evidence(env):
    env.setenv("OLA_NINA_BASE_URL", "http://127.0.0.1:1")
    tenant, key = make_tenant()
    b = post(key, **HUMAN).json()
    assert b["status"] == "BLOCK" and b["igor"]["status"] == "BLOCK", b
    assert b["nina"]["status"] != "VERIFIED"
    assert len(anchors(tenant)) == 1


def test_unknown_model_config_is_blocked_not_defaulted(env, fake):
    env.delenv("OLA_NINA_MODEL")                          # no hardcoded model anywhere
    _, key = make_tenant()
    b = post(key, **HUMAN).json()
    assert b["status"] == "BLOCK" and b["nina"]["status"] != "VERIFIED", b
    assert fake.calls.get("nina-test", 0) == 0


def test_unknown_tool_blocks_before_any_model_call(env, fake):
    tenant, key = make_tenant()
    b = post(key, requested_tools=["rm_rf"], **HUMAN).json()
    assert b["status"] == "BLOCK" and b["nina"]["status"] == "BLOCK" and b["pipeline"]["status"] == "NOT_CREATED"
    assert fake.requests == [] and anchors(tenant) == []


def test_bad_inputs(env):
    _, key = make_tenant()
    assert post(key, task="  ").status_code == 400
    assert post(key, requested_tools="x").status_code == 400
    assert TestClient(app).post("/pipeline-run", json={"task": TASK}).status_code == 401


def test_malformed_pin_is_an_error_not_a_silent_downgrade(env, fake):
    env.setenv("OLA_PIPELINE_TRUSTED_KEY", "not-a-key")
    _, key = make_tenant()
    r = post(key, **HUMAN)
    assert r.status_code == 503 and fake.requests == []   # refused before talking to any model


def test_bad_numeric_config_is_503(env):
    env.setenv("OLA_NINA_TIMEOUT_S", "soon")
    _, key = make_tenant()
    assert post(key, **HUMAN).status_code == 503


# ------------------------------------------------------------------ anchoring detects what the vault cannot
def test_consistent_rewrite_of_a_session_is_caught_by_the_anchor(env, fake, tmp_path):
    """The attacker regenerates the WHOLE session under the same session_id (fresh, internally
    consistent envelopes/artifacts/final). The standalone verifier cannot object - nothing inside the
    directory is inconsistent - but the anchor in the tenant chain records what was really produced."""
    from ola_pipeline import Pipeline
    from ola_pipeline import pipeline as pipeline_mod
    import secrets as real_secrets

    tenant, key = make_tenant()
    a = post(key, **HUMAN).json()
    sid = a["session_id"]

    class Fixed:                                           # reuse A's session id, everything else stays random
        @staticmethod
        def token_hex(n):
            return sid[len("ses_"):] if n == 12 else real_secrets.token_hex(n)

    env.setattr(pipeline_mod, "secrets", Fixed)
    fake.script("nina-test", "Lyon is the capital of France.")
    forged = Pipeline(pb.build_config(tenant, base=tmp_path / "forge")).run(TASK)     # no anchor: attacker's copy
    assert forged.session_dir.name == sid
    env.setattr(pipeline_mod, "secrets", real_secrets)          # only the id shim is reverted

    sd = session_dir(env, tenant, sid)
    for q in list(sd.rglob("*")):
        os.chmod(q, 0o755 if q.is_dir() else 0o644)
    os.chmod(sd, 0o755)
    shutil.rmtree(sd)
    shutil.copytree(forged.session_dir, sd)

    v = pb.verify_anchor(tenant, sid, base=tmp_path / "vaults")
    assert v["verifier"]["overall"] == "VERIFIED", v["verifier"]       # invisible to the vault alone
    assert v["status"] == "BLOCK" and "changed after anchoring" in v["reason"], v
    assert not v["checks"]["chain_head_matches_anchor"] and not v["checks"]["final_matches_anchor"]


def test_interior_envelope_edit_is_reported_as_a_change_after_anchoring(env):
    """chain_head (the LAST envelope's hash) is untouched by an edit to an interior envelope, so only the
    anchored envelope summary pinpoints it - on top of the standalone verifier failing."""
    tenant, key = make_tenant()
    a = post(key, **HUMAN).json()
    sd = session_dir(env, tenant, a["session_id"])
    first = sorted((sd / "envelopes").glob("*.json"))[0]
    doc = json.loads(first.read_text())
    doc["output_hash"] = "0" * 64
    os.chmod(first, 0o644)
    first.write_text(json.dumps(doc))
    v = pb.verify_anchor(tenant, a["session_id"])
    assert v["verifier"]["overall"] == "FAILED"
    assert v["status"] == "BLOCK" and "envelopes differ" in v["reason"], v
    assert v["checks"]["chain_head_matches_anchor"] is True and v["checks"]["envelopes_match_anchor"] is False


def test_tampered_artifact_blocks(env):
    tenant, key = make_tenant()
    a = post(key, **HUMAN).json()
    sd = session_dir(env, tenant, a["session_id"])
    victim = next((sd / "artifacts").iterdir())
    os.chmod(victim, 0o644)
    victim.write_bytes(victim.read_bytes() + b"x")
    assert pb.verify_anchor(tenant, a["session_id"])["status"] == "BLOCK"


def test_session_without_anchor_is_unknown(env):
    tenant, key = make_tenant()
    a = post(key, **HUMAN).json()
    other, _ = make_tenant()
    shutil.copytree(session_dir(env, tenant, a["session_id"]), session_dir(env, other, a["session_id"]))
    v = pb.verify_anchor(other, a["session_id"])
    assert v["status"] == "UNKNOWN" and "not anchored" in v["reason"]


def test_double_anchor_is_blocked(env):
    tenant, key = make_tenant()
    a = post(key, **HUMAN).json()
    pb.anchor_session(tenant, session_dir(env, tenant, a["session_id"]))
    v = pb.verify_anchor(tenant, a["session_id"])
    assert v["status"] == "BLOCK" and "more than once" in v["reason"]


def test_broken_tenant_chain_blocks(env, monkeypatch):
    tenant, key = make_tenant()
    a = post(key, **HUMAN).json()
    good = pb.load_chain(tenant)
    bad = [dict(r) for r in good]
    bad[-1]["payload_json"] = bad[-1]["payload_json"].replace("ANCHORED", "ANCHORED ")
    monkeypatch.setattr(pb, "load_chain", lambda t: bad)
    v = pb.verify_anchor(tenant, a["session_id"])
    assert v["status"] == "BLOCK" and "chain invalid" in v["reason"]


def test_reverification_later_matches_and_replays(env):
    tenant, key = make_tenant()
    a = post(key, **HUMAN).json()
    r = TestClient(app).get(f"/pipeline-session/{a['session_id']}", headers={"X-API-Key": key})
    body = r.json()
    assert r.status_code == 200 and body["verification"]["status"] == "VERIFIED"
    assert body["replay_verification"]["status"] == "VERIFIED" and body["replay"] == a["replay"]


# ------------------------------------------------------------------ isolation + input hardening
def test_other_tenant_gets_404_for_a_foreign_session(env):
    t1, k1 = make_tenant()
    _, k2 = make_tenant()
    a = post(k1, **HUMAN).json()
    r = TestClient(app).get(f"/pipeline-session/{a['session_id']}", headers={"X-API-Key": k2})
    assert r.status_code == 404


@pytest.mark.parametrize("bad", ["../etc", "a/b", "", "x" * 65, "..", "t\x00x", "t t"])
def test_path_traversal_in_tenant_id_is_rejected(bad):
    with pytest.raises(ValueError):
        pb.verify_anchor(bad, "ses_" + "0" * 24)
    with pytest.raises(ValueError):
        pb.append_evidence(bad, "x", {})


@pytest.mark.parametrize("bad", ["ses_../..", "ses_" + "0" * 23, "SES_" + "0" * 24, "ses_" + "g" * 24, "../ses_" + "0" * 24])
def test_bad_session_id_is_rejected_and_endpoint_hides_it(env, bad):
    tenant, key = make_tenant()
    with pytest.raises(ValueError):
        pb.verify_anchor(tenant, bad)
    r = TestClient(app).get("/pipeline-session/" + bad.replace("/", "%2F"), headers={"X-API-Key": key})
    assert r.status_code == 404


# ------------------------------------------------------------------ state mapping
@pytest.mark.parametrize("gate,overall,expected", [
    ("PASS", "VERIFIED", "VERIFIED"),
    ("PASS", "PARTIAL", "UNKNOWN"), ("PASS", "CONSISTENT", "UNKNOWN"), ("PASS", None, "UNKNOWN"),
    ("PASS", "FAILED", "BLOCK"),
    ("REVIEW_REQUIRED", "CONSISTENT", "UNKNOWN"), ("REVIEW_REQUIRED", "VERIFIED", "UNKNOWN"),
    ("REVIEW_REQUIRED", "FAILED", "BLOCK"),
    ("BLOCKED", "CONSISTENT", "BLOCK"), ("BLOCKED", "FAILED", "BLOCK"),
    ("ALLOW", "VERIFIED", "BLOCK"), ("", "VERIFIED", "BLOCK"), (None, None, "BLOCK"), ("pass", "VERIFIED", "BLOCK"),
    ("BLOCKED", "VERIFIED", "BLOCK"), ("PASS", "", "UNKNOWN"), ("PASS", "verified", "UNKNOWN"), (["PASS"], "VERIFIED", "BLOCK"),
])
def test_state_mapping_is_fail_closed(gate, overall, expected):
    assert pb.map_states(gate, overall)[0] == expected


# ------------------------------------------------------------------ signing + pinning
def _key(tmp_path, name="k"):
    info = attest.generate_keypair(tmp_path / name)
    return Path(info["private_key_file"]), info["public_key"]


def test_signed_session_with_pinned_key(env, tmp_path):
    keyfile, pub = _key(tmp_path)
    env.setenv("OLA_SIGNING_KEY_FILE", str(keyfile))
    env.setenv("OLA_PIPELINE_TRUSTED_KEY", pub)
    tenant, key = make_tenant()
    b = post(key, **HUMAN).json()
    assert b["status"] == "VERIFIED" and b["pipeline"]["signed"] is True
    assert b["pipeline"]["authenticity"] == "PINNED_VALID"
    assert json.loads(anchors(tenant)[0]["payload_json"])["key_id"]
    att = json.loads((session_dir(env, tenant, b["session_id"]) / "attestation.json").read_text())
    # requirements.txt pulls in `cryptography`: the server must not sign with the pure-Python fallback
    assert att["signer_impl"] == "cryptography"


def test_wrong_pin_blocks(env, tmp_path):
    keyfile, _ = _key(tmp_path, "a")
    _, other_pub = _key(tmp_path, "b")
    env.setenv("OLA_SIGNING_KEY_FILE", str(keyfile))
    env.setenv("OLA_PIPELINE_TRUSTED_KEY", other_pub)
    _, key = make_tenant()
    b = post(key, **HUMAN).json()
    assert b["status"] == "BLOCK" and b["igor"]["status"] == "BLOCK", b


def test_pin_without_signature_blocks(env, tmp_path):
    _, pub = _key(tmp_path)
    env.setenv("OLA_PIPELINE_TRUSTED_KEY", pub)           # a pin is configured, but nothing signs
    _, key = make_tenant()
    b = post(key, **HUMAN).json()
    assert b["status"] == "BLOCK" and b["igor"]["status"] == "BLOCK", b


def test_signing_failure_is_block_but_the_session_is_anchored(env, tmp_path):
    env.setenv("OLA_SIGNING_KEY_FILE", str(tmp_path / "missing.key"))
    tenant, key = make_tenant()
    b = post(key, **HUMAN).json()
    assert b["status"] == "BLOCK" and "signing requested but failed" in b["human_gate"]["reason"], b
    p = json.loads(anchors(tenant)[0]["payload_json"])
    assert p["signed"] is False


# ------------------------------------------------------------------ resource limits (fail closed)
def test_task_length_limit_blocks_before_any_model_call(env, fake):
    env.setenv("OLA_PIPELINE_MAX_TASK_CHARS", "50")
    _, key = make_tenant()
    r = post(key, task="x" * 51, **HUMAN)
    assert r.status_code == 400 and "too long" in r.text and fake.requests == []
    assert post(key, task="x" * 50, **HUMAN).status_code == 200            # the exact limit is allowed


@pytest.mark.parametrize("bad", ["0", "-1", "many", "1.5"])
def test_invalid_limits_are_503_never_unlimited(env, fake, bad):
    _, key = make_tenant()
    env.setenv("OLA_PIPELINE_MAX_CONCURRENCY", bad)
    assert post(key, **HUMAN).status_code == 503
    env.setenv("OLA_PIPELINE_MAX_CONCURRENCY", "4")
    env.setenv("OLA_PIPELINE_MAX_TASK_CHARS", bad)
    assert post(key, **HUMAN).status_code == 503
    assert fake.requests == [] and pb._active_runs == 0


def test_concurrency_limit_sheds_load_and_the_slot_is_reusable(env, fake):
    env.setenv("OLA_PIPELINE_MAX_CONCURRENCY", "1")
    _, key = make_tenant()
    entered, release = threading.Event(), threading.Event()
    real_run = Pipeline.run

    def slow_run(self, task):
        entered.set()
        assert release.wait(60)
        return real_run(self, task)

    env.setattr(Pipeline, "run", slow_run)
    result = {}
    t = threading.Thread(target=lambda: result.update(r=post(key, **HUMAN)))
    t.start()
    assert entered.wait(15)
    busy = post(key, **HUMAN)                                              # second run while the first holds the slot
    assert busy.status_code == 429 and busy.headers["retry-after"] == "5"
    release.set()
    t.join(90)
    assert result["r"].status_code == 200 and pb._active_runs == 0
    env.setattr(Pipeline, "run", real_run)
    assert post(key, **HUMAN).status_code == 200                           # slot was released


def test_slot_is_released_when_the_run_raises(env):
    def boom(self, task):
        raise RuntimeError("boom")

    env.setattr(Pipeline, "run", boom)
    tenant, _ = make_tenant()
    with pytest.raises(RuntimeError):
        pb.run_pipeline(tenant, TASK, ReviewDecision(True, "r", "ok"))
    assert pb._active_runs == 0


# ------------------------------------------------------------------ concurrency
def test_concurrent_appends_keep_one_valid_chain():
    tenant, _ = make_tenant()
    errors, n = [], 12

    def work(i):
        try:
            pb.append_evidence(tenant, "pipeline.test", {"i": i})
        except Exception as exc:                          # pragma: no cover - failure is asserted below
            errors.append(repr(exc))

    threads = [threading.Thread(target=work, args=(i,)) for i in range(n)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert errors == []
    chain = pb.load_chain(tenant)
    assert len(chain) == n and [r["seq"] for r in chain] == list(range(n))
    assert verify_chain(chain)[0]


# ------------------------------------------------------------------ judge qualification (opt-in)
DATASET_SHA = hashlib.sha256((Path(__file__).resolve().parent / "data" / "judge_eval.json").read_bytes()).hexdigest()
JUDGE_DIGEST = "e5f6a1b2c3d4" * 5 + "abcd"          # FakeOllama.add_model default


PROMPT_FP = judge_prompt_fingerprint(DEFAULT_REQUIREMENTS, 70)     # the judge as the pipeline configures it by default
_DEFAULT = object()


def write_qualification(tmp_path, *, k=0, n=26, model="igor-test", provider="ollama-local", digest=JUDGE_DIGEST,
                        kind="OLLAMA_OBSERVED", dataset=DATASET_SHA, schema="ola.judge-eval/1", verdicts=47,
                        ck=21, cn=21, prompt=_DEFAULT, variant="baseline"):
    doc = {"schema": schema, "provider": provider, "model": model, "dataset_sha256": dataset,
           "meta": {"runtime_kind": kind, "model_digest": digest},
           "summary": {"false_accept": {"k": k, "n": n}, "correct_accepted": {"k": ck, "n": cn},
                       "verdicts_obtained": verdicts}}
    if variant is not None:
        doc["variant"] = variant
    if prompt is not None:
        doc["judge_prompt_sha256"] = PROMPT_FP if prompt is _DEFAULT else prompt
    path = tmp_path / "judge-eval.json"
    path.write_text(json.dumps(doc))
    return path


def require_qualification(env, path, *, pin=DATASET_SHA, **limits):
    env.setenv("OLA_JUDGE_QUALIFICATION_FILE", str(path))
    if pin is not None:
        env.setenv("OLA_JUDGE_QUALIFICATION_DATASET_SHA256", pin)
    for name, value in limits.items():
        env.setenv(name, str(value))


def test_qualification_is_off_by_default_and_the_result_says_so(env):
    _, key = make_tenant()
    b = post(key, **HUMAN).json()
    assert b["igor"]["status"] == "VERIFIED" and b["status"] == "VERIFIED", b
    assert b["igor"]["judge_qualification"]["state"] == "NOT_CONFIGURED"


def test_a_qualified_judge_keeps_verified_and_the_evidence_is_named(env, tmp_path):
    path = write_qualification(tmp_path, k=0, n=26)
    require_qualification(env, path)
    _, key = make_tenant()
    b = post(key, **HUMAN).json()
    q = b["igor"]["judge_qualification"]
    assert b["igor"]["status"] == "VERIFIED" and b["status"] == "VERIFIED", b
    assert q["state"] == "QUALIFIED" and q["file_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert q["false_accept"] == {"k": 0, "n": 26} and q["model_digest"] == JUDGE_DIGEST
    assert q["upper95"] == pytest.approx(pb._wilson_upper(0, 26), abs=1e-4) and q["upper95"] <= 0.15
    assert str(tmp_path) not in json.dumps(b), "the server path of the qualification file must not leak"
    assert "judge_qualification" in json.dumps(b["decision_report"]), "the qualification is part of the report"


@pytest.mark.parametrize("name,kwargs", [
    ("many false accepts", dict(k=5, n=26)),
    ("too few wrong items", dict(k=0, n=10)),
    ("other labelled set", dict(dataset="0" * 64)),
    ("test double runtime", dict(kind="TEST_DOUBLE")),
    ("no runtime kind", dict(kind=None)),
    ("other model", dict(model="someone-else")),
    ("other provider", dict(provider="openai")),
    ("other digest", dict(digest="f" * 64)),
    ("no digest", dict(digest=None)),
    ("no verdict obtained", dict(verdicts=0)),
    ("unknown schema", dict(schema="ola.judge-eval/2")),
    ("k greater than n", dict(k=30, n=26)),
    ("boolean counts", dict(k=True, n=26)),
    ("boolean zero count", dict(k=False, n=26)),
    ("string counts", dict(k="0", n=26)),
])
def test_an_unqualified_judge_downgrades_verified_to_unknown_even_with_human_approval(env, tmp_path, name, kwargs):
    require_qualification(env, write_qualification(tmp_path, **kwargs))
    tenant, key = make_tenant()
    b = post(key, **HUMAN).json()
    assert b["igor"]["pipeline_igor_status"] == "VERIFIED" or b["igor"]["gate_state"] == "PASS", "the gate itself said PASS"
    assert b["igor"]["judge_qualification"]["state"] == "NOT_QUALIFIED", (name, b["igor"]["judge_qualification"])
    assert b["igor"]["status"] == "UNKNOWN" and "not qualified" in b["igor"]["reason"]
    assert b["status"] == "BLOCK" and "UNKNOWN" in b["human_gate"]["reason"], "a human cannot promote UNKNOWN"
    assert len(anchors(tenant)) == 1, "the refusal is itself evidence"


@pytest.mark.parametrize("content", [None, "not json", "[]", "{}", json.dumps({"schema": "ola.judge-eval/1"}),
                                     json.dumps({"schema": "ola.judge-eval/1", "meta": {}, "summary": {}})])
def test_missing_or_malformed_qualification_file_is_not_qualified(env, tmp_path, content):
    path = tmp_path / "judge-eval.json"
    if content is not None:
        path.write_text(content)
    require_qualification(env, path)
    _, key = make_tenant()
    b = post(key, **HUMAN).json()
    assert b["igor"]["judge_qualification"]["state"] == "NOT_QUALIFIED" and b["igor"]["status"] == "UNKNOWN", b


def test_the_false_accept_limit_is_applied_to_the_recomputed_upper_bound(env, tmp_path):
    upper = pb._wilson_upper(1, 40)
    path = write_qualification(tmp_path, k=1, n=40)
    _, key = make_tenant()
    require_qualification(env, path, OLA_JUDGE_MAX_FALSE_ACCEPT=round(upper + 0.002, 4))
    assert post(key, **HUMAN).json()["igor"]["judge_qualification"]["state"] == "QUALIFIED"
    env.setenv("OLA_JUDGE_MAX_FALSE_ACCEPT", str(round(upper - 0.002, 4)))
    assert post(key, **HUMAN).json()["igor"]["judge_qualification"]["state"] == "NOT_QUALIFIED"


def test_the_wrong_item_minimum_is_configurable(env, tmp_path):
    require_qualification(env, write_qualification(tmp_path, k=0, n=10), OLA_JUDGE_MAX_FALSE_ACCEPT=0.5,
                          OLA_JUDGE_QUALIFICATION_MIN_WRONG=10)
    _, key = make_tenant()
    assert post(key, **HUMAN).json()["igor"]["judge_qualification"]["state"] == "QUALIFIED"
    env.setenv("OLA_JUDGE_QUALIFICATION_MIN_WRONG", "11")
    assert post(key, **HUMAN).json()["igor"]["judge_qualification"]["state"] == "NOT_QUALIFIED"


def test_qualification_can_only_downgrade_never_upgrade(env, fake, tmp_path):
    fake.canary_mode = "accept"                                   # the gate itself says REVIEW_REQUIRED
    require_qualification(env, write_qualification(tmp_path, k=0, n=26))
    _, key = make_tenant()
    b = post(key, **HUMAN).json()
    assert b["igor"]["judge_qualification"]["state"] == "QUALIFIED"
    assert b["igor"]["status"] == "UNKNOWN" and b["status"] == "BLOCK", b


@pytest.mark.parametrize("name,value", [
    ("OLA_JUDGE_MAX_FALSE_ACCEPT", "abc"), ("OLA_JUDGE_MAX_FALSE_ACCEPT", "0"), ("OLA_JUDGE_MAX_FALSE_ACCEPT", "1.5"),
    ("OLA_JUDGE_MAX_FALSE_ACCEPT", "-0.1"), ("OLA_JUDGE_QUALIFICATION_MIN_WRONG", "0"),
    ("OLA_JUDGE_QUALIFICATION_MIN_WRONG", "many"),
])
def test_bad_qualification_settings_are_503_before_any_model_is_called(env, fake, tmp_path, name, value):
    require_qualification(env, write_qualification(tmp_path), **{name: value})
    _, key = make_tenant()
    r = post(key, **HUMAN)
    assert r.status_code == 503, r.text
    assert fake.calls.get("nina-test", 0) == 0 and fake.calls.get("igor-test", 0) == 0


@pytest.mark.parametrize("pin", [None, "", "abc", "G" * 64, "a" * 63])
def test_a_qualification_file_without_a_valid_dataset_pin_is_503(env, fake, tmp_path, pin):
    require_qualification(env, write_qualification(tmp_path), pin=pin)
    if pin == "":
        env.setenv("OLA_JUDGE_QUALIFICATION_DATASET_SHA256", "")
    elif pin is not None:
        env.setenv("OLA_JUDGE_QUALIFICATION_DATASET_SHA256", pin)
    _, key = make_tenant()
    r = post(key, **HUMAN)
    assert r.status_code == 503 and fake.calls.get("nina-test", 0) == 0, r.text


def test_reverification_applies_the_policy_in_force_now(env, tmp_path):
    tenant, key = make_tenant()
    b = post(key, **HUMAN).json()
    assert b["igor"]["status"] == "VERIFIED"
    sid = b["session_id"]
    client = TestClient(app)
    assert client.get(f"/pipeline-session/{sid}", headers={"X-API-Key": key}).json()["verification"]["status"] == "VERIFIED"
    require_qualification(env, write_qualification(tmp_path, k=5, n=26))        # operator turns the requirement on
    v = client.get(f"/pipeline-session/{sid}", headers={"X-API-Key": key}).json()["verification"]
    assert v["status"] == "UNKNOWN" and v["judge_qualification"]["state"] == "NOT_QUALIFIED"
    env.setenv("OLA_JUDGE_QUALIFICATION_DATASET_SHA256", "nonsense")
    assert client.get(f"/pipeline-session/{sid}", headers={"X-API-Key": key}).status_code == 503


def test_wilson_upper_bound_matches_the_measuring_script():
    import importlib.util
    spec = importlib.util.spec_from_file_location("judge_eval_for_test", Path(__file__).resolve().parents[1] / "scripts" / "judge_eval.py")
    je = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(je)
    for k, n in [(0, 26), (1, 26), (5, 26), (20, 26), (26, 26), (3, 100)]:
        assert pb._wilson_upper(k, n) == pytest.approx(je.wilson(k, n)[1], abs=1e-9)


def test_default_wrong_item_minimum_is_twenty(env, tmp_path):
    # the bound is not what rejects the 19-item measurement (limit 50%), the item minimum is
    path = write_qualification(tmp_path, k=0, n=19)
    require_qualification(env, path, OLA_JUDGE_MAX_FALSE_ACCEPT=0.5)
    _, key = make_tenant()
    q = post(key, **HUMAN).json()["igor"]["judge_qualification"]
    assert q["state"] == "NOT_QUALIFIED" and "too few wrong answers" in q["reason"]
    write_qualification(tmp_path, k=0, n=20)
    assert post(key, **HUMAN).json()["igor"]["judge_qualification"]["state"] == "QUALIFIED"


def test_a_judge_without_a_digest_cannot_be_matched_to_a_measurement_without_one(env, fake, tmp_path):
    fake.add_model("igor-test", digest=None)                    # the runtime does not report a digest for the judge
    require_qualification(env, write_qualification(tmp_path, digest=None))
    _, key = make_tenant()
    b = post(key, **HUMAN).json()
    assert b["igor"]["judge_qualification"]["state"] == "NOT_QUALIFIED", b["igor"]["judge_qualification"]
    assert b["igor"]["status"] != "VERIFIED" and b["status"] == "BLOCK"


@pytest.mark.parametrize("judge_env", [None, "igor", [], 0])
def test_a_session_without_a_judge_envelope_is_not_qualified(tmp_path, judge_env, monkeypatch):
    policy = pb.QualificationPolicy(write_qualification(tmp_path), DATASET_SHA, 0.15, 20)
    q = pb.judge_qualification(judge_env, policy)
    assert q["state"] == "NOT_QUALIFIED" and "no judge envelope" in q["reason"]
    good = {"provider": "ollama-local", "model": "igor-test", "model_digest": JUDGE_DIGEST}
    monkeypatch.setattr(pb, "session_judge_fingerprint", lambda *a: (PROMPT_FP, ""))
    assert pb.judge_qualification(good, policy, tmp_path, {})["state"] == "QUALIFIED", \
        "the same file qualifies the matching envelope"


# ------------------------------------------------------------------ two-sided qualification
def judged(env, tmp_path, **kw):
    require_qualification(env, write_qualification(tmp_path, **kw), **kw.pop("limits", {}))
    _, key = make_tenant()
    return post(key, **HUMAN).json()["igor"]


def test_a_judge_that_rejects_everything_is_not_qualified(env, tmp_path):
    """The measured qwen2.5:7b result on the v2 set: 0/72 false accepts, 0/67 correct answers accepted."""
    ig = judged(env, tmp_path, k=0, n=72, ck=0, cn=67)
    q = ig["judge_qualification"]
    assert q["state"] == "NOT_QUALIFIED" and "rejects everything" in q["reason"], q
    assert q["false_accept"] == {"k": 0, "n": 72} and q["correct_accepted"] == {"k": 0, "n": 67}
    assert ig["status"] == "UNKNOWN"


def test_a_missing_or_malformed_correct_accepted_block_is_not_qualified(env, tmp_path):
    path = write_qualification(tmp_path)
    doc = json.loads(path.read_text())
    del doc["summary"]["correct_accepted"]
    path.write_text(json.dumps(doc))
    require_qualification(env, path)
    _, key = make_tenant()
    assert post(key, **HUMAN).json()["igor"]["judge_qualification"]["state"] == "NOT_QUALIFIED"
    for bad in ({"k": 5, "n": 3}, {"k": True, "n": 21}, {"k": -1, "n": 21}, {"k": "21", "n": 21}):
        doc["summary"]["correct_accepted"] = bad
        path.write_text(json.dumps(doc))
        q = post(key, **HUMAN).json()["igor"]["judge_qualification"]
        assert q["state"] == "NOT_QUALIFIED" and "malformed" in q["reason"], (bad, q)


def test_correct_accept_limit_uses_the_recomputed_lower_bound(env, tmp_path):
    lower = pb._wilson_lower(15, 21)
    path = write_qualification(tmp_path, ck=15, cn=21)
    _, key = make_tenant()
    require_qualification(env, path, OLA_JUDGE_MIN_CORRECT_ACCEPT=round(lower - 0.002, 4))
    assert post(key, **HUMAN).json()["igor"]["judge_qualification"]["state"] == "QUALIFIED"
    env.setenv("OLA_JUDGE_MIN_CORRECT_ACCEPT", str(round(lower + 0.002, 4)))
    assert post(key, **HUMAN).json()["igor"]["judge_qualification"]["state"] == "NOT_QUALIFIED"


def test_the_correct_item_minimum_is_configurable(env, tmp_path):
    require_qualification(env, write_qualification(tmp_path, ck=10, cn=10), OLA_JUDGE_QUALIFICATION_MIN_CORRECT=10)
    _, key = make_tenant()
    assert post(key, **HUMAN).json()["igor"]["judge_qualification"]["state"] == "QUALIFIED"
    env.setenv("OLA_JUDGE_QUALIFICATION_MIN_CORRECT", "11")
    assert post(key, **HUMAN).json()["igor"]["judge_qualification"]["state"] == "NOT_QUALIFIED"


@pytest.mark.parametrize("name,value", [("OLA_JUDGE_MIN_CORRECT_ACCEPT", "0"), ("OLA_JUDGE_MIN_CORRECT_ACCEPT", "abc"),
                                        ("OLA_JUDGE_MIN_CORRECT_ACCEPT", "1.5"),
                                        ("OLA_JUDGE_QUALIFICATION_MIN_CORRECT", "0")])
def test_bad_two_sided_configuration_is_503(env, tmp_path, name, value):
    require_qualification(env, write_qualification(tmp_path), **{name: value})
    _, key = make_tenant()
    assert post(key, **HUMAN).status_code == 503


def test_wilson_lower_matches_known_values():
    assert pb._wilson_lower(0, 67) == 0.0
    assert pb._wilson_lower(21, 21) == pytest.approx(0.8454, abs=1e-3)
    assert pb._wilson_lower(30, 60) == pytest.approx(0.3773, abs=1e-3)


# ------------------------------------------------------------------ qualification is bound to the judge prompt
def qualified_with(env, tmp_path, **kw):
    require_qualification(env, write_qualification(tmp_path, **kw))
    _, key = make_tenant()
    return post(key, **HUMAN).json()["igor"]


def test_a_qualification_without_a_prompt_fingerprint_is_not_qualified(env, tmp_path):
    ig = qualified_with(env, tmp_path, prompt=None)
    q = ig["judge_qualification"]
    assert q["state"] == "NOT_QUALIFIED" and "different judge prompt" in q["reason"], q
    assert q["session_judge_prompt_sha256"] == PROMPT_FP, "the reason names what the session actually used"
    assert ig["status"] == "UNKNOWN"


def test_a_qualification_of_another_prompt_is_not_qualified(env, tmp_path):
    other = judge_prompt_fingerprint(DEFAULT_REQUIREMENTS + ("Be lenient.",), 70)
    q = qualified_with(env, tmp_path, prompt=other)["judge_qualification"]
    assert q["state"] == "NOT_QUALIFIED" and "different judge prompt" in q["reason"], q


@pytest.mark.parametrize("bad", ["", "0" * 64, PROMPT_FP.upper(), PROMPT_FP[:-1], 7, [PROMPT_FP]])
def test_a_malformed_prompt_fingerprint_is_not_qualified(env, tmp_path, bad):
    assert qualified_with(env, tmp_path, prompt=bad)["judge_qualification"]["state"] == "NOT_QUALIFIED"


def test_a_session_with_another_threshold_does_not_borrow_the_measurement(env, tmp_path):
    env.setenv("OLA_MIN_QUALITY_SCORE", "60")
    q = qualified_with(env, tmp_path)["judge_qualification"]                    # measured at 70, session ran at 60
    assert q["state"] == "NOT_QUALIFIED" and q["session_judge_prompt_sha256"] == judge_prompt_fingerprint(
        DEFAULT_REQUIREMENTS, 60)


def test_the_measurement_at_the_session_threshold_qualifies(env, tmp_path):
    env.setenv("OLA_MIN_QUALITY_SCORE", "60")
    ig = qualified_with(env, tmp_path, prompt=judge_prompt_fingerprint(DEFAULT_REQUIREMENTS, 60))
    assert ig["judge_qualification"]["state"] == "QUALIFIED", ig["judge_qualification"]
    assert ig["judge_qualification"]["judge_prompt_sha256"] == judge_prompt_fingerprint(DEFAULT_REQUIREMENTS, 60)


def test_a_session_with_other_quality_requirements_does_not_borrow_the_measurement(env, tmp_path):
    env.setenv("OLA_QUALITY_REQUIREMENTS", "Answers the task correctly.\nFollows every explicit constraint.")
    q = qualified_with(env, tmp_path)["judge_qualification"]
    assert q["state"] == "NOT_QUALIFIED" and "different judge prompt" in q["reason"], q
    scoped = judge_prompt_fingerprint(("Answers the task correctly.", "Follows every explicit constraint."), 70)
    assert qualified_with(env, tmp_path, prompt=scoped)["judge_qualification"]["state"] == "QUALIFIED"


def test_a_session_made_with_another_prompt_template_is_not_qualified(env, tmp_path, monkeypatch):
    """The requirements and threshold match, but the stored prompt is not what the CURRENT template produces."""
    require_qualification(env, write_qualification(tmp_path))
    _, key = make_tenant()
    b = post(key, **HUMAN).json()
    assert b["igor"]["judge_qualification"]["state"] == "QUALIFIED"
    sd = next(Path(os.environ["OLA_PIPELINE_VAULT_DIR"]).glob(f"*/{b['session_id']}"))
    real = pb.build_messages
    monkeypatch.setattr(pb, "build_messages", lambda *a: real(*a)[:1] + [{"role": "user", "content": "lenient"}])
    final = json.loads((sd / "final.json").read_text())
    env_igor = pb.inspect_session(sd).igor[-1]
    fp, why = pb.session_judge_fingerprint(sd, env_igor, final)
    assert fp is None and "current prompt template" in why


def real_session(env):
    _, key = make_tenant()
    b = post(key, **HUMAN).json()
    sd = next(Path(os.environ["OLA_PIPELINE_VAULT_DIR"]).glob(f"*/{b['session_id']}"))
    return sd, pb.inspect_session(sd).igor[-1], json.loads((sd / "final.json").read_text())


def test_session_fingerprint_matches_the_pure_function(env):
    sd, igor_env, final = real_session(env)
    assert pb.session_judge_fingerprint(sd, igor_env, final) == (PROMPT_FP, "")


@pytest.mark.parametrize("mutate", ["no_policy", "bool_threshold", "float_threshold", "huge_threshold", "no_final",
                                    "bad_input_hash", "missing_artifact", "bad_prompt_hash", "no_envelope"])
def test_session_fingerprint_fails_closed(env, mutate):
    sd, igor_env, final = real_session(env)
    final = json.loads(json.dumps(final))
    if mutate == "no_policy":
        del final["policy"]
    elif mutate == "bool_threshold":
        final["policy"]["min_quality_score"] = True
    elif mutate == "float_threshold":
        final["policy"]["min_quality_score"] = 70.0
    elif mutate == "huge_threshold":
        final["policy"]["min_quality_score"] = 101
    elif mutate == "no_final":
        final = None
    elif mutate == "bad_input_hash":
        igor_env = {**igor_env, "input_hash": "../../etc/passwd"}
    elif mutate == "missing_artifact":
        igor_env = {**igor_env, "input_hash": "f" * 64}
    elif mutate == "bad_prompt_hash":
        igor_env = {**igor_env, "prompt_hash": "0" * 64}
    elif mutate == "no_envelope":
        igor_env = {}
    fp, why = pb.session_judge_fingerprint(sd, igor_env, final)
    assert fp is None and why, (mutate, fp, why)


def test_without_a_session_directory_nothing_is_qualified(tmp_path):
    policy = pb.QualificationPolicy(write_qualification(tmp_path), DATASET_SHA, 0.15, 20)
    good = {"provider": "ollama-local", "model": "igor-test", "model_digest": JUDGE_DIGEST}
    q = pb.judge_qualification(good, policy)
    assert q["state"] == "NOT_QUALIFIED" and "no session directory" in q["reason"]


def _forge_input(sd, igor_env, edit):
    """Write a modified copy of the stored judge input (and the matching prompt) as new artifacts and return an envelope
    that points at them: what an attacker who controls the session directory but not the anchor would have to do."""
    from ola_pipeline.hashing import canonical_bytes
    from ola_pipeline.igor import build_messages
    inp = json.loads((sd / "artifacts" / igor_env["input_hash"]).read_text())
    edit(inp)
    data = canonical_bytes(inp)
    h = hashlib.sha256(data).hexdigest()
    (sd / "artifacts" / h).write_bytes(data)
    prompt = canonical_bytes(build_messages(inp["task"], inp["nina_output"], inp["evidence_checks"],
                                            tuple(inp["quality_requirements"])))
    ph = hashlib.sha256(prompt).hexdigest()
    (sd / "artifacts" / ph).write_bytes(prompt)
    return {**igor_env, "input_hash": h, "prompt_hash": ph}


@pytest.mark.parametrize("reqs", [[], "text", ["ok", 1], [None]])
def test_unusable_stored_requirements_are_refused_even_with_a_consistent_prompt(env, reqs):
    """The stored prompt matches the stored input here, so only the validation of the requirements stops it."""
    sd, igor_env, final = real_session(env)
    forged = _forge_input(sd, igor_env, lambda i: i.__setitem__("quality_requirements", reqs)) \
        if isinstance(reqs, list) else None
    if forged is None:                                    # a non-list cannot be fed to the prompt builder: store it raw
        data = json.dumps({**json.loads((sd / "artifacts" / igor_env["input_hash"]).read_text()),
                           "quality_requirements": reqs}, sort_keys=True, separators=(",", ":")).encode()
        h = hashlib.sha256(data).hexdigest()
        (sd / "artifacts" / h).write_bytes(data)
        forged = {**igor_env, "input_hash": h}
    fp, why = pb.session_judge_fingerprint(sd, forged, final)
    assert fp is None and why


def test_a_modified_input_artifact_is_refused_even_when_the_prompt_is_unchanged(env):
    """Extra field in the stored input: the rebuilt prompt is identical, so only the artifact's own hash notices."""
    sd, igor_env, final = real_session(env)
    path = sd / "artifacts" / igor_env["input_hash"]
    inp = json.loads(path.read_text())
    inp["extra"] = "tampered"
    path.chmod(0o644)
    path.write_text(json.dumps(inp, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    fp, why = pb.session_judge_fingerprint(sd, igor_env, final)
    assert fp is None and "cannot be reconstructed" in why


@pytest.mark.parametrize("variant", ["scoped-requirements", "plain-input", None, "", 0])
def test_a_measurement_made_with_a_prompt_variant_never_qualifies(env, tmp_path, variant):
    """Found by review: the scoped-requirements variant has the fingerprint of a production run configured with the
    same requirements. Its measurement still must not qualify a session - only 'baseline' files can."""
    scoped = ("Answers the task correctly.", "Follows every explicit constraint stated in the task.")
    env.setenv("OLA_QUALITY_REQUIREMENTS", "\n".join(scoped))
    fp = judge_prompt_fingerprint(scoped, 70)
    q = qualified_with(env, tmp_path, prompt=fp, variant=variant)["judge_qualification"]
    assert q["state"] == "NOT_QUALIFIED" and "variant" in q["reason"], q
    ok = qualified_with(env, tmp_path, prompt=fp, variant="baseline")["judge_qualification"]
    assert ok["state"] == "QUALIFIED", "the same fingerprint measured as the baseline qualifies"


def test_a_pathologically_nested_stored_input_fails_closed(env):
    sd, igor_env, final = real_session(env)
    forged = _forge_input(sd, igor_env, lambda i: i.__setitem__("task", None))
    deep = "[" * 100000 + "]" * 100000
    data = ('{"evidence_checks":[],"nina_output":"x","quality_requirements":["r"],"task":' + deep + '}').encode()
    h = hashlib.sha256(data).hexdigest()
    (sd / "artifacts" / h).write_bytes(data)
    fp, why = pb.session_judge_fingerprint(sd, {**forged, "input_hash": h}, final)
    assert fp is None and why
