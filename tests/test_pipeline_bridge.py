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
    assert b["replay_verification"]["status"] == "PASS" and len(b["replay"]) == 3   # nina + igor + canary
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
    assert body["replay_verification"]["status"] == "PASS" and body["replay"] == a["replay"]


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
