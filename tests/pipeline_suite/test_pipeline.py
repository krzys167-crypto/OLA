"""Pipeline tests. Numbering follows the 14 required cases (T01..T14) + extra hardening tests.

IMPORTANT: runs against FakeOllama are labelled TEST_DOUBLE by construction. They prove protocol
handling and gate logic, NOT that a real Ollama runtime executed anything. See test_real_ollama.py.
"""
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from pipeline_helpers import igor_json
from ola_pipeline import Pipeline, Policy, verify_session
from ola_pipeline import pipeline as pipeline_mod
from ola_pipeline.config import ConfigError
from ola_pipeline.errors import ReplayDetected
from ola_pipeline.hashing import canonical_bytes, sha256_hex
from ola_pipeline.source import SourceAnchor
from ola_pipeline.vault import EvidenceVault

TASK = "State the capital of France in one sentence."


def run(cfg, task=TASK):
    return Pipeline(cfg).run(task)


def envelopes(session_dir):
    return [json.loads(p.read_text()) for p in sorted((Path(session_dir) / "envelopes").glob("*.json"))]


def all_files(root):
    return {str(p): sha256_hex(p.read_bytes()) for p in Path(root).rglob("*") if p.is_file()}


def assert_clean(r):
    rep = verify_session(r.session_dir)
    assert rep["failures"] == [], rep["failures"]
    return rep


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def tamper(path, mutate):
    os.chmod(path, 0o644)
    mutate(path)


# ---------------------------------------------------------------- T01
def test_t01_protocol_execution_and_provenance_against_test_double(fake, make_cfg):
    fake.script("nina-test", "Paris is the capital of France.")
    fake.script("igor-test", igor_json("PASS", 92))
    r = run(make_cfg())
    f = r.final
    assert f["nina_status"] == "EXECUTED" and f["iterations"] == 1
    assert f["gate_state"] == "PASS"
    # labelled honestly: a test double is never "VERIFIED"
    assert f["evidence_class"] == "TEST_DOUBLE" and f["igor_status"] == "PASS_UNATTESTED"
    assert f["evidence"]["output_hash"] == sha256_hex(b"Paris is the capital of France.")
    n, g, c = envelopes(r.session_dir)   # Nina, Igor, and the Igor calibration canary
    assert c["agent_id"] == "igor-canary" and c["gate_state"] == "CANARY_REJECTED"
    for k in ("run_id", "parent_run_id", "source_sha", "agent_id", "provider", "model", "model_digest",
              "prompt_hash", "input_hash", "output_hash", "timestamp", "iteration", "execution_status",
              "gate_state"):
        assert k in n, k
    assert n["provider"] == "ollama-local" and n["model"] == "nina-test" and n["model_digest"]
    assert g["parent_run_id"] == n["run_id"] and g["agent_id"] == "igor"
    rep = assert_clean(r)
    assert rep["overall"] == "PARTIAL"  # integrity fine, runtime is a declared test double


def test_t02_ollama_unavailable_fails_closed(make_cfg):
    cfg = make_cfg(nina_url=f"http://127.0.0.1:{free_port()}")  # nothing listens here (real, not mocked)
    r = run(cfg)
    f = r.final
    assert f["nina_status"] == "PROVIDER_UNAVAILABLE"
    assert f["gate_state"] == "BLOCKED" and f["igor_status"] == "NOT_RUN"
    assert f["evidence"]["output_hash"] is None
    assert len(envelopes(r.session_dir)) == 1
    rep = assert_clean(r)
    assert rep["overall"] == "PARTIAL"  # never VERIFIED/CONSISTENT without a runtime


def test_t03_missing_provenance_blocks(fake, make_cfg):
    fake.script("igor-test", igor_json("PASS"))
    unknown = lambda: SourceAnchor("", "UNKNOWN", "2026-10-03T00:00:00Z")
    r = Pipeline(make_cfg()).__class__(make_cfg(), source_fn=unknown).run(TASK)
    assert r.final["gate_state"] == "BLOCKED"
    assert any("provenance incomplete" in x and "source_sha" in x for x in r.final["gate_reasons"])


def test_t04_changed_output_hash_mismatch(fake, make_cfg):
    fake.script("igor-test", igor_json("PASS"))
    r = run(make_cfg())
    assert_clean(r)
    out = Path(r.session_dir) / "artifacts" / r.final["evidence"]["output_hash"]
    tamper(out, lambda p: p.write_text("Lyon is the capital of France."))
    rep = verify_session(r.session_dir)
    assert rep["overall"] == "FAILED"
    assert any("hash mismatch" in x and "output" in x for x in rep["failures"])


def test_t05_changed_evidence_fails_verification(fake, make_cfg):
    fake.script("igor-test", igor_json("PASS"))
    r = run(make_cfg())
    first = sorted((Path(r.session_dir) / "envelopes").glob("*.json"))[0]
    original = first.read_text()

    # (a) naive edit
    def edit(p):
        e = json.loads(p.read_text()); e["model"] = "other-model"; p.write_text(json.dumps(e))
    tamper(first, edit)
    rep = verify_session(r.session_dir)
    assert rep["overall"] == "FAILED" and any("envelope_hash mismatch" in x for x in rep["failures"])

    # (b) smarter edit: attacker recomputes that envelope's hash -> the chain breaks downstream
    from ola_pipeline.verify import compute_envelope_hash, compute_binding
    def edit2(p):
        e = json.loads(original); e["model"] = "other-model"
        e["binding"] = compute_binding(e); e["envelope_hash"] = compute_envelope_hash(e)
        p.write_text(json.dumps(e))
    tamper(first, edit2)
    rep = verify_session(r.session_dir)
    assert rep["overall"] == "FAILED" and any("hash-chain broken" in x for x in rep["failures"])


def test_t06_igor_pass_allows_gate_only_with_accepted_runtime(fake, make_cfg):
    fake.script("igor-test", igor_json("PASS", 95))
    assert run(make_cfg()).final["gate_state"] == "PASS"
    # default policy (no test doubles) -> same evidence is BLOCKED
    r = run(make_cfg(policy=Policy()))
    assert r.final["gate_state"] == "BLOCKED"
    assert any("TEST_DOUBLE" in x for x in r.final["gate_reasons"])


def test_t07_igor_review_never_passes(fake, make_cfg):
    fake.script("igor-test", igor_json("REVIEW", 55, corrections=["cite a source"], findings=["unsupported"]))
    r = run(make_cfg())
    f = r.final
    assert f["gate_state"] == "REVIEW_REQUIRED" and f["igor_status"] == "REVIEW"
    assert f["iterations"] == 3  # max 3, then stop
    assert_clean(r)


def test_t08_igor_block_never_passes(fake, make_cfg):
    fake.script("igor-test", igor_json("BLOCK", 10, corrections=["remove fabricated claim"]))
    r = run(make_cfg())
    assert r.final["gate_state"] == "BLOCKED" and r.final["iterations"] == 3
    # BLOCK without anything to correct is terminal immediately
    fake.calls.clear()
    fake.script("igor-test", igor_json("BLOCK", 0, corrections=[]))
    r2 = run(make_cfg())
    assert r2.final["gate_state"] == "BLOCKED" and r2.final["iterations"] == 1


@pytest.mark.parametrize("mode", ["timeout", "http_error", "invalid_json", "wrong_schema"])
def test_t09_igor_failure_never_passes(fake, make_cfg, mode):
    if mode == "timeout":
        fake.delays["igor-test"] = 1.5
    elif mode == "http_error":
        fake.http_fail["igor-test"] = 500
    elif mode == "invalid_json":
        fake.script("igor-test", "PASS, looks great!")
    else:
        fake.script("igor-test", json.dumps({"decision": "PASS", "quality_score": "high"}))
    r = run(make_cfg(igor_timeout=0.4))
    f = r.final
    assert f["gate_state"] == "BLOCKED" and f["igor_status"] == "UNAVAILABLE"
    assert f["iterations"] == 1  # an Igor outage is not Nina's fault: no correction loop
    assert_clean(r)


def test_t10_t11_replay_new_run_id_and_previous_evidence_untouched(fake, make_cfg, tmp_path):
    snapshots = {}

    def nina_second(idx, messages):
        root = tmp_path / "vault"
        snapshots.update(all_files(next(root.glob("ses_*"))))
        snapshots["__prompt__"] = messages[-1]["content"]
        return "draft v2 (date fixed)"

    fake.script("nina-test", "draft v1", nina_second)
    fake.script("igor-test",
                igor_json("REVIEW", 50, corrections=["fix the date"], findings=["wrong date"]),
                igor_json("PASS", 93))
    r = run(make_cfg())
    f = r.final
    assert f["gate_state"] == "PASS" and f["iterations"] == 2
    envs = envelopes(r.session_dir)
    nina = [e for e in envs if e["agent_id"] == "nina"]
    assert len({e["run_id"] for e in envs}) == len(envs) == 5          # T10: every run has its own id (2x nina, 2x igor, 1 canary)
    assert nina[1]["parent_run_id"] == nina[0]["run_id"]               # linked by parent_run_id
    assert nina[1]["refs"]["correction_of_run_id"] == nina[0]["run_id"]
    assert "fix the date" in snapshots["__prompt__"]                  # correction actually reached Nina
    prompt = snapshots.pop("__prompt__")
    now = all_files(r.session_dir)
    for path, h in snapshots.items():                                  # T11: history never rewritten
        assert now[path] == h, path
    assert len(now) > len(snapshots)
    assert nina[0]["output_hash"] != nina[1]["output_hash"]
    assert_clean(r)


def test_t12_unknown_provider_blocks_without_network(fake, make_cfg):
    r = run(make_cfg(nina_provider="mystery-llm"))
    assert r.final["gate_state"] == "BLOCKED" and r.final["nina_status"] == "PROVIDER_UNKNOWN"
    assert fake.requests == []
    assert any("unknown provider" in x for x in r.final["gate_reasons"])


def test_t13_missing_model_digest_is_review_required_not_pass(fake, make_cfg):
    fake.add_model("nina-test", None)  # endpoint exposes no digest
    fake.script("igor-test", igor_json("PASS", 95))
    r = run(make_cfg())
    f = r.final
    assert f["gate_state"] == "REVIEW_REQUIRED" and f["model_digest"] is None
    assert f["igor_status"] == "REVIEW" and f["iterations"] == 1
    assert any("digest" in x for x in f["gate_reasons"])
    # explicit policy waiver -> allowed (recorded in the final policy snapshot)
    r2 = run(make_cfg(policy=Policy(allow_test_double=True, require_model_digest=False)))
    assert r2.final["gate_state"] == "PASS"
    assert r2.final["policy"]["require_model_digest"] is False


def test_t14_independent_verification_from_stored_artifacts_only(fake, make_cfg, tmp_path):
    fake.script("igor-test", igor_json("PASS"))
    r = run(make_cfg())
    lone = tmp_path / "elsewhere"
    lone.mkdir()
    shutil.copy(Path(__file__).resolve().parents[2] / "ola_pipeline" / "verify.py", lone / "verify.py")
    cmd = [sys.executable, "-I", str(lone / "verify.py"), str(r.session_dir), "--json"]
    p = subprocess.run(cmd, capture_output=True, text=True)
    rep = json.loads(p.stdout)
    assert rep["failures"] == [] and rep["recomputed"]["state"] == "PASS"
    assert p.returncode == 3 and rep["overall"] == "PARTIAL"           # test double -> never VERIFIED
    out = Path(r.session_dir) / "artifacts" / r.final["evidence"]["output_hash"]
    tamper(out, lambda q: q.write_text("forged"))
    p2 = subprocess.run(cmd, capture_output=True, text=True)
    assert p2.returncode == 1 and json.loads(p2.stdout)["overall"] == "FAILED"


# ---------------------------------------------------------------- hardening
def test_verified_requires_live_runtime_kind(fake, make_cfg):
    """If the proof says OLLAMA_OBSERVED the same artifacts verify as VERIFIED; TEST_DOUBLE never does."""
    fake.version = "0.99.0"  # a (non-declared) endpoint -> pipeline records OLLAMA_OBSERVED
    fake.script("igor-test", igor_json("PASS"))
    r = run(make_cfg(policy=Policy()))  # default policy: no test doubles allowed
    assert r.final["gate_state"] == "PASS" and r.final["evidence_class"] == "LIVE_RUNTIME_OBSERVED"
    assert r.final["igor_status"] == "VERIFIED"
    assert assert_clean(r)["overall"] == "VERIFIED"


def test_secret_in_task_is_neither_sent_nor_stored(fake, make_cfg):
    secret = "sk-" + "a1B2c3D4" * 4
    r = run(make_cfg(), task=f"Use this key {secret} to call the API")
    assert r.final["gate_state"] == "BLOCKED" and fake.requests == []
    assert all(secret.encode() not in p.read_bytes() for p in Path(r.session_dir).rglob("*") if p.is_file())


def test_api_key_never_persisted(fake, make_cfg, monkeypatch):
    key = "ollama-cloud-key-" + "z9Y8x7W6" * 3
    monkeypatch.setenv("OLLAMA_API_KEY", key)
    fake.script("igor-test", igor_json("PASS"))
    r = run(make_cfg(nina_provider="ollama-cloud", igor_provider="ollama-cloud"))
    assert r.final["provider"] == "ollama-cloud"
    root = Path(r.session_dir).parent
    assert all(key.encode() not in p.read_bytes() for p in root.rglob("*") if p.is_file())


def test_model_is_never_hardcoded(fake, make_cfg):
    r = run(make_cfg(nina_model=""))
    assert r.final["nina_status"] == "CONFIG_ERROR" and r.final["gate_state"] == "BLOCKED"
    assert fake.requests == []


def test_model_missing_on_endpoint_blocks(fake, make_cfg):
    r = run(make_cfg(nina_model="not-pulled"))
    assert r.final["nina_status"] == "MODEL_UNRESOLVED" and r.final["gate_state"] == "BLOCKED"


def test_max_iterations_cap():
    with pytest.raises(ConfigError):
        Policy(max_iterations=4).validate()


def test_vault_refuses_reuse_of_run_id_and_overwrite(tmp_path):
    base = {"agent_id": "nina", "iteration": 1, "source_sha": "s", "input_hash": None,
            "prompt_hash": None, "output_hash": None, "run_id": "run_dup"}
    v1 = EvidenceVault(tmp_path, "ses_one")
    v1.append_envelope(dict(base, session_id="ses_one"))
    v2 = EvidenceVault(tmp_path, "ses_two")
    with pytest.raises(ReplayDetected):
        v2.append_envelope(dict(base, session_id="ses_two"))   # same run_id in another session
    with pytest.raises(ReplayDetected):
        EvidenceVault(tmp_path, "ses_one")                      # session dir can't be recreated
    p = next((tmp_path / "ses_one" / "envelopes").glob("*.json"))
    assert stat.S_IMODE(p.stat().st_mode) == 0o444


def test_copied_session_is_detected_as_replay(fake, make_cfg, tmp_path):
    fake.script("igor-test", igor_json("PASS"))
    r = run(make_cfg())
    root = Path(r.session_dir).parent
    clone = root / "ses_clone"
    shutil.copytree(r.session_dir, clone)
    rep = verify_session(clone)
    assert rep["overall"] == "FAILED" and any("directory name" in x for x in rep["failures"])
    rep2 = verify_session(r.session_dir, scan_root=root)
    assert rep2["overall"] == "FAILED" and any("replayed artifact" in x for x in rep2["failures"])


def test_expected_source_sha_detects_stale_artifact(fake, make_cfg):
    fake.script("igor-test", igor_json("PASS"))
    r = run(make_cfg())
    assert not verify_session(r.session_dir, expected_source_sha=r.final["source_sha"])["failures"]
    rep = verify_session(r.session_dir, expected_source_sha="0" * 64)
    assert rep["overall"] == "FAILED" and any("stale or foreign" in x for x in rep["failures"])


def test_source_change_during_run_blocks(fake, make_cfg):
    fake.script("igor-test", igor_json("PASS"))
    anchors = iter([SourceAnchor("a" * 64, "tree-sha256", "t"), SourceAnchor("b" * 64, "tree-sha256", "t")])
    r = Pipeline(make_cfg(), source_fn=lambda: next(anchors)).run(TASK)
    assert r.final["gate_state"] == "BLOCKED"
    assert any("source_sha changed" in x for x in r.final["gate_reasons"])


def test_final_nonce_minted_only_after_final_source_freeze(fake, make_cfg, monkeypatch):
    fake.script("igor-test", igor_json("PASS"))
    calls = []
    real = pipeline_mod.freeze_source

    def spy_source():
        calls.append("freeze")
        return real()

    seen = {}
    orig = pipeline_mod.mint_final_nonce
    monkeypatch.setattr(pipeline_mod, "mint_final_nonce",
                        lambda a: (seen.setdefault("freezes_before_nonce", len(calls)), orig(a))[1])
    Pipeline(make_cfg(), source_fn=spy_source).run(TASK)
    assert seen["freezes_before_nonce"] == 2  # initial freeze + final freeze, THEN nonce


def test_tampered_final_json_is_detected(fake, make_cfg):
    fake.script("igor-test", igor_json("REVIEW", 40, corrections=["x"]))
    r = run(make_cfg(policy=Policy(allow_test_double=True, max_iterations=1)))
    assert r.final["gate_state"] == "REVIEW_REQUIRED"
    fp = Path(r.session_dir) / "final.json"
    def flip(p):
        d = json.loads(p.read_text()); d["gate_state"] = "PASS"; p.write_text(json.dumps(d))
    tamper(fp, flip)
    rep = verify_session(r.session_dir)
    assert rep["overall"] == "FAILED" and any("gate_state" in x for x in rep["failures"])


def test_report_cli_prints_run_ids_and_hashes(fake, make_cfg):
    fake.script("igor-test", igor_json("PASS"))
    r = run(make_cfg())
    p = subprocess.run([sys.executable, "-m", "ola_pipeline", "report", str(r.session_dir)],
                       capture_output=True, text=True, cwd=str(Path(__file__).resolve().parents[2]))
    assert p.returncode == 0
    assert r.final["run_id"] in p.stdout and r.final["evidence"]["output_hash"] in p.stdout
    assert "verifier       : PARTIAL" in p.stdout  # test double -> never VERIFIED


def test_think_flag_forwarded_only_when_configured(fake, make_cfg):
    """Reasoning models (e.g. qwen3) need `think` controllable from config; unset means 'not sent'."""
    import dataclasses
    fake.script("igor-test", igor_json("PASS"))
    run(make_cfg())
    assert all("think" not in b for b in fake.bodies)
    fake.bodies.clear()
    cfg = make_cfg()
    cfg = dataclasses.replace(cfg, nina=dataclasses.replace(cfg.nina, think=False))
    fake.script("igor-test", igor_json("PASS"))
    r = run(cfg)
    nina_bodies = [b for b in fake.bodies if b["model"] == "nina-test"]
    assert nina_bodies and all(b["think"] is False for b in nina_bodies)
    assert r.final["gate_state"] == "PASS"



# ------------------------------------------------ calibration + independence (found by the live run)
def test_calibration_rubber_stamp_judge_cannot_pass(fake, make_cfg):
    """Live finding: a 0.6B judge returned PASS/100 for a nonsense answer. A judge that PASSes the
    known-wrong canary (2 + 2 = 5) must never produce a PASS, whatever it says about real work."""
    fake.canary_mode = "accept"
    fake.script("nina-test", "Stolica francuska to klasa 10.")
    fake.script("igor-test", igor_json("PASS", 100, reason="fully satisfies the task"))
    r = run(make_cfg())
    f = r.final
    assert f["gate_state"] == "REVIEW_REQUIRED" and f["igor_status"] == "UNCALIBRATED"
    assert any("failed calibration" in x for x in f["gate_reasons"])
    assert fake.canary_calls == 1
    assert_clean(r)


@pytest.mark.parametrize("mode", ["invalid", "fail"])
def test_calibration_unavailable_is_not_pass(fake, make_cfg, mode):
    fake.canary_mode = mode
    fake.script("igor-test", igor_json("PASS", 92))
    f = run(make_cfg()).final
    assert f["gate_state"] == "REVIEW_REQUIRED" and f["igor_status"] == "UNCALIBRATED"
    assert any("calibration" in x for x in f["gate_reasons"])


def test_calibration_runs_only_after_igor_pass_and_can_be_disabled(fake, make_cfg):
    fake.script("igor-test", igor_json("BLOCK", 10, corrections=["redo"]))
    run(make_cfg(policy=Policy(allow_test_double=True, max_iterations=1)))
    assert fake.canary_calls == 0                       # nothing to trust -> no extra LLM call
    fake.script("igor-test", igor_json("PASS", 92))
    fake.canary_mode = "accept"
    f = run(make_cfg(policy=Policy(allow_test_double=True, require_igor_calibration=False))).final
    assert fake.canary_calls == 0 and f["gate_state"] == "PASS"   # explicit opt-out is honoured


def test_same_model_igor_is_not_independent_by_default(fake, make_cfg):
    fake.script("nina-test", igor_json("PASS", 92))      # same model plays both roles
    f = run(make_cfg(igor_model="nina-test")).final     # same provider + model + endpoint
    assert f["gate_state"] == "REVIEW_REQUIRED" and f["igor_status"] == "NOT_INDEPENDENT"
    assert any("not independent" in x for x in f["gate_reasons"])


def test_same_model_igor_allowed_only_by_explicit_policy_and_calibration_still_applies(fake, make_cfg):
    fake.script("nina-test", igor_json("PASS", 92))      # one shared script (same model answers both roles)
    pol = Policy(allow_test_double=True, allow_same_model_igor=True)
    f = run(make_cfg(igor_model="nina-test", policy=pol)).final
    assert f["gate_state"] == "PASS"
    assert any("same provider/model" in w for w in f["warnings"])
    fake.canary_mode = "accept"
    f2 = run(make_cfg(igor_model="nina-test", policy=pol)).final
    assert f2["gate_state"] == "REVIEW_REQUIRED" and f2["igor_status"] == "UNCALIBRATED"


def test_tampered_canary_content_is_detected_by_independent_verifier(fake, make_cfg):
    """verify.py re-derives the canary verdict from raw fields; it does not trust the stored label."""
    fake.canary_mode = "accept"
    fake.script("igor-test", igor_json("PASS", 92))
    r = run(make_cfg())
    sd = r.session_dir
    cev = [e for e in envelopes(sd) if e["agent_id"] == "igor-canary"][0]
    path = sd / "artifacts" / cev["refs"]["evaluation_hash"]
    os.chmod(path, 0o644)
    ev = json.loads(path.read_bytes())
    ev.update(verdict="REJECTED", decision="BLOCK")      # lie about the outcome
    path.write_bytes(canonical_bytes(ev))
    rep = verify_session(sd)
    assert rep["overall"] == "FAILED" and any("hash mismatch" in x or "does not match" in x for x in rep["failures"])
