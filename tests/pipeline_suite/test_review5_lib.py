"""Fifth review, ola_pipeline library: CLI pins, verifier strictness, provider transport, poisoned output."""
import json
import os
import shutil
import stat
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from forge_session import canary_eval, env as forge_env, session
from pipeline_helpers import igor_json
from ola_pipeline import Pipeline, Policy, verify_session
from ola_pipeline import providers
from ola_pipeline.config import PipelineConfig, ProviderConfig
from ola_pipeline.errors import ConfigError, ProviderError
from ola_pipeline.hashing import canonical_bytes
from ola_pipeline.redact import contains_secret

REPO = Path(__file__).resolve().parents[2]
TASK = "State the capital of France in one sentence."


def cli(*args):
    return subprocess.run([sys.executable, "-m", "ola_pipeline", *args], capture_output=True, text=True, cwd=str(REPO))


def unlock(path):
    for p in [path, *Path(path).rglob("*")]:
        os.chmod(p, 0o755 if Path(p).is_dir() else 0o644)


# ----------------------------------------------------------------- verifier baseline and strictness
def test_baseline_forged_session_is_verified(tmp_path):
    v, _ = session(tmp_path)
    assert verify_session(v.dir)["overall"] == "VERIFIED"


def test_two_igor_verdicts_for_one_nina_run_are_verdict_shopping(tmp_path):
    v, _ = session(tmp_path, igors=[{"decision": "BLOCK", "score": 5}, {}])
    r = verify_session(v.dir)
    assert r["overall"] == "FAILED" and any("verdict shopping" in f for f in r["failures"]), r["failures"]


def test_two_canary_verdicts_are_refused(tmp_path):
    v, _ = session(tmp_path, canaries=[{}, {"decision": "PASS", "score": 100}])
    assert verify_session(v.dir)["overall"] == "FAILED"


@pytest.mark.parametrize("kw", [{"score": 5}, {"corrections": ["fix it"]},
                                {"checks": [{"name": "x", "status": "FAIL", "critical": True, "detail": "d"}]}],
                         ids=["low-score", "open-corrections", "critical-fail"])
def test_a_pass_that_contradicts_its_own_evaluation_never_verifies(tmp_path, kw):
    v, _ = session(tmp_path, igors=[kw])
    r = verify_session(v.dir)
    assert r["overall"] != "VERIFIED" and r["recomputed"]["state"] == "BLOCKED", r


@pytest.mark.parametrize("score", [100.0, None, "100", True], ids=["float", "null", "str", "bool"])
def test_a_canary_pass_with_a_non_int_score_counts_as_accepted(tmp_path, score):
    v, _ = session(tmp_path, canaries=[{"decision": "PASS", "score": score}])
    assert verify_session(v.dir)["overall"] != "VERIFIED"


def test_independence_is_recomputed_from_the_envelopes_not_the_label(tmp_path):
    v, _ = session(tmp_path, igor_model="nina-m")             # same model/endpoint, label says DIFFERENT_MODEL
    r = verify_session(v.dir)
    assert r["overall"] != "VERIFIED" and r["recomputed"]["igor_status"] == "NOT_INDEPENDENT", r["recomputed"]


def test_more_iterations_than_the_policy_allows_is_blocked(tmp_path):
    v, _ = session(tmp_path, nina_n=5, policy=Policy(max_iterations=3))
    r = verify_session(v.dir)
    assert r["overall"] != "VERIFIED" and any("exceed the policy maximum" in x for x in r["recomputed"]["reasons"])


def test_an_envelope_with_an_unknown_agent_is_a_failure(tmp_path):
    def extra(v, sid, n):
        forge_env(v, sid, "mallory", 1, None)
    v, _ = session(tmp_path, extra=extra)
    r = verify_session(v.dir)
    assert r["overall"] == "FAILED" and any("unknown agent_id" in f for f in r["failures"])


def test_a_weakened_policy_snapshot_is_flagged(tmp_path):
    v, _ = session(tmp_path, policy=Policy(min_quality_score=0, require_model_digest=False))
    assert any("weaker than the defaults" in w for w in verify_session(v.dir)["warnings"])


# ----------------------------------------------------------------- malformed evidence is a verdict, not an exception
@pytest.mark.parametrize("content", ["[]", "null", "5", '"x"'])
def test_a_final_json_that_is_not_an_object_is_failed(tmp_path, content):
    v, _ = session(tmp_path)
    unlock(v.dir)
    (v.dir / "final.json").write_text(content)
    r = verify_session(v.dir)
    assert r["overall"] == "FAILED" and r["failures"], r


def test_an_evaluation_artifact_that_is_a_list_is_failed_not_an_exception(tmp_path):
    v, _ = session(tmp_path)
    sd = v.dir
    unlock(sd)
    # replace the Igor evaluation by a JSON list under its own hash name is impossible (hash), so corrupt in place
    ev = next(p for p in (sd / "artifacts").iterdir() if b'"judge_status"' in p.read_bytes() and b'"canary"' not in p.read_bytes())
    ev.write_text("[1, 2]")
    r = verify_session(sd)
    assert r["overall"] == "FAILED"


def test_verify_inside_the_session_directory_works(tmp_path, monkeypatch):
    v, _ = session(tmp_path)
    monkeypatch.chdir(v.dir)
    assert verify_session(".")["overall"] == "VERIFIED"


def test_scan_root_sees_underscore_dirs_and_a_missing_root_is_a_failure(tmp_path):
    v, _ = session(tmp_path / "a")
    copy = tmp_path / "scan" / "_copy"
    shutil.copytree(v.dir, copy)
    r = verify_session(v.dir, scan_root=tmp_path / "scan")
    assert r["overall"] == "FAILED" and any("replayed artifact" in f for f in r["failures"]), r["failures"]
    r2 = verify_session(v.dir, scan_root=tmp_path / "does-not-exist")
    assert r2["overall"] == "FAILED" and any("scan root" in f for f in r2["failures"])


# ----------------------------------------------------------------- CLI
def test_cli_an_empty_trusted_key_is_refused_not_ignored(tmp_path):
    v, _ = session(tmp_path)
    ok = cli("verify", str(v.dir))
    assert ok.returncode == 0, ok.stdout + ok.stderr
    bad = cli("verify", str(v.dir), "--trusted-key", "")
    assert bad.returncode == 4, (bad.returncode, bad.stdout, bad.stderr)


def test_cli_an_empty_expected_source_sha_is_not_ignored(tmp_path):
    v, _ = session(tmp_path)
    assert cli("verify", str(v.dir), "--expected-source-sha", "").returncode == 1
    assert cli("verify", str(v.dir), "--expected-source-sha", "a" * 40).returncode == 0


def test_cli_report_of_a_tampered_session_exits_nonzero_and_says_claimed(tmp_path):
    v, _ = session(tmp_path)
    unlock(v.dir)
    e = sorted((v.dir / "envelopes").glob("*.json"))[0]
    doc = json.loads(e.read_text())
    doc["detail"] = "tampered"
    e.write_text(json.dumps(doc))
    p = cli("report", str(v.dir))
    assert p.returncode == 1 and "NOT verified" in p.stdout, (p.returncode, p.stdout[-400:])
    assert cli("report", str(tmp_path / "nope")).returncode == 1


# ----------------------------------------------------------------- providers: transport
class _Recorder(BaseHTTPRequestHandler):
    seen = []

    def do_GET(self):
        type(self).seen.append((self.path, self.headers.get("Authorization")))
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _server(handler):
    s = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s


def test_a_redirect_is_refused_and_the_credential_is_not_forwarded():
    target_seen = []

    class Target(_Recorder):
        seen = target_seen

    target = _server(Target)

    class Redirector(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(307)
            self.send_header("Location", f"http://127.0.0.1:{target.server_port}/leak")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    red = _server(Redirector)
    try:
        with pytest.raises(ProviderError, match="HTTP 307"):
            providers._http("GET", f"http://127.0.0.1:{red.server_port}/api/version", None,
                            {"Authorization": "Bearer sk-SECRETSECRETSECRET1234"}, 5)
        assert target_seen == []
    finally:
        red.shutdown()
        target.shutdown()


def test_only_http_and_https_and_no_credentials_over_plain_http_to_a_remote_host():
    with pytest.raises(ConfigError, match="scheme"):
        providers._http("GET", "file:///etc/hostname", None, {}, 1)
    with pytest.raises(ConfigError, match="plain http"):
        providers._http("GET", "http://example.invalid/x", None, {"Authorization": "Bearer abc"}, 1)


def test_a_response_without_a_model_name_is_not_accepted(monkeypatch):
    def fake_http(method, url, body, headers, timeout, secrets=()):
        if url.endswith("/api/version"):
            return {"version": "0.5.0"}
        if url.endswith("/api/tags"):
            return {"models": [{"name": "m1", "digest": "d" * 64}]}        # no "model" key
        return {"message": {"content": "hi"}, "done": True}                   # no "model" in the answer
    monkeypatch.setattr(providers, "_http", fake_http)
    prov = providers.build_provider(ProviderConfig("ollama-local", "m1", base_url="http://127.0.0.1:1"))
    with pytest.raises(ProviderError, match="does not match"):
        prov.execute([{"role": "user", "content": "x"}])


def test_bad_numeric_policy_env_is_a_config_error_not_a_crash():
    for name in ("OLA_MAX_ITERATIONS", "OLA_MIN_QUALITY_SCORE"):
        with pytest.raises(ConfigError):
            PipelineConfig.from_env({"OLA_NINA_MODEL": "m", "OLA_NINA_BASE_URL": "http://127.0.0.1:1", name: "abc"})


# ----------------------------------------------------------------- poisoned model output
def test_a_lone_surrogate_in_the_answer_is_a_recorded_block_not_an_exception(fake, make_cfg):
    fake.script("nina-test", "Paris \ud800 is the capital.")
    fake.script("igor-test", igor_json("PASS", 92))
    r = Pipeline(make_cfg()).run(TASK)                       # must not raise
    assert r.final["gate_state"] != "PASS" and r.final["nina_status"] == "ERROR", r.final
    assert verify_session(r.session_dir)["failures"] == []


def test_a_surrogate_in_the_judge_reason_is_a_recorded_block_not_an_exception(fake, make_cfg):
    fake.script("nina-test", "Paris is the capital of France.")
    fake.script("igor-test", igor_json("PASS", 92, reason="fine \ud800"))
    r = Pipeline(make_cfg()).run(TASK)
    assert r.final["gate_state"] != "PASS", r.final


def test_a_probable_secret_in_the_answer_is_blocked_and_never_persisted(fake, make_cfg):
    secret = "sk-ant-api03-" + "A" * 30
    fake.script("nina-test", f"The key is {secret}")
    fake.script("igor-test", igor_json("PASS", 92))
    r = Pipeline(make_cfg()).run(TASK)
    assert r.final["gate_state"] != "PASS"
    assert all(secret.encode() not in p.read_bytes() for p in Path(r.session_dir).rglob("*") if p.is_file())


@pytest.mark.parametrize("text", [
    "sk_live_" + "a1B2c3D4e5F6", "rk_live_" + "a1B2c3D4e5F6", "whsec_" + "a1B2c3D4e5F6g7",
    "AIza" + "A" * 35, "eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4fw",
    "https://hooks.slack.com/services/T0000000/B0000000/XXXXXXXXXXXXXXXXXXXX",
    "Authorization: Basic dXNlcjpwYXNzd29yZA==", "postgres://admin:hunter2@db.internal/app",
], ids=["stripe-sk", "stripe-rk", "whsec", "google", "jwt", "slack", "basic", "dsn"])
def test_more_secret_shapes_are_detected(text):
    assert contains_secret(text)


@pytest.mark.parametrize("text", ["bearer authentication is used", "see http://localhost:8080/docs",
                                  "ratio 3:4 at 10:30", "https://example.com/path"])
def test_ordinary_text_is_not_flagged(text):
    assert not contains_secret(text)
