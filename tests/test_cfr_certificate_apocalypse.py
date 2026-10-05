"""Certificate Apocalypse (cfr_scenarios/certificate-apocalypse): the manifest, the metric computation, the certificate
scripts and ONE real run per outcome through the CFR API (signed runner result, server-side scoring).

The services are real local TLS servers and the verification is real (openssl / ssl / curl); what is NOT covered:
containers (docker/k3d), k6, and independent measurement (the runner attests the metrics).
"""
import copy
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import cfr
from app import identity as idn
from app.database import SessionLocal
from app.main import app
from app.models import ApiKey, Tenant

DIR = Path(__file__).resolve().parents[1] / "cfr_scenarios" / "certificate-apocalypse"
sys.path.insert(0, str(DIR))
import cfr_range as rng  # noqa: E402

_spec = importlib.util.spec_from_file_location("ca_score", DIR / "score.py")
sc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sc)

TOOLS = pytest.mark.skipif(not (shutil.which("openssl") and shutil.which("curl")), reason="needs openssl and curl")
C = TestClient(app)
TOKEN = "operator-token"
TOKEN_SHA = hashlib.sha256(TOKEN.encode()).hexdigest()
MANIFEST = json.loads((DIR / "manifest.json").read_text())


# ------------------------------------------------------------------ the manifest
def test_the_manifest_is_valid_and_pins_the_assertions_the_scripts_emit():
    m = cfr.validate_manifest(MANIFEST)
    emitted = set(json.loads(l)["id"] for l in
                  subprocess.run([str(DIR / "assertions.sh")], capture_output=True, text=True,
                                 env={"PATH": "/usr/bin:/bin", "STATE": "/nonexistent"}).stdout.splitlines())
    assert emitted == set(m["required_assertions"]) | set(m["hidden_assertions"]), \
        "the script and the manifest must name exactly the same assertions"
    assert set(m["variants"]) == set(rng.VARIANTS)


def test_perfect_metrics_score_elite_and_a_slow_recovery_scores_less():
    m = cfr.validate_manifest(MANIFEST)
    best = {"availability": 1.0, "latency_p95_ms": 10, "mttr_s": 10, "blast_radius": 0, "restarts": 0, "downtime_s": 0}
    assert cfr.score(m, best)["score"] == 1.0
    slow = {**best, "mttr_s": 160}                                   # halfway between 20 and 300 -> component 0.5
    assert cfr.score(m, slow)["components"]["time_to_recover"] == pytest.approx(0.5, abs=0.01)
    assert cfr.score(m, {**best, "blast_radius": 1})["components"]["blast_radius"] == 0.5
    assert cfr.score(m, {**best, "mttr_s": None})["components"]["time_to_recover"] == 0.0


# ------------------------------------------------------------------ metrics from observations (pure)
def rounds(spec, t0=1000.0, dt=0.2, ms=5.0):
    """spec: list of sets of failing services per round."""
    out = []
    for i, bad in enumerate(spec):
        out.append({"t": t0 + i * dt, "results": {s: {"ok": s not in bad, "ms": ms, "err": ""} for s in rng.SERVICES}})
    return out


def test_metrics_of_a_clean_recovery():
    n_ok_before, n_bad, n_ok_after = 10, 25, 80
    spec = [set()] * n_ok_before + [set(rng.AFFECTED)] * n_bad + [set()] * n_ok_after
    tl = rounds(spec)
    inj = tl[n_ok_before]["t"] - 0.01
    m = rng.compute_metrics(tl, [{"t": inj, "event": "fault_injected"}], stable_s=5)
    assert m["blast_radius"] == 0 and m["restarts"] == 0
    assert m["mttr_s"] == pytest.approx(tl[n_ok_before + n_bad]["t"] - inj, abs=1e-6)
    total = len(spec) * 4
    assert m["availability"] == pytest.approx(1 - n_bad * 2 / total, abs=1e-6)
    assert m["downtime_s"] == pytest.approx(n_bad * 0.2, abs=1e-6)
    assert m["latency_p95_ms"] == 5.0


def test_never_recovered_and_too_short_a_window_give_no_mttr():
    tl = rounds([set()] * 5 + [set(rng.AFFECTED)] * 30)
    assert rng.compute_metrics(tl, [{"t": tl[5]["t"], "event": "fault_injected"}], stable_s=2)["mttr_s"] is None
    tl2 = rounds([set()] * 5 + [set(rng.AFFECTED)] * 5 + [set()] * 10)           # healthy again for only ~1.8 s
    assert rng.compute_metrics(tl2, [{"t": tl2[5]["t"], "event": "fault_injected"}], stable_s=5)["mttr_s"] is None
    assert rng.compute_metrics(tl2, [{"t": tl2[5]["t"], "event": "fault_injected"}], stable_s=1)["mttr_s"] is not None


def test_a_flap_resets_the_stable_window():
    spec = [set()] * 3 + [set(rng.AFFECTED)] * 5 + [set()] * 20 + [{"api"}] + [set()] * 60
    tl = rounds(spec)
    m = rng.compute_metrics(tl, [{"t": tl[3]["t"], "event": "fault_injected"}], stable_s=8)
    assert m["mttr_s"] == pytest.approx(tl[3 + 5 + 20 + 1]["t"] - tl[3]["t"], abs=1e-6), \
        "recovery counts from the start of the window that finally held, not from the first healthy round"


def test_collateral_damage_is_blast_radius_and_restarts_are_counted():
    spec = [set()] * 3 + [set(rng.AFFECTED) | {"static"}] * 4 + [set()] * 60
    tl = rounds(spec)
    ev = [{"t": tl[3]["t"], "event": "fault_injected"}, {"t": tl[8]["t"], "event": "restart"},
          {"t": tl[9]["t"], "event": "restart"}]
    m = rng.compute_metrics(tl, ev, stable_s=5)
    assert m["blast_radius"] == 1 and m["restarts"] == 2
    assert rng.compute_metrics(tl, [{"t": 1.0, "event": "up"}], stable_s=5) is None, "no injected fault, nothing to score"
    assert rng.compute_metrics(tl[:1], ev, stable_s=5) is None, "one round is not a measurement"
    assert rng.compute_metrics([{"t": 1, "results": {"api": {"ok": True, "ms": 1}}}] * 3, ev) is None, "missing services"


def test_the_earliest_injection_defines_the_start_of_the_incident():
    tl = rounds([set()] * 3 + [set(rng.AFFECTED)] * 10 + [set()] * 60)
    ev = [{"t": tl[8]["t"], "event": "fault_injected"}, {"t": tl[3]["t"], "event": "fault_injected"}]
    m = rng.compute_metrics(tl, ev, stable_s=5)
    assert m["mttr_s"] == pytest.approx(tl[13]["t"] - tl[3]["t"], abs=1e-6)


def test_p95_of_nothing_and_of_some():
    assert rng._p95([]) == 0.0
    assert rng._p95(list(map(float, range(1, 101)))) == 95.0


# ------------------------------------------------------------------ certificate scripts
def run_sh(name, cert_dir, host, *args):
    return subprocess.run([str(DIR / "scripts" / name), *args], capture_output=True, text=True,
                          env={"PATH": "/usr/bin:/bin", "CERT_DIR": str(cert_dir), "HOST": host})


def openssl_verify(cert_dir, host):
    pem = (cert_dir / "server.pem").read_text()
    crt = pem[pem.index("-----BEGIN CERTIFICATE-----"):]
    (cert_dir / "leaf.crt").write_text(crt)
    r = subprocess.run(["openssl", "verify", "-CAfile", str(cert_dir / "ca.crt"), "-verify_hostname", host,
                        str(cert_dir / "leaf.crt")], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


@TOOLS
def test_good_and_bad_certificates_fail_in_the_way_their_variant_says(tmp_path):
    host = "svc-abc123.range.test"
    assert run_sh("gen_good_cert.sh", tmp_path, host).returncode == 0
    ca_before = (tmp_path / "ca.crt").read_bytes()
    assert openssl_verify(tmp_path, host)[0] == 0
    expect = {"expired": "has expired", "untrusted-chain": "self-signed", "wrong-san": "Hostname mismatch"}
    for variant, needle in expect.items():
        assert run_sh("gen_bad_cert.sh", tmp_path, host, variant).returncode == 0, variant
        rc, out = openssl_verify(tmp_path, host)
        assert rc != 0 and needle.lower() in out.lower(), (variant, out)
    assert run_sh("gen_good_cert.sh", tmp_path, host).returncode == 0
    assert openssl_verify(tmp_path, host)[0] == 0, "the good script repairs every variant"
    assert (tmp_path / "ca.crt").read_bytes() == ca_before, "fixing must not replace the CA"
    assert run_sh("gen_bad_cert.sh", tmp_path, host, "nonsense").returncode == 2
    assert run_sh("gen_bad_cert.sh", tmp_path / "empty", host, "expired").returncode != 0, "no CA -> refuses"


@TOOLS
def test_a_certificate_for_another_host_does_not_fix_the_run(tmp_path):
    """The host name derives from the per-run seed: a fix copied from another run (other name) cannot pass."""
    assert rng.host_for("aaaaaa111") != rng.host_for("bbbbbb222")
    assert run_sh("gen_good_cert.sh", tmp_path, rng.host_for("aaaaaa111")).returncode == 0
    assert openssl_verify(tmp_path, rng.host_for("bbbbbb222"))[0] != 0


# ------------------------------------------------------------------ real runs through the API
def make_tenant():
    tid, key = str(uuid.uuid4()), "ca-" + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(Tenant(id=tid, name="ca"))
        db.add(ApiKey(id=str(uuid.uuid4()), tenant_id=tid, key_hash=hashlib.sha256(key.encode()).hexdigest()))
        db.commit()
    return tid, key


@pytest.fixture
def world(monkeypatch, tmp_path):
    monkeypatch.setenv("OLA_CFR_SEED_SECRET", "a-long-enough-server-secret")
    monkeypatch.setenv("OLA_IDENTITY_ENROLL_TOKEN_SHA256", TOKEN_SHA)
    for v in ("OLA_CFR_RUN_TTL_S", "OLA_IDENTITY_MAX_SKEW_S", "OLA_FIREWALL_AGENT_AUTH"):
        monkeypatch.delenv(v, raising=False)
    tid, key = make_tenant()
    api = sc.Api(C, key)
    seed, pub = idn.generate_keypair()
    r = C.post("/identity/enroll", headers={"X-API-Key": key, "X-Enroll-Token": TOKEN},
               json={"principal_id": "runner-1", "role": "runner", "public_key": pub})
    assert r.status_code == 200, r.text
    sc.register(api, TOKEN)
    state = tmp_path / "state"
    run = sc.issue(api, state, "alice")
    yield {"tid": tid, "key": key, "api": api, "seed": seed, "state": state, "run": run}
    subprocess.run([sys.executable, str(DIR / "cfr_range.py"), "--state", str(state), "down"], capture_output=True)


def cli(state, *args):
    return subprocess.run([sys.executable, str(DIR / "cfr_range.py"), "--state", str(state), *args],
                          capture_output=True, text=True)


def fix(state, host):
    return subprocess.run([str(DIR / "scripts" / "gen_good_cert.sh")], capture_output=True, text=True,
                          env={"PATH": "/usr/bin:/bin", "CERT_DIR": str(state / "certs"), "HOST": host})


def begin(w, variant=None):
    assert cli(w["state"], "up").returncode == 0
    host = rng.host_for(w["run"]["seed"])
    time.sleep(1.5)
    extra = ["--variant", variant] if variant else []              # default: the variant of the server-issued run
    assert cli(w["state"], "break", *extra).returncode == 0
    time.sleep(2.0)
    return host


def finish(w, stable_s):
    sub = sc.build_submission(w["state"], stable_s)
    assert sub is not None
    return sub, sc.submit(w["api"], w["tid"], "runner-1", w["seed"], sub)


@TOOLS
def test_a_fixed_run_is_scored_by_the_server_and_ranks(world):
    w = world
    host = begin(w)
    assert fix(w["state"], host).returncode == 0
    time.sleep(11.5)                                                  # the stable window is 10 s
    sub, r = finish(w, rng.STABLE_S)
    assert r.status_code == 200, r.text
    res = r.json()
    assert {a["id"]: a["result"] for a in sub["assertions"]} == {i: "pass" for i in (
        "tls_handshake_ok", "x509_not_expired", "x509_chain_ok", "health_stable_10s", "san_matches_host", "ca_untouched")}
    assert res["state"] == "PASS" and res["tier"] in ("pass", "merit", "elite") and res["score"] > 0.5, res
    assert res["components"]["blast_radius"] == 1.0, "nothing outside the broken certificate was touched"
    assert sub["metrics"]["mttr_s"] is not None and sub["metrics"]["blast_radius"] == 0
    lb = C.get(f"/cfr/leaderboard/{MANIFEST['scenario_id']}", headers={"X-API-Key": w["key"]}).json()
    assert [row["participant_id"] for row in lb["ranking"]] == ["alice"]
    # the runner's own preview agrees with the server (same code), and is labelled as a preview
    assert sc.preview(sub)["score"] == res["score"]


@TOOLS
def test_an_unfixed_run_fails_and_never_ranks(world):
    w = world
    begin(w)
    sub, r = finish(w, 3)
    assert r.status_code == 200, r.text
    res = r.json()
    assert res["state"] == "FAIL" and res["tier"] == "none", res
    assert sub["metrics"]["mttr_s"] is None
    broken = {a["id"] for a in sub["assertions"] if a["result"] == "fail"}
    assert broken, "at least the assertion of the injected variant must fail"
    lb = C.get(f"/cfr/leaderboard/{MANIFEST['scenario_id']}", headers={"X-API-Key": w["key"]}).json()
    assert lb["ranking"] == []


@TOOLS
def test_replacing_the_ca_is_collateral_damage_and_caught_by_the_hidden_assertion(world):
    """The tempting fix - throw the certificates away and start over - heals api/billing and breaks static/admin."""
    w = world
    host = begin(w)
    (w["state"] / "certs" / "ca.key").unlink()
    (w["state"] / "certs" / "ca.crt").unlink()
    assert fix(w["state"], host).returncode == 0                      # creates a NEW CA and a leaf signed by it
    time.sleep(3.0)
    sub, r = finish(w, 2)
    got = {a["id"]: a["result"] for a in sub["assertions"]}
    assert got["ca_untouched"] == "fail", got
    assert sub["metrics"]["blast_radius"] == 2, sub["metrics"]
    assert r.json()["state"] == "FAIL" and r.json()["tier"] == "none", r.text


@TOOLS
@pytest.mark.parametrize("variant,failing", [("expired", {"x509_not_expired"}), ("untrusted-chain", {"x509_chain_ok"}),
                                             ("wrong-san", {"san_matches_host"})])
def test_each_variant_breaks_its_own_assertion_and_only_that_one(world, variant, failing):
    w = world
    begin(w, variant)
    got = {a["id"]: a["result"] for a in sc.collect_assertions(w["state"], rng.host_for(w["run"]["seed"]), 3)}
    assert {k for k, v in got.items() if v == "fail"} == failing | {"health_stable_10s"}, got
    assert got["tls_handshake_ok"] == "pass" and got["ca_untouched"] == "pass"


# ------------------------------------------------------------------ independent measurement (witness)
_wspec = importlib.util.spec_from_file_location("ca_witness", DIR / "witness.py")
wit = importlib.util.module_from_spec(_wspec)
_wspec.loader.exec_module(wit)


def test_the_manifest_asks_to_confirm_exactly_what_a_witness_can_check():
    im = cfr.validate_manifest(MANIFEST)["independent_measurement"]
    assert set(im["confirm_assertions"]) <= set(MANIFEST["required_assertions"])
    assert "ca_untouched" not in im["confirm_assertions"], "hidden assertions are not part of the public confirm list"
    assert im["required"] is False, "local-process mode cannot isolate the witness from the participant: not required here"


def test_witness_metrics_start_at_the_first_failure_it_saw_and_ignore_the_range_log():
    tl = rounds([set()] * 5 + [{"api", "billing"}] * 10 + [set()] * 30)
    m = wit.compute_witness_metrics(tl, stable_s=5)
    assert set(m) == set(wit.WITNESS_METRICS) and m["mttr_s"] == pytest.approx(10 * 0.2, abs=0.01)
    assert m["availability"] == pytest.approx(1 - (10 * 2) / (45 * 4), abs=1e-6)
    assert wit.compute_witness_metrics(rounds([set()] * 20), stable_s=5) is None, "no failure seen, nothing to measure"
    assert wit.compute_witness_metrics(rounds([{"api"}]), stable_s=5) is None, "one round is not a measurement"
    never = wit.compute_witness_metrics(rounds([set()] * 3 + [{"api"}] * 20), stable_s=5)
    assert never["mttr_s"] is None


def test_stable_now_needs_a_covered_window_and_only_healthy_rounds():
    assert wit.stable_now(rounds([set()] * 100), 10) == "pass"
    assert wit.stable_now(rounds([set()] * 20), 10) == "unknown", "4 s of observation do not cover a 10 s window"
    assert wit.stable_now(rounds([set()] * 99 + [{"admin"}]), 10) == "fail"
    assert wit.stable_now(rounds([{"admin"}] + [set()] * 99), 10) == "pass", "a failure before the window does not count"
    assert wit.stable_now([], 10) == "unknown"


@pytest.fixture
def wworld(world, tmp_path):
    w = dict(world)
    w["wstate"] = tmp_path / "state-witness"
    w["wseed"], wpub = idn.generate_keypair()
    r = C.post("/identity/enroll", headers={"X-API-Key": w["key"], "X-Enroll-Token": TOKEN},
               json={"principal_id": "witness-1", "role": "witness", "public_key": wpub})
    assert r.status_code == 200, r.text
    yield w
    subprocess.run([sys.executable, str(DIR / "witness.py"), "--state", str(w["wstate"]), "--range-state", str(w["state"]),
                    "down"], capture_output=True)


def wcli(w, *args):
    return subprocess.run([sys.executable, str(DIR / "witness.py"), "--state", str(w["wstate"]), "--range-state",
                           str(w["state"]), *args], capture_output=True, text=True)


def begin_witnessed(w, variant=None):
    assert cli(w["state"], "up").returncode == 0
    r = wcli(w, "up")
    assert r.returncode == 0, r.stderr
    host = rng.host_for(w["run"]["seed"])
    time.sleep(1.5)
    extra = ["--variant", variant] if variant else []
    assert cli(w["state"], "break", *extra).returncode == 0
    time.sleep(2.0)
    return host


def witness_posts(w, stable_s):
    obs = wit.build_observation(w["wstate"], w["state"], stable_s)
    assert obs is not None
    return obs, wit.sign_and_post(w["api"], w["tid"], "witness-1", w["wseed"], obs)


@TOOLS
def test_an_honest_run_is_confirmed_by_an_independent_observer(wworld):
    w = wworld
    host = begin_witnessed(w)
    assert fix(w["state"], host).returncode == 0
    time.sleep(5.5)
    sub, r = finish(w, 3)
    assert r.status_code == 200 and r.json()["state"] == "PASS" and r.json()["measurement"]["status"] == "UNWITNESSED", r.text
    obs, wr = witness_posts(w, 3)
    assert wr.status_code == 200, wr.text
    assert wr.json()["measurement"] == "CONFIRMED", wr.text
    res = C.get(f"/cfr/results/{w['run']['run_id']}", headers={"X-API-Key": w["key"]}).json()
    assert res["state"] == "PASS" and res["measurement"]["witnesses"] == ["witness-1"], res
    assert res["score"] <= res["runner_claim"]["score"], "a witness never raises the score"
    assert {a["id"]: a["result"] for a in obs["assertions"]}["health_stable_10s"] in ("pass", "unknown")
    lb = C.get(f"/cfr/leaderboard/{MANIFEST['scenario_id']}", headers={"X-API-Key": w["key"]}).json()
    assert [(x["participant_id"], x["measurement"]) for x in lb["ranking"]] == [("alice", "CONFIRMED")]


@TOOLS
def test_a_runner_that_claims_a_fix_nobody_made_is_disputed_by_the_witness(wworld):
    """The participant never fixed the certificate; the (lying) runner signs a perfect result. The witness saw failures."""
    w = wworld
    begin_witnessed(w)
    time.sleep(3.0)
    now = time.time()
    claim = {"run_id": w["run"]["run_id"], "manifest_sha256": w["run"]["manifest_sha256"], "started_at": now - 20,
             "ended_at": now - 1,
             "metrics": {"availability": 1.0, "latency_p95_ms": 10, "mttr_s": 2.0, "blast_radius": 0, "restarts": 0,
                         "downtime_s": 0},
             "assertions": [{"id": i, "result": "pass"} for i in (
                 "tls_handshake_ok", "x509_not_expired", "x509_chain_ok", "health_stable_10s", "san_matches_host",
                 "ca_untouched")],
             "artifacts": {}}
    r = sc.submit(w["api"], w["tid"], "runner-1", w["seed"], claim)
    assert r.status_code == 200 and r.json()["state"] == "PASS", "on the runner's word alone it passes"
    obs, wr = witness_posts(w, 3)
    assert wr.status_code == 200 and wr.json()["measurement"] == "CONTRADICTED", wr.text
    res = C.get(f"/cfr/results/{w['run']['run_id']}", headers={"X-API-Key": w["key"]}).json()
    assert res["state"] == "DISPUTED" and res["tier"] == "none" and res["runner_claim"]["state"] == "PASS", res
    assert res["score"] < res["runner_claim"]["score"]
    assert any("availability" in x or "mttr_s" in x for x in res["measurement"]["reasons"]), res["measurement"]
    seen = {a["id"]: a["result"] for a in obs["assertions"]}
    # which verification assertion trips depends on the per-run variant (expired / SAN / chain); some one always does
    assert "fail" in (seen["x509_not_expired"], seen["x509_chain_ok"], seen["san_matches_host"]), seen
    assert seen["health_stable_10s"] == "fail", seen
    lb = C.get(f"/cfr/leaderboard/{MANIFEST['scenario_id']}", headers={"X-API-Key": w["key"]}).json()
    assert lb["ranking"] == []


@TOOLS
def test_the_witness_pins_the_ca_when_it_starts_and_observes_nothing_before_an_incident(wworld):
    w = wworld
    assert cli(w["state"], "up").returncode == 0
    assert wcli(w, "up").returncode == 0
    pinned = hashlib.sha256((w["wstate"] / "ca.crt").read_bytes()).hexdigest()
    assert pinned == hashlib.sha256((w["state"] / "certs" / "ca.crt").read_bytes()).hexdigest()
    time.sleep(2.0)
    r = wcli(w, "observe")
    assert r.returncode == 3 and "UNKNOWN" in r.stdout, "healthy so far: nothing to observe"
    assert wcli(w, "up").returncode == 1, "a second witness daemon is refused"
    host = rng.host_for(w["run"]["seed"])
    assert cli(w["state"], "break").returncode == 0
    time.sleep(1.5)
    (w["state"] / "certs" / "ca.key").unlink()
    (w["state"] / "certs" / "ca.crt").unlink()
    assert fix(w["state"], host).returncode == 0                      # a NEW CA now sits in the range's state
    assert hashlib.sha256((w["wstate"] / "ca.crt").read_bytes()).hexdigest() == pinned, "the witness trust anchor is its own"
    time.sleep(2.0)
    obs = wit.build_observation(w["wstate"], w["state"], 3)
    assert obs is not None
    got = {a["id"]: a["result"] for a in obs["assertions"]}
    # The witness trusts the OLD CA. static/admin were never re-signed, so they still verify (the unaffected control);
    # the regenerated api/billing certificates chain to a CA the witness never pinned, so it sees them as untrusted.
    assert got["x509_chain_ok"] == "fail", "a replaced CA must not make the broken services look healthy: " + str(got)
    assert got["ca_untouched"] == "pass", got
    assert obs["artifacts"]["pinned_ca"] == pinned


def test_the_witness_needs_a_running_range_and_an_issued_run(tmp_path):
    r = subprocess.run([sys.executable, str(DIR / "witness.py"), "--state", str(tmp_path / "w"), "--range-state",
                        str(tmp_path / "nothing"), "up"], capture_output=True, text=True)
    assert r.returncode == 2 and "must be up" in r.stderr


# ------------------------------------------------------------------ findings of the independent review
def test_one_failed_probe_before_the_fault_is_a_blip_not_an_incident():
    """A single failed round (a loaded host, a 2 s probe timeout) must not become the incident start: MTTR would collapse."""
    tl = rounds([set()] * 5 + [{"api"}] + [set()] * 20 + [{"api", "billing"}] * 400 + [set()] * 60)
    m = wit.compute_witness_metrics(tl, stable_s=5)
    assert m["mttr_s"] == pytest.approx(400 * 0.2, abs=0.5), "the outage is 80 s, not the blip's 0.2 s"
    assert wit.compute_witness_metrics(rounds([set()] * 5 + [{"api"}] + [set()] * 50), stable_s=5) is None
    assert wit.compute_witness_metrics(rounds([set()] * 5 + [{"api"}, {"api"}] + [set()] * 50), stable_s=5) is None
    assert wit.compute_witness_metrics(rounds([set()] * 5 + [{"api"}] * wit.MIN_INCIDENT_ROUNDS + [set()] * 50),
                                       stable_s=5) is not None


def test_a_timeline_that_stopped_growing_is_not_a_pass():
    tl = rounds([set()] * 100)
    last = tl[-1]["t"]
    assert wit.stable_now(tl, 10) == "pass", "without `now` the pure check is unchanged"
    assert wit.stable_now(tl, 10, now=last + 1.0) == "pass"
    assert wit.stable_now(tl, 10, now=last + wit.STALE_S + 1) == "unknown", "the observer may be dead: no pass from old data"


def test_the_witness_that_never_came_up_does_not_block_the_next_up(tmp_path):
    state = tmp_path / "range"
    (state / "certs").mkdir(parents=True)
    (state / "certs" / "ca.crt").write_text("x")
    (state / "run.json").write_text("not json")                      # the daemon dies on start
    ws = tmp_path / "w"
    r = subprocess.run([sys.executable, str(DIR / "witness.py"), "--state", str(ws), "--range-state", str(state), "up"],
                       capture_output=True, text=True)
    assert r.returncode == 1 and "did not become ready" in r.stderr
    assert not (ws / "witness.pid").exists(), "a stale pid file would make every later `up` say 'already running'"


def test_submit_names_the_missing_environment(tmp_path, monkeypatch):
    env = {k: v for k, v in __import__("os").environ.items() if not k.startswith("OLA_")}
    env.update(OLA_URL="http://127.0.0.1:1", OLA_API_KEY="k")
    r = subprocess.run([sys.executable, str(DIR / "witness.py"), "--state", str(tmp_path), "--range-state", str(tmp_path),
                        "submit"], capture_output=True, text=True, env=env)
    assert r.returncode == 2 and "OLA_TENANT_ID" in r.stderr and "OLA_WITNESS_SEED" in r.stderr


@TOOLS
def test_a_witness_refuses_to_pin_a_ca_that_was_replaced_before_it_started(wworld):
    w = wworld
    assert cli(w["state"], "up").returncode == 0
    up = [e for e in rng.read_lines(w["state"] / "events.jsonl") if e.get("event") == "up"][-1]
    assert up["ca_sha256"] == hashlib.sha256((w["state"] / "certs" / "ca.crt").read_bytes()).hexdigest()
    host = rng.host_for(w["run"]["seed"])
    assert cli(w["state"], "break").returncode == 0
    (w["state"] / "certs" / "ca.key").unlink()
    (w["state"] / "certs" / "ca.crt").unlink()
    assert fix(w["state"], host).returncode == 0                      # the participant's "fix": a brand new CA
    r = wcli(w, "up")
    assert r.returncode == 2 and "replaced before the witness started" in r.stderr, (r.returncode, r.stderr)
    assert not (w["wstate"] / "witness.pid").exists() and not (w["wstate"] / "ca.crt").exists()
