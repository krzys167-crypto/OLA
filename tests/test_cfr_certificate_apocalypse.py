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
