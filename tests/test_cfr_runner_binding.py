"""A run is bound to the runner it was issued for (second security review, item 12)."""
import copy
import hashlib
import json
import time
import uuid

import pytest
from fastapi.testclient import TestClient

from app import cfr, identity as idn, pipeline_bridge as pb
from app.database import SessionLocal
from app.main import app
from app.models import ApiKey, Tenant

C = TestClient(app, raise_server_exceptions=False)
TOKEN = "operator-token-bind"
MANIFEST = {
    "scenario_id": "cfr-14", "version": "1", "required_assertions": ["tls_handshake_ok", "x509_chain_ok"],
    "hidden_assertions": ["HIDDEN-001"], "variants": ["expired_leaf"],
    "scoring": {"weights": {"availability": 0.35, "latency": 0.2, "time_to_recover": 0.3, "blast_radius": 0.15},
                "limits": {"availability_zero": 0.9, "latency_p95_ms_full": 200, "latency_p95_ms_zero": 2000,
                           "mttr_s_full": 60, "mttr_s_zero": 900, "blast_radius_full": 1, "blast_radius_zero": 6},
                "penalties": {"per_restart": 0.02, "max_restarts_penalty": 0.1, "downtime_over_s": 60,
                              "downtime_penalty": 0.1},
                "tiers": {"pass": 0.6, "merit": 0.8, "elite": 0.92}}}
PERFECT = {"availability": 1.0, "latency_p95_ms": 150, "mttr_s": 30, "blast_radius": 1, "restarts": 0, "downtime_s": 0}


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.delenv("OLA_FIREWALL_AGENT_AUTH", raising=False)
    monkeypatch.setenv("OLA_IDENTITY_ENROLL_TOKEN_SHA256", hashlib.sha256(TOKEN.encode()).hexdigest())
    monkeypatch.setenv("OLA_CFR_SEED_SECRET", "a-long-enough-server-secret")


def post(path, key, **body):
    return C.post(path, headers={"X-API-Key": key, "X-Enroll-Token": TOKEN}, json=body)


class Runner:
    def __init__(self, tenant, rid, role="runner"):
        self.tid, self.key, self.rid = tenant[0], tenant[1], rid
        self.seed, self.pub = idn.generate_keypair()
        r = post("/identity/enroll", self.key, principal_id=rid, role=role, public_key=self.pub)
        assert r.status_code == 200, r.text


@pytest.fixture
def world():
    tid, key = str(uuid.uuid4()), "bind-" + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(Tenant(id=tid, name="bind"))
        db.add(ApiKey(id=str(uuid.uuid4()), tenant_id=tid, key_hash=hashlib.sha256(key.encode()).hexdigest()))
        db.commit()
    assert post("/cfr/scenarios", key, manifest=MANIFEST).status_code == 200
    return tid, key


def issue(world, runner_id=None, participant="alice"):
    body = {"scenario_id": "cfr-14", "participant_id": participant}
    if runner_id is not None:
        body["runner_id"] = runner_id
    return post("/cfr/runs", world[1], **body)


def submit(world, runner, run, metrics=None, results="pass"):
    now = time.time()
    sub = {"run_id": run["run_id"], "manifest_sha256": run["manifest_sha256"], "started_at": now - 120,
           "ended_at": now - 5, "metrics": copy.deepcopy(metrics or PERFECT),
           "assertions": [{"id": a, "result": results} for a in ("tls_handshake_ok", "x509_chain_ok", "HIDDEN-001")],
           "artifacts": {"final_json": "ab" * 32}}
    body = dict(sub)
    body["auth"] = cfr.sign_result(runner.seed, runner.tid, runner.rid, sub)
    return post("/cfr/results", world[1], **body)


def test_a_bound_run_records_its_runner_and_only_that_runner_can_report(world):
    a, b = Runner(world, "runner-a"), Runner(world, "runner-b")
    r = issue(world, "runner-a")
    assert r.status_code == 200 and r.json()["runner_id"] == "runner-a"
    run = r.json()
    rec = [json.loads(x["payload_json"]) for x in pb.load_chain(world[0]) if x["record_type"] == "cfr.run"][0]
    assert rec["runner_id"] == "runner-a"                                       # the binding is in the chain
    r = submit(world, b, run)
    assert r.status_code == 401 and "bound" in r.text
    assert not [x for x in pb.load_chain(world[0]) if x["record_type"] == "cfr.result"]
    r = submit(world, a, run)
    assert r.status_code == 200 and r.json()["state"] == "PASS"


def test_another_runner_cannot_lock_the_real_runner_out_with_a_fail(world):
    a, b = Runner(world, "runner-a"), Runner(world, "runner-b")
    run = issue(world, "runner-a").json()
    assert submit(world, b, run, metrics={**PERFECT, "availability": 0.0}, results="fail").status_code == 401
    assert submit(world, a, run).status_code == 200                              # no 409: nothing was first


@pytest.mark.parametrize("who", ["nobody", "witness-1", "runner-gone", "bad id!", 7, ["x"], {"a": 1}, "runner-a\n"])
def test_the_runner_must_be_an_active_enrolled_runner(world, who):
    Runner(world, "witness-1", role="witness")
    Runner(world, "runner-gone")
    assert post("/identity/revoke", world[1], principal_id="runner-gone", reason="left").status_code == 200
    assert issue(world, who).status_code == 400


def test_unbound_runs_stay_possible_when_signatures_are_not_required(world):
    a = Runner(world, "runner-a")
    run = issue(world).json()
    assert run["runner_id"] is None
    assert submit(world, a, run).status_code == 200


def test_required_mode_demands_a_runner_when_issuing(world, monkeypatch):
    Runner(world, "runner-a")
    monkeypatch.setenv("OLA_FIREWALL_AGENT_AUTH", "required")
    r = issue(world)
    assert r.status_code == 400 and "runner_id" in r.text
    assert issue(world, "runner-a").status_code == 200


def test_required_mode_refuses_a_result_for_a_run_that_was_never_bound(world, monkeypatch):
    a = Runner(world, "runner-a")
    run = issue(world).json()                                                    # issued while signatures were optional
    monkeypatch.setenv("OLA_FIREWALL_AGENT_AUTH", "required")
    r = submit(world, a, run)
    assert r.status_code == 409 and "bound" in r.text


def test_a_witness_is_not_bound_to_the_runner(world):
    Runner(world, "runner-a")
    w = Runner(world, "witness-1", role="witness")
    run = issue(world, "runner-a").json()
    now = time.time()
    obs = {"run_id": run["run_id"], "manifest_sha256": run["manifest_sha256"], "observed_from": now - 120,
           "observed_until": now - 5,
           "metrics": {"availability": 1.0, "latency_p95_ms": 150, "mttr_s": 30, "downtime_s": 0},
           "assertions": [{"id": "tls_handshake_ok", "result": "pass"}], "artifacts": {}}
    body = dict(obs)
    body["auth"] = cfr.sign_witness(w.seed, w.tid, w.rid, obs)
    r = post("/cfr/witness", world[1], **body)
    assert r.status_code == 200, r.text                                          # witnesses are independent of the binding
