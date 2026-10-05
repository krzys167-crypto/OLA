"""CFR independent measurement (witness): a second signer measures the run and the server cross-checks the runner.

What these tests pin: a witness can only LOWER what the runner claimed (state, tier, score), a contradiction is DISPUTED
and never ranks, a manifest that requires independent measurement never passes without a CONFIRMED reconciliation, the
witness key is never the runner key, and manifests without the new block keep the digest they always had."""
import copy
import hashlib
import json
import random
import time
import uuid

import pytest
from fastapi.testclient import TestClient

from app import cfr
from app import identity as idn
from app import pipeline_bridge as pb
from app.database import SessionLocal
from app.main import app
from app.models import ApiKey, Tenant

C = TestClient(app)
TOKEN = "operator-token"
TOKEN_SHA = hashlib.sha256(TOKEN.encode()).hexdigest()

REQ = ["tls_handshake_ok", "x509_chain_ok", "health_stable_60s"]
MANIFEST = {
    "scenario_id": "cfr-14", "version": "1",
    "required_assertions": REQ, "hidden_assertions": ["HIDDEN-001"],
    "variants": ["expired_leaf", "wrong_chain"],
    "scoring": {
        "weights": {"availability": 0.35, "latency": 0.2, "time_to_recover": 0.3, "blast_radius": 0.15},
        "limits": {"availability_zero": 0.9, "latency_p95_ms_full": 200, "latency_p95_ms_zero": 2000,
                   "mttr_s_full": 60, "mttr_s_zero": 900, "blast_radius_full": 1, "blast_radius_zero": 6},
        "penalties": {"per_restart": 0.02, "max_restarts_penalty": 0.1, "downtime_over_s": 60, "downtime_penalty": 0.1},
        "tiers": {"pass": 0.6, "merit": 0.8, "elite": 0.92},
    },
}
IM = {"required": True, "confirm_assertions": ["tls_handshake_ok", "x509_chain_ok"],
      "tolerance": {"availability": 0.05, "latency_p95_rel": 0.5, "mttr_s": 10.0, "downtime_s": 10.0}}
REQUIRED_MANIFEST = {**MANIFEST, "scenario_id": "cfr-req", "independent_measurement": IM}
OPTIONAL_MANIFEST = {**MANIFEST, "scenario_id": "cfr-opt", "independent_measurement": {**IM, "required": False}}

PERFECT = {"availability": 1.0, "latency_p95_ms": 150, "mttr_s": 30, "blast_radius": 1, "restarts": 0, "downtime_s": 0}
SEEN = {"availability": 1.0, "latency_p95_ms": 150, "mttr_s": 30, "downtime_s": 0}          # what a witness can see
ALL_PASS = [{"id": a, "result": "pass"} for a in REQ + ["HIDDEN-001"]]
WITNESSED = [{"id": a, "result": "pass"} for a in ("tls_handshake_ok", "x509_chain_ok", "HIDDEN-001")]


def make_tenant():
    tid, key = str(uuid.uuid4()), "cfr-" + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(Tenant(id=tid, name="cfr"))
        db.add(ApiKey(id=str(uuid.uuid4()), tenant_id=tid, key_hash=hashlib.sha256(key.encode()).hexdigest()))
        db.commit()
    return tid, key


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("OLA_CFR_SEED_SECRET", "a-long-enough-server-secret")
    monkeypatch.setenv("OLA_IDENTITY_ENROLL_TOKEN_SHA256", TOKEN_SHA)
    for v in ("OLA_CFR_RUN_TTL_S", "OLA_IDENTITY_MAX_SKEW_S", "OLA_FIREWALL_AGENT_AUTH"):
        monkeypatch.delenv(v, raising=False)


def post(path, key, token=None, **body):
    h = {"X-API-Key": key}
    if token:
        h["X-Enroll-Token"] = token
    return C.post(path, headers=h, json=body)


def get(path, key):
    return C.get(path, headers={"X-API-Key": key})


def types(tid):
    return [r["record_type"] for r in pb.load_chain(tid)]


class P:
    """A principal with its own key."""
    def __init__(self, tenant, pid, role, enroll=True):
        self.tid, self.key, self.pid = tenant[0], tenant[1], pid
        self.seed, self.pub = idn.generate_keypair()
        if enroll:
            r = post("/identity/enroll", self.key, TOKEN, principal_id=pid, role=role, public_key=self.pub)
            assert r.status_code == 200, r.text


@pytest.fixture
def world():
    tenant = make_tenant()
    for m in (MANIFEST, REQUIRED_MANIFEST, OPTIONAL_MANIFEST):
        assert post("/cfr/scenarios", tenant[1], TOKEN, manifest=m).status_code == 200
    return tenant, P(tenant, "runner-1", "runner"), P(tenant, "witness-1", "witness")


def run_of(tenant, scenario="cfr-14", participant="alice"):
    r = post("/cfr/runs", tenant[1], scenario_id=scenario, participant_id=participant)
    assert r.status_code == 200, r.text
    return r.json()


def result_sub(run, metrics=PERFECT, assertions=ALL_PASS, **over):
    now = time.time()
    s = {"run_id": run["run_id"], "manifest_sha256": run["manifest_sha256"], "started_at": now - 120, "ended_at": now - 5,
         "metrics": copy.deepcopy(metrics), "assertions": copy.deepcopy(assertions), "artifacts": {"final_json": "ab" * 32}}
    s.update(over)
    return s


def obs(run, metrics=SEEN, assertions=WITNESSED, **over):
    now = time.time()
    o = {"run_id": run["run_id"], "manifest_sha256": run["manifest_sha256"], "observed_from": now - 120,
         "observed_until": now - 5, "metrics": copy.deepcopy(metrics), "assertions": copy.deepcopy(assertions),
         "artifacts": {"probe_log": "cd" * 32}}
    o.update(over)
    return o


def runner_submits(runner, sub, **kw):
    body = dict(sub)
    body["auth"] = cfr.sign_result(runner.seed, runner.tid, runner.pid, sub, **kw)
    return post("/cfr/results", runner.key, **body)


def witness_submits(w, o, auth="auto", **kw):
    body = dict(o)
    if auth == "auto":
        auth = cfr.sign_witness(w.seed, w.tid, w.pid, o, **kw)
    if auth is not None:
        body["auth"] = auth
    return post("/cfr/witness", w.key, **body)


def outcome(tenant, run):
    return get(f"/cfr/results/{run['run_id']}", tenant[1]).json()


def board(tenant, scenario):
    return get(f"/cfr/leaderboard/{scenario}", tenant[1]).json()["ranking"]


# ------------------------------------------------------------------ agreement and order
def test_a_confirming_witness_changes_nothing_but_the_label(world):
    tenant, runner, w = world
    run = run_of(tenant, "cfr-req")
    assert runner_submits(runner, result_sub(run)).status_code == 200
    r = witness_submits(w, obs(run))
    assert r.status_code == 200, r.text
    assert r.json()["measurement"] == "CONFIRMED" and r.json()["witnesses"] == 1
    b = outcome(tenant, run)
    assert b["state"] == "PASS" and b["score"] == 1.0 and b["tier"] == "elite"
    assert b["measurement"]["status"] == "CONFIRMED" and b["measurement"]["witnesses"] == ["witness-1"]
    assert b["runner_claim"] == {"score": 1.0, "state": "PASS", "tier": "elite"}
    assert "witnesses agree" in b["note"]
    assert [(x["participant_id"], x["measurement"]) for x in board(tenant, "cfr-req")] == [("alice", "CONFIRMED")]


def test_order_does_not_matter_and_the_record_is_digest_bound(world):
    tenant, runner, w = world
    run = run_of(tenant, "cfr-req")
    r = witness_submits(w, obs(run))                                   # the witness is first: no result yet
    assert r.status_code == 200 and r.json()["measurement"] == "AWAITING_RESULT"
    assert outcome(tenant, run)["state"] == "PENDING"
    assert runner_submits(runner, result_sub(run)).status_code == 200
    assert outcome(tenant, run)["measurement"]["status"] == "CONFIRMED"
    rec = [x for x in pb.load_chain(tenant[0]) if x["record_type"] == "cfr.witness"][0]
    p = json.loads(rec["payload_json"])
    assert p["identity"] == "verified" and p["auth"]["principal_id"] == "witness-1" and p["auth"]["role"] == "witness"
    assert p["observation_sha256"] == cfr.witness_subject(obs(run, observed_from=p["observed_from"],
                                                               observed_until=p["observed_until"]))
    assert "signature" not in p["auth"] and w.seed not in rec["payload_json"]


def test_without_a_witness_the_result_is_what_it_was(world):
    tenant, runner, _ = world
    run = run_of(tenant)
    assert runner_submits(runner, result_sub(run)).status_code == 200
    b = outcome(tenant, run)
    assert b["measurement"] == {"status": "UNWITNESSED", "required": False, "witnesses": [], "reasons": []}
    assert b["state"] == "PASS" and b["score"] == 1.0 and "not independently measured" in b["note"]


# ------------------------------------------------------------------ a witness can only lower
@pytest.mark.parametrize("seen,why", [
    ({**SEEN, "availability": 0.8}, "availability"),
    ({**SEEN, "mttr_s": None}, "mttr_s"),
    ({**SEEN, "mttr_s": 100.0}, "mttr_s"),
    ({**SEEN, "downtime_s": 50.0}, "downtime_s"),
    ({**SEEN, "latency_p95_ms": 900}, "latency_p95_ms"),
])
def test_a_metric_the_witness_does_not_see_is_disputed_and_never_ranks(world, seen, why):
    tenant, runner, w = world
    run = run_of(tenant, "cfr-req")
    assert runner_submits(runner, result_sub(run)).status_code == 200
    assert witness_submits(w, obs(run, metrics=seen)).status_code == 200
    b = outcome(tenant, run)
    assert b["state"] == "DISPUTED" and b["tier"] == "none" and b["measurement"]["status"] == "CONTRADICTED"
    assert any(why in x for x in b["measurement"]["reasons"]), b["measurement"]
    assert b["runner_claim"]["state"] == "PASS" and b["score"] <= b["runner_claim"]["score"]
    assert board(tenant, "cfr-req") == [] and "DISPUTED" in b["note"]


@pytest.mark.parametrize("runner_says,witness_says", [("pass", "fail"), ("fail", "pass")])
def test_an_assertion_the_two_disagree_on_is_disputed_both_ways(world, runner_says, witness_says):
    tenant, runner, w = world
    run = run_of(tenant, "cfr-opt")
    ra = [{"id": a, "result": runner_says if a == "x509_chain_ok" else "pass"} for a in REQ + ["HIDDEN-001"]]
    wa = [{"id": a, "result": witness_says if a == "x509_chain_ok" else "pass"} for a in ("tls_handshake_ok", "x509_chain_ok")]
    assert runner_submits(runner, result_sub(run, assertions=ra)).status_code == 200
    assert witness_submits(w, obs(run, assertions=wa)).status_code == 200
    b = outcome(tenant, run)
    assert b["state"] == "DISPUTED" and b["tier"] == "none" and board(tenant, "cfr-opt") == []
    assert any("x509_chain_ok" in x for x in b["measurement"]["reasons"])


def test_lying_inside_the_tolerance_gains_nothing(world):
    """The runner claims a perfect run, the witness saw 3% less availability, 20 ms more latency, 8 s more MTTR: inside
    the tolerance, so CONFIRMED, but the score is the one computed from the worse numbers."""
    tenant, runner, w = world
    run = run_of(tenant, "cfr-req")
    assert runner_submits(runner, result_sub(run)).status_code == 200
    seen = {"availability": 0.97, "latency_p95_ms": 170, "mttr_s": 38.0, "downtime_s": 4.0}
    assert witness_submits(w, obs(run, metrics=seen)).status_code == 200
    b = outcome(tenant, run)
    assert b["measurement"]["status"] == "CONFIRMED" and b["state"] == "PASS"
    manifest = cfr.validate_manifest(REQUIRED_MANIFEST)
    worse = {**PERFECT, **seen}
    assert b["score"] == cfr.score(manifest, worse)["score"] < b["runner_claim"]["score"] == 1.0
    assert board(tenant, "cfr-req")[0]["score"] == b["score"]                    # the board uses the lowered score
    assert b["tier"] == cfr.judge(manifest, {a["id"]: a["result"] for a in ALL_PASS}, cfr.score(manifest, worse))["tier"]


def test_a_better_looking_witness_cannot_raise_the_score(world):
    tenant, runner, w = world
    run = run_of(tenant, "cfr-req")
    assert runner_submits(runner, result_sub(run, {**PERFECT, "availability": 0.97, "mttr_s": 38})).status_code == 200
    assert witness_submits(w, obs(run)).status_code == 200                       # witness saw a perfect run
    b = outcome(tenant, run)
    assert b["score"] == b["runner_claim"]["score"] < 1.0


# ------------------------------------------------------------------ required, insufficient, quorum
def test_a_required_manifest_never_passes_without_a_confirmed_witness(world):
    tenant, runner, w = world
    run = run_of(tenant, "cfr-req")
    assert runner_submits(runner, result_sub(run)).status_code == 200
    b = outcome(tenant, run)
    assert b["state"] == "UNKNOWN" and b["tier"] == "none" and b["runner_claim"]["state"] == "PASS"
    assert b["measurement"]["required"] is True and board(tenant, "cfr-req") == []
    assert witness_submits(w, obs(run)).status_code == 200
    assert outcome(tenant, run)["state"] == "PASS" and len(board(tenant, "cfr-req")) == 1


def test_required_does_not_turn_a_runner_fail_into_anything_better(world):
    tenant, runner, w = world
    run = run_of(tenant, "cfr-req")
    ra = [{"id": a, "result": "fail" if a == "tls_handshake_ok" else "pass"} for a in REQ + ["HIDDEN-001"]]
    assert runner_submits(runner, result_sub(run, assertions=ra)).status_code == 200
    assert outcome(tenant, run)["state"] == "FAIL"
    wa = [{"id": a, "result": "fail" if a == "tls_handshake_ok" else "pass"} for a in ("tls_handshake_ok", "x509_chain_ok")]
    assert witness_submits(w, obs(run, assertions=wa)).status_code == 200
    b = outcome(tenant, run)
    assert b["state"] == "FAIL" and b["measurement"]["status"] == "CONFIRMED"      # a confirmed failure stays a failure


@pytest.mark.parametrize("scenario,state,ranked", [("cfr-req", "UNKNOWN", 0), ("cfr-opt", "PASS", 1)])
def test_a_witness_that_does_not_cover_the_confirm_list_is_insufficient(world, scenario, state, ranked):
    tenant, runner, w = world
    run = run_of(tenant, scenario)
    assert runner_submits(runner, result_sub(run)).status_code == 200
    only_one = [{"id": "tls_handshake_ok", "result": "pass"}]
    assert witness_submits(w, obs(run, assertions=only_one)).status_code == 200
    b = outcome(tenant, run)
    assert b["measurement"]["status"] == "INSUFFICIENT" and b["state"] == state
    assert len(board(tenant, scenario)) == ranked


def test_an_unknown_witness_answer_does_not_confirm(world):
    tenant, runner, w = world
    run = run_of(tenant, "cfr-req")
    assert runner_submits(runner, result_sub(run)).status_code == 200
    wa = [{"id": "tls_handshake_ok", "result": "pass"}, {"id": "x509_chain_ok", "result": "unknown"}]
    assert witness_submits(w, obs(run, assertions=wa)).status_code == 200
    b = outcome(tenant, run)
    assert b["measurement"]["status"] == "INSUFFICIENT" and b["state"] == "UNKNOWN"


def test_one_dissenting_witness_disputes_the_run_and_the_quorum_is_capped(world):
    tenant, runner, w1 = world
    w2, w3, w4 = (P(tenant, f"witness-{i}", "witness") for i in (2, 3, 4))
    run = run_of(tenant, "cfr-req")
    assert runner_submits(runner, result_sub(run)).status_code == 200
    assert witness_submits(w1, obs(run)).status_code == 200
    assert witness_submits(w2, obs(run)).status_code == 200
    assert outcome(tenant, run)["measurement"]["status"] == "CONFIRMED"
    assert witness_submits(w3, obs(run, metrics={**SEEN, "availability": 0.5})).status_code == 200
    assert outcome(tenant, run)["state"] == "DISPUTED"
    r = witness_submits(w4, obs(run))
    assert r.status_code == 409 and "at most 3" in r.text
    assert types(tenant[0]).count("cfr.witness") == 3
    r = witness_submits(w1, obs(run))                                              # the same witness cannot speak twice
    assert r.status_code == 409


def test_a_witness_cannot_vote_twice_to_outweigh_a_dissenter(world):
    tenant, runner, w1 = world
    w2 = P(tenant, "witness-2", "witness")
    run = run_of(tenant, "cfr-req")
    assert runner_submits(runner, result_sub(run)).status_code == 200
    assert witness_submits(w1, obs(run, metrics={**SEEN, "availability": 0.5})).status_code == 200
    assert witness_submits(w1, obs(run)).status_code == 409                       # cannot replace its dissent
    assert types(tenant[0]).count("cfr.witness") == 1, "a refused observation must not leave a record behind"
    assert witness_submits(w2, obs(run)).status_code == 200
    assert outcome(tenant, run)["state"] == "DISPUTED"


# ------------------------------------------------------------------ identity
def test_the_runner_cannot_be_its_own_witness(world):
    tenant, runner, w = world
    run = run_of(tenant, "cfr-req")
    o = obs(run)
    body = dict(o)
    body["auth"] = {**idn.sign_request(runner.seed, runner.tid, "cfr.witness", "runner-1", cfr.witness_subject(o)),
                    "witness_id": "runner-1"}
    r = post("/cfr/witness", runner.key, **body)
    assert r.status_code == 401 and "not enrolled as 'witness'" in r.text         # a runner key is not a witness key
    twin = post("/identity/enroll", runner.key, TOKEN, principal_id="witness-twin", role="witness", public_key=runner.pub)
    assert twin.status_code == 409                                                # one key, one principal: no re-enrolling it
    assert "cfr.witness" not in types(tenant[0])


def test_a_witness_key_cannot_submit_a_runner_result(world):
    tenant, _, w = world
    run = run_of(tenant, "cfr-req")
    sub = result_sub(run)
    body = dict(sub)
    body["auth"] = cfr.sign_result(w.seed, w.tid, "witness-1", sub)
    r = post("/cfr/results", w.key, **body)
    assert r.status_code == 401 and "not enrolled as 'runner'" in r.text
    assert "cfr.result" not in types(tenant[0])


def test_unsigned_unknown_and_tampered_witness_requests_are_denied(world):
    tenant, runner, w = world
    run = run_of(tenant, "cfr-req")
    o = obs(run)
    assert witness_submits(w, o, auth=None).status_code == 401
    assert witness_submits(w, o, auth="x").status_code == 401
    ghost = P(tenant, "ghost", "witness", enroll=False)
    assert witness_submits(ghost, o).status_code == 401
    a = cfr.sign_witness(w.seed, w.tid, "witness-1", o)
    a.pop("witness_id")
    assert witness_submits(w, o, auth=a).status_code == 401
    mallory_seed, _ = idn.generate_keypair()
    assert witness_submits(w, o, auth=cfr.sign_witness(mallory_seed, w.tid, "witness-1", o)).status_code == 401
    auth = cfr.sign_witness(w.seed, w.tid, "witness-1", o)
    for tamper in ({"metrics": {**SEEN, "availability": 0.99}}, {"assertions": WITNESSED[:1]},
                   {"observed_from": o["observed_from"] - 1}, {"observed_until": o["observed_until"] - 1},
                   {"artifacts": {"probe_log": "ef" * 32}}):
        assert witness_submits(w, {**o, **tamper}, auth=auth).status_code == 401, tamper
    assert "cfr.witness" not in types(tenant[0])
    assert witness_submits(w, o, auth=auth).status_code == 200
    r = witness_submits(w, o, auth=auth)
    assert r.status_code == 401 and "nonce" in r.text                              # replay


def test_a_revoked_witness_is_locked_out_and_other_tenants_cannot_use_a_run(world):
    tenant, _, w = world
    run = run_of(tenant, "cfr-req")
    other = make_tenant()
    post("/cfr/scenarios", other[1], TOKEN, manifest=REQUIRED_MANIFEST)
    twin = P(other, "witness-1", "witness", enroll=False)
    twin.seed, twin.pub = w.seed, w.pub
    assert witness_submits(twin, obs(run)).status_code == 401                      # not enrolled there
    post("/identity/enroll", other[1], TOKEN, principal_id="witness-1", role="witness", public_key=w.pub)
    assert witness_submits(twin, obs(run)).status_code == 404                      # enrolled, but the run is not theirs
    assert post("/identity/revoke", tenant[1], TOKEN, principal_id="witness-1", reason="rotated").status_code == 200
    assert witness_submits(w, obs(run)).status_code == 401


def test_forged_witness_records_cannot_be_posted(world):
    tenant, _, _ = world
    before = types(tenant[0])
    assert post("/evidence", tenant[1], record_type="cfr.witness", payload={"schema": cfr.SCHEMA}).status_code == 400
    assert types(tenant[0]) == before


# ------------------------------------------------------------------ validation
def test_the_witness_cannot_supply_a_score_a_state_or_unobservable_metrics(world):
    tenant, _, w = world
    run = run_of(tenant, "cfr-req")
    for extra in ({"score": 1.0}, {"state": "PASS"}, {"tier": "elite"}):
        r = witness_submits(w, {**obs(run), **extra})
        assert r.status_code == 400 and "computed by the server" in r.text
    for metrics in ({**SEEN, "restarts": 0}, {**SEEN, "blast_radius": 0}, {k: v for k, v in SEEN.items() if k != "downtime_s"}):
        assert witness_submits(w, obs(run, metrics=metrics)).status_code == 400
    assert "cfr.witness" not in types(tenant[0])


@pytest.mark.parametrize("bad", [
    {"availability": 1.5}, {"availability": -0.1}, {"availability": True},
    {"latency_p95_ms": -1}, {"latency_p95_ms": "x"}, {"mttr_s": -3}, {"mttr_s": "x"}, {"downtime_s": -1},
])
def test_bad_witness_metrics_are_rejected(world, bad):
    tenant, _, w = world
    run = run_of(tenant, "cfr-req")
    r = witness_submits(w, obs(run, metrics={**SEEN, **bad}))
    assert r.status_code in (400, 422), r.text
    assert "cfr.witness" not in types(tenant[0])


def test_non_finite_witness_numbers_are_rejected_by_the_validator():
    for bad in (float("nan"), float("inf")):
        for k in ("availability", "latency_p95_ms", "downtime_s"):
            with pytest.raises(cfr.CfrError):
                cfr.validate_witness_metrics({**SEEN, k: bad})
    with pytest.raises(cfr.CfrError):
        cfr.validate_witness_metrics({**SEEN, "mttr_s": float("nan")})


@pytest.mark.parametrize("bad", [
    "x", [{"id": "nope", "result": "pass"}], [{"id": "tls_handshake_ok", "result": "yes"}],
    [{"id": "tls_handshake_ok", "result": "pass"}, {"id": "tls_handshake_ok", "result": "fail"}],
])
def test_bad_witness_assertions_are_rejected(world, bad):
    tenant, _, w = world
    run = run_of(tenant, "cfr-req")
    assert witness_submits(w, obs(run, assertions=bad)).status_code == 400
    assert "cfr.witness" not in types(tenant[0])


def test_unknown_run_manifest_mismatch_and_bad_artifacts(world):
    tenant, _, w = world
    run = run_of(tenant, "cfr-req")
    assert witness_submits(w, obs({**run, "run_id": "run_" + "0" * 24})).status_code == 404
    assert witness_submits(w, obs({**run, "run_id": "bad"})).status_code == 400
    assert witness_submits(w, obs({**run, "manifest_sha256": "0" * 64})).status_code == 400
    for art in ({"x": "nothex"}, {"bad name!": "ab" * 32}, "x"):
        assert witness_submits(w, obs(run, artifacts=art)).status_code == 400
    assert "cfr.witness" not in types(tenant[0])


def test_witness_time_rules(world):
    tenant, _, w = world
    run = run_of(tenant, "cfr-req")
    now = time.time()
    assert witness_submits(w, obs(run, observed_from=now - 10, observed_until=now - 20)).status_code == 400
    assert witness_submits(w, obs(run, observed_from="x")).status_code == 400
    assert witness_submits(w, obs(run, observed_from=now - 90000, observed_until=now - 80000)).status_code == 400
    assert witness_submits(w, obs(run, observed_from=now, observed_until=now + 3600)).status_code == 400
    assert "cfr.witness" not in types(tenant[0])


def test_a_broken_chain_refuses_witness_submissions(world):
    from sqlalchemy import text
    tenant, runner, w = world
    run = run_of(tenant, "cfr-req")
    assert runner_submits(runner, result_sub(run)).status_code == 200
    with SessionLocal() as db:
        db.execute(text("DROP TRIGGER IF EXISTS evidence_no_update"))
        db.execute(text("UPDATE evidence_records SET payload_json = payload_json || ' ' WHERE tenant_id = :t AND seq = 0"),
                   {"t": tenant[0]})
        db.commit()
    try:
        assert witness_submits(w, obs(run)).status_code == 503
        assert get(f"/cfr/results/{run['run_id']}", tenant[1]).status_code == 503
        assert get("/cfr/leaderboard/cfr-req", tenant[1]).status_code == 503
    finally:
        with SessionLocal() as db:
            db.execute(text("CREATE TRIGGER IF NOT EXISTS evidence_no_update BEFORE UPDATE ON evidence_records "
                            "BEGIN SELECT RAISE(ABORT, 'evidence_records is append-only'); END;"))
            db.commit()


# ------------------------------------------------------------------ manifests
@pytest.mark.parametrize("mutate", [
    lambda im: im.pop("required"), lambda im: im.update(extra=1), lambda im: im.update(required="yes"),
    lambda im: im.update(confirm_assertions=[]), lambda im: im.update(confirm_assertions=["nope"]),
    lambda im: im.update(confirm_assertions=["tls_handshake_ok", "tls_handshake_ok"]),
    lambda im: im.update(confirm_assertions="tls_handshake_ok"),
    lambda im: im["tolerance"].pop("mttr_s"), lambda im: im["tolerance"].update(availability=1.5),
    lambda im: im["tolerance"].update(mttr_s=-1), lambda im: im["tolerance"].update(latency_p95_rel=True),
    lambda im: im.update(tolerance=[]),
])
def test_bad_independent_measurement_blocks_are_rejected_and_not_recorded(mutate):
    tenant = make_tenant()
    m = copy.deepcopy(REQUIRED_MANIFEST)
    mutate(m["independent_measurement"])
    assert post("/cfr/scenarios", tenant[1], TOKEN, manifest=m).status_code == 400
    assert types(tenant[0]) == []
    assert post("/cfr/scenarios", tenant[1], TOKEN, manifest={**REQUIRED_MANIFEST, "independent_measurement": 5}).status_code == 400


def test_a_manifest_without_the_block_keeps_the_digest_it_always_had():
    """Computed with the code before this change (33702420… for this very manifest)."""
    assert cfr._sha(cfr.validate_manifest(MANIFEST)) == "337024200674fa68c6edf2b6e39b15138543a263fdd7ecfb4290c79a263169f4"
    assert "independent_measurement" not in cfr.validate_manifest(MANIFEST)
    assert cfr._sha(cfr.validate_manifest(REQUIRED_MANIFEST)) != cfr._sha(cfr.validate_manifest(MANIFEST))


# ------------------------------------------------------------------ the pure reconciliation
def _rp(metrics=PERFECT, assertions=None, state="PASS"):
    return {"metrics": dict(metrics), "assertions": dict(assertions or {a["id"]: a["result"] for a in ALL_PASS}),
            "state": state}


def _wit(wid="w", metrics=SEEN, assertions=None):
    return {"witness_id": wid, "metrics": dict(metrics), "assertions": dict(assertions or {a["id"]: a["result"] for a in WITNESSED})}


def test_the_effective_view_is_never_better_than_the_runner_claim():
    """Randomised: whatever a witness reports, the score never rises and a non-PASS claim never becomes PASS."""
    rnd = random.Random(20261005)
    manifests = [cfr.validate_manifest(m) for m in (MANIFEST, REQUIRED_MANIFEST, OPTIONAL_MANIFEST)]
    vals = ("pass", "fail", "unknown")
    for _ in range(400):
        m = rnd.choice(manifests)
        rm = {"availability": round(rnd.uniform(0.85, 1), 3), "latency_p95_ms": rnd.uniform(50, 2500),
              "mttr_s": rnd.choice([None, rnd.uniform(0, 1000)]), "blast_radius": rnd.randint(0, 6),
              "restarts": rnd.randint(0, 5), "downtime_s": rnd.uniform(0, 200)}
        ra = {a: rnd.choice(vals) for a in REQ + ["HIDDEN-001"] if rnd.random() < 0.9}
        scored = cfr.score(m, rm)
        verdict = cfr.judge(m, ra, scored)
        rp = {"metrics": rm, "assertions": ra, "state": verdict["state"]}
        wits = [{"witness_id": f"w{i}",
                 "metrics": {"availability": round(rnd.uniform(0.8, 1), 3), "latency_p95_ms": rnd.uniform(50, 2500),
                             "mttr_s": rnd.choice([None, rnd.uniform(0, 1000)]), "downtime_s": rnd.uniform(0, 200)},
                 "assertions": {a: rnd.choice(vals) for a in ("tls_handshake_ok", "x509_chain_ok", "HIDDEN-001") if rnd.random() < 0.9}}
                for i in range(rnd.randint(0, 3))]
        eff = cfr._effective(m, rp, wits)
        assert eff["score"] <= scored["score"] + 1e-12, (rp, wits)
        if rp["state"] != "PASS":
            assert eff["state"] in (rp["state"], "DISPUTED"), (rp, wits, eff)
        if eff["state"] == "PASS":
            assert eff["measurement"]["status"] != "CONTRADICTED"
            if m.get("independent_measurement", {}).get("required"):
                assert eff["measurement"]["status"] == "CONFIRMED"
        else:
            assert eff["tier"] == "none"


def test_reconcile_statuses_and_reasons():
    m = cfr.validate_manifest(REQUIRED_MANIFEST)
    assert cfr.reconcile(m, _rp(), [])["status"] == "UNWITNESSED"
    assert cfr.reconcile(m, _rp(), [_wit()])["status"] == "CONFIRMED"
    # edge of the tolerance is still agreement; just past it is not
    edge = {**SEEN, "availability": 0.95, "mttr_s": 40.0, "downtime_s": 10.0}
    assert cfr.reconcile(m, _rp(), [_wit(metrics=edge)])["status"] == "CONFIRMED"
    for k, v in (("availability", 0.949), ("mttr_s", 40.01), ("downtime_s", 10.01), ("latency_p95_ms", 300.1)):
        assert cfr.reconcile(m, _rp(), [_wit(metrics={**SEEN, k: v})])["status"] == "CONTRADICTED", k
    assert cfr.reconcile(m, _rp(), [_wit(metrics={**SEEN, "latency_p95_ms": 300})])["status"] == "CONFIRMED"
    both_none = cfr.reconcile(m, _rp({**PERFECT, "mttr_s": None}), [_wit(metrics={**SEEN, "mttr_s": None})])
    assert both_none["status"] == "CONFIRMED"
    # an assertion nobody can confirm: the runner missing it, the witness knowing it
    r = cfr.reconcile(m, _rp(assertions={"tls_handshake_ok": "pass"}), [_wit()])
    assert r["status"] == "INSUFFICIENT"
    assert cfr.reconcile(m, _rp(), [_wit(), _wit("w2", metrics={**SEEN, "availability": 0.5})])["status"] == "CONTRADICTED"
    # no block in the manifest: defaults apply and the required assertions are what has to be confirmed
    plain = cfr.validate_manifest(MANIFEST)
    full = {a: "pass" for a in REQ}
    assert cfr.reconcile(plain, _rp(), [_wit(assertions=full)])["status"] == "CONFIRMED"
    assert cfr.reconcile(plain, _rp(), [_wit()])["status"] == "INSUFFICIENT"            # health_stable_60s not covered
    assert cfr.reconcile(plain, _rp(), [_wit(assertions=full)])["required"] is False


# ------------------------------------------------------------------ gaps found by the mutation check
def test_a_witness_that_lowers_mttr_inside_the_tolerance_lowers_the_score(world):
    """Needs an MTTR above the full-score limit, otherwise 100 and 108 s score the same and nothing is tested."""
    tenant, runner, w = world
    run = run_of(tenant, "cfr-req")
    assert runner_submits(runner, result_sub(run, {**PERFECT, "mttr_s": 100})).status_code == 200
    assert witness_submits(w, obs(run, metrics={**SEEN, "mttr_s": 108.0})).status_code == 200
    b = outcome(tenant, run)
    manifest = cfr.validate_manifest(REQUIRED_MANIFEST)
    assert b["measurement"]["status"] == "CONFIRMED"
    assert b["score"] == cfr.score(manifest, {**PERFECT, "mttr_s": 108.0})["score"] < b["runner_claim"]["score"]


def test_unknown_on_both_sides_or_missing_on_both_is_not_a_confirmation():
    m = cfr.validate_manifest(REQUIRED_MANIFEST)
    both_unknown = cfr.reconcile(m, _rp(assertions={"tls_handshake_ok": "pass", "x509_chain_ok": "unknown"}),
                                 [_wit(assertions={"tls_handshake_ok": "pass", "x509_chain_ok": "unknown"})])
    assert both_unknown["status"] == "INSUFFICIENT"
    both_missing = cfr.reconcile(m, _rp(assertions={"tls_handshake_ok": "pass"}),
                                 [_wit(assertions={"tls_handshake_ok": "pass"})])
    assert both_missing["status"] == "INSUFFICIENT"


def test_zero_latency_on_both_sides_does_not_divide_by_zero():
    m = cfr.validate_manifest(REQUIRED_MANIFEST)
    r = cfr.reconcile(m, _rp({**PERFECT, "latency_p95_ms": 0}), [_wit(metrics={**SEEN, "latency_p95_ms": 0})])
    assert r["status"] == "CONFIRMED"
    r = cfr.reconcile(m, _rp({**PERFECT, "latency_p95_ms": 0}), [_wit(metrics={**SEEN, "latency_p95_ms": 0.4})])
    assert r["status"] == "CONFIRMED"                                              # a 1 ms floor: 0.4 ms noise is not a dispute
    r = cfr.reconcile(m, _rp({**PERFECT, "latency_p95_ms": 0}), [_wit(metrics={**SEEN, "latency_p95_ms": 0.8})])
    assert r["status"] == "CONTRADICTED"


def test_the_default_tolerance_applies_without_a_block():
    plain = cfr.validate_manifest(MANIFEST)
    full = {a: "pass" for a in REQ}
    near = cfr.reconcile(plain, _rp(), [_wit(metrics={**SEEN, "availability": 0.96}, assertions=full)])
    far = cfr.reconcile(plain, _rp(), [_wit(metrics={**SEEN, "availability": 0.9}, assertions=full)])
    assert near["status"] == "CONFIRMED" and far["status"] == "CONTRADICTED"
    assert cfr.DEFAULT_TOLERANCE["availability"] == 0.05


def test_a_second_record_by_the_same_witness_is_ignored_when_reading(world):
    """The API refuses it, but a record that was written anyway (a race, a bug) must not count twice or replace the first."""
    tenant, runner, w = world
    run = run_of(tenant, "cfr-req")
    assert runner_submits(runner, result_sub(run)).status_code == 200
    assert witness_submits(w, obs(run)).status_code == 200
    first = [r for r in pb.load_chain(tenant[0]) if r["record_type"] == "cfr.witness"][0]
    p = json.loads(first["payload_json"])
    p["metrics"] = {**p["metrics"], "availability": 0.1}
    pb.append_evidence(tenant[0], "cfr.witness", p)                                # same witness, dissenting, later
    b = outcome(tenant, run)
    assert b["measurement"]["status"] == "CONFIRMED" and b["state"] == "PASS"
    assert b["measurement"]["witnesses"] == ["witness-1"]


def test_a_witness_that_lost_the_slot_race_is_refused(world, monkeypatch):
    tenant, runner, w = world
    run = run_of(tenant, "cfr-req")
    real, calls = cfr._witnesses, {"n": 0}

    def racing(chain):
        calls["n"] += 1
        out = real(chain)
        if calls["n"] >= 2:                                   # the post-write re-read: three earlier witnesses took the slots
            out = {**out, run["run_id"]: [({"seq": -i}, {"witness_id": f"x{i}"}) for i in (1, 2, 3)]}
        return out
    monkeypatch.setattr(cfr, "_witnesses", racing)
    r = witness_submits(w, obs(run))
    assert r.status_code == 409 and "took this slot first" in r.text


# ------------------------------------------------------------------ findings of the independent review
def test_the_submit_response_tells_the_same_story_as_the_read_side(world):
    """A client that trusts the POST /cfr/results response must not see a PASS the server will not stand behind."""
    tenant, runner, w = world
    run = run_of(tenant, "cfr-req")                                  # required witness, none yet
    r = runner_submits(runner, result_sub(run))
    assert r.status_code == 200
    assert r.json()["state"] == "UNKNOWN" and r.json()["tier"] == "none" and r.json()["measurement"]["required"] is True
    assert r.json()["runner_claim"]["state"] == "PASS"
    assert r.json()["state"] == outcome(tenant, run)["state"]
    run2 = run_of(tenant, "cfr-opt", "bob")                          # a dissenting witness posted BEFORE the result
    assert witness_submits(w, obs(run2, metrics={**SEEN, "availability": 0.2})).json()["measurement"] == "AWAITING_RESULT"
    r2 = runner_submits(runner, result_sub(run2))
    assert r2.json()["state"] == "DISPUTED" and r2.json()["tier"] == "none" and r2.json()["score"] < 1.0, r2.text
    assert r2.json()["state"] == outcome(tenant, run2)["state"]


def test_hidden_assertion_ids_stay_out_of_the_public_reasons(world):
    tenant, runner, w = world
    run = run_of(tenant, "cfr-opt")
    assert runner_submits(runner, result_sub(run)).status_code == 200
    seen = [{"id": "tls_handshake_ok", "result": "pass"}, {"id": "x509_chain_ok", "result": "pass"},
            {"id": "HIDDEN-001", "result": "fail"}]
    assert witness_submits(w, obs(run, assertions=seen)).json()["measurement"] == "CONTRADICTED"
    res = outcome(tenant, run)
    assert res["state"] == "DISPUTED" and res["measurement"]["reasons"] == [f"witness-1: a hidden assertion disagrees"]
    assert "HIDDEN-001" not in json.dumps(res)
    run2 = run_of(tenant, "cfr-opt", "bob")                          # a REQUIRED assertion keeps its id: it is public anyway
    assert runner_submits(runner, result_sub(run2)).status_code == 200
    bad = [{"id": "tls_handshake_ok", "result": "fail"}, {"id": "x509_chain_ok", "result": "pass"},
           {"id": "HIDDEN-001", "result": "pass"}]
    assert witness_submits(w, obs(run2, assertions=bad)).status_code == 200
    assert "assertion tls_handshake_ok witness=fail runner=pass" in outcome(tenant, run2)["measurement"]["reasons"][0]


@pytest.mark.parametrize("field", ["observed_from", "observed_until", "availability"])
def test_integers_beyond_float_range_are_refused_not_a_500(world, field):
    tenant, _, w = world
    run = run_of(tenant, "cfr-opt")
    o = obs(run)
    if field == "availability":
        o["metrics"]["availability"] = 10 ** 400
    else:
        o[field] = 10 ** 400
    r = witness_submits(w, o)
    assert r.status_code == 400, r.text
    assert "cfr.witness" not in types(tenant[0])


def test_a_huge_integer_timestamp_in_auth_is_a_denial_not_a_500(world):
    tenant, _, w = world
    run = run_of(tenant, "cfr-opt")
    o = obs(run)
    auth = cfr.sign_witness(w.seed, w.tid, w.pid, o)
    auth["ts"] = 10 ** 400
    assert witness_submits(w, o, auth=auth).status_code in (400, 401, 403)
    assert not cfr._num(10 ** 400) and not idn._num(10 ** 400) and cfr._num(3) and not cfr._num(True)


def test_the_tolerance_block_refuses_huge_integers():
    bad = {**IM, "tolerance": {**IM["tolerance"], "mttr_s": 10 ** 400}}
    with pytest.raises(cfr.CfrError):
        cfr._validate_independent(bad, set(REQ + ["HIDDEN-001"]))


def test_a_witness_cannot_observe_after_the_run_expired(world, monkeypatch):
    tenant, runner, w = world
    monkeypatch.setenv("OLA_CFR_RUN_TTL_S", "60")
    run = run_of(tenant, "cfr-req")
    real = time.time
    monkeypatch.setattr(cfr, "_now", lambda: real() + 3600)
    r = witness_submits(w, obs(run, observed_from=real() - 30, observed_until=real() - 5))
    assert r.status_code == 400 and "expired" in r.text, r.text
    assert "cfr.witness" not in types(tenant[0])


def test_a_witness_that_did_not_watch_during_the_runners_run_confirms_nothing(world):
    tenant, runner, w = world
    run = run_of(tenant, "cfr-req")
    now = time.time()
    assert runner_submits(runner, result_sub(run, started_at=now - 120, ended_at=now - 60)).status_code == 200
    late = obs(run, observed_from=now - 10, observed_until=now - 5)         # a short look AFTER the runner finished
    assert witness_submits(w, late).json()["measurement"] == "INSUFFICIENT"
    res = outcome(tenant, run)
    assert res["state"] == "UNKNOWN" and "does not overlap" in res["measurement"]["reasons"][0], res
    assert board(tenant, "cfr-req") == []


def test_reconcile_reports_the_gap_only_when_nothing_contradicts(world):
    rp = {"metrics": {**PERFECT}, "assertions": {a["id"]: a["result"] for a in ALL_PASS}, "started_at": 100.0,
          "ended_at": 200.0}
    rp["assertions"] = dict(rp["assertions"])
    m = {**OPTIONAL_MANIFEST}
    w = {"witness_id": "w", "metrics": dict(SEEN), "assertions": {a["id"]: a["result"] for a in WITNESSED},
         "observed_from": 300.0, "observed_until": 310.0}
    assert cfr.reconcile(m, rp, [w])["status"] == "INSUFFICIENT"
    assert cfr.reconcile(m, rp, [{**w, "observed_from": 150.0, "observed_until": 160.0}])["status"] == "CONFIRMED"
    assert cfr.reconcile(m, rp, [{**w, "observed_from": 50.0, "observed_until": 99.0}])["status"] == "INSUFFICIENT"
    res = cfr.reconcile(m, rp, [{**w, "metrics": {**SEEN, "availability": 0.1}}])
    assert res["status"] == "CONTRADICTED" and "does not overlap" not in " ".join(res["reasons"])


# ------------------------------------------------------------------ a revoked witness
def test_a_revoked_witness_can_no_longer_confirm_a_required_pass(world):
    """Revocation may mean 'compromised': its earlier confirmation must not keep a required PASS alive."""
    tenant, runner, w = world
    run = run_of(tenant, "cfr-req")
    assert runner_submits(runner, result_sub(run)).status_code == 200
    assert witness_submits(w, obs(run)).json()["measurement"] == "CONFIRMED"
    assert outcome(tenant, run)["state"] == "PASS" and [r["participant_id"] for r in board(tenant, "cfr-req")] == ["alice"]
    assert post("/identity/revoke", tenant[1], TOKEN, principal_id="witness-1", reason="compromised").status_code == 200
    res = outcome(tenant, run)
    assert res["state"] == "UNKNOWN" and res["tier"] == "none", res
    assert res["measurement"]["status"] == "INSUFFICIENT" and "revoked" in res["measurement"]["reasons"][0], res
    assert board(tenant, "cfr-req") == []


def test_a_revoked_witness_can_still_only_lower_never_raise(world):
    tenant, runner, w = world
    run = run_of(tenant, "cfr-opt")
    assert runner_submits(runner, result_sub(run)).status_code == 200
    assert witness_submits(w, obs(run, metrics={**SEEN, "availability": 0.2})).json()["measurement"] == "CONTRADICTED"
    assert post("/identity/revoke", tenant[1], TOKEN, principal_id="witness-1", reason="rotated").status_code == 200
    res = outcome(tenant, run)
    assert res["state"] == "DISPUTED" and res["score"] < res["runner_claim"]["score"], res
    assert board(tenant, "cfr-opt") == []


def test_reconcile_treats_a_revoked_witness_as_no_confirmation():
    rp = {"metrics": {**PERFECT}, "assertions": {a["id"]: a["result"] for a in ALL_PASS}}
    w = {"witness_id": "w", "metrics": dict(SEEN), "assertions": {a["id"]: a["result"] for a in WITNESSED}}
    assert cfr.reconcile(OPTIONAL_MANIFEST, rp, [w])["status"] == "CONFIRMED"
    assert cfr.reconcile(OPTIONAL_MANIFEST, rp, [{**w, "revoked": True}])["status"] == "INSUFFICIENT"
    assert cfr.reconcile(OPTIONAL_MANIFEST, rp, [{**w, "revoked": False}])["status"] == "CONFIRMED"
