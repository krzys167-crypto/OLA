"""CFR integration (app/cfr.py): signed runner results, server-side scoring, no silent pass."""
import copy
import hashlib
import json
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

MANIFEST = {
    "scenario_id": "cfr-14", "version": "1",
    "required_assertions": ["tls_handshake_ok", "x509_chain_ok", "health_stable_60s"],
    "hidden_assertions": ["HIDDEN-001"],
    "variants": ["expired_leaf", "wrong_chain", "truststore_missing"],
    "scoring": {
        "weights": {"availability": 0.35, "latency": 0.2, "time_to_recover": 0.3, "blast_radius": 0.15},
        "limits": {"availability_zero": 0.9, "latency_p95_ms_full": 200, "latency_p95_ms_zero": 2000,
                   "mttr_s_full": 60, "mttr_s_zero": 900, "blast_radius_full": 1, "blast_radius_zero": 6},
        "penalties": {"per_restart": 0.02, "max_restarts_penalty": 0.1, "downtime_over_s": 60, "downtime_penalty": 0.1},
        "tiers": {"pass": 0.6, "merit": 0.8, "elite": 0.92},
    },
}
PERFECT = {"availability": 1.0, "latency_p95_ms": 150, "mttr_s": 30, "blast_radius": 1, "restarts": 0, "downtime_s": 0}
HALF = {"availability": 0.95, "latency_p95_ms": 1100, "mttr_s": 480, "blast_radius": 3, "restarts": 0, "downtime_s": 0}
ALL_PASS = [{"id": a, "result": "pass"} for a in ("tls_handshake_ok", "x509_chain_ok", "health_stable_60s", "HIDDEN-001")]


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


@pytest.fixture
def tenant():
    return make_tenant()


def post(path, key, token=None, **body):
    h = {"X-API-Key": key}
    if token:
        h["X-Enroll-Token"] = token
    return C.post(path, headers=h, json=body)


def get(path, key):
    return C.get(path, headers={"X-API-Key": key})


def types(tid):
    return [r["record_type"] for r in pb.load_chain(tid)]


class Runner:
    def __init__(self, tenant, rid="runner-1", role="runner", enroll=True):
        self.tid, self.key, self.rid = tenant[0], tenant[1], rid
        self.seed, self.pub = idn.generate_keypair()
        if enroll:
            r = post("/identity/enroll", self.key, TOKEN, principal_id=rid, role=role, public_key=self.pub)
            assert r.status_code == 200, r.text


def register(tenant, manifest=MANIFEST):
    return post("/cfr/scenarios", tenant[1], TOKEN, manifest=manifest)


def issue(tenant, participant="alice", scenario="cfr-14"):
    return post("/cfr/runs", tenant[1], scenario_id=scenario, participant_id=participant)


def submission(run, metrics=PERFECT, assertions=ALL_PASS, **over):
    now = time.time()
    s = {"run_id": run["run_id"], "manifest_sha256": run["manifest_sha256"], "started_at": now - 120, "ended_at": now - 5,
         "metrics": copy.deepcopy(metrics), "assertions": copy.deepcopy(assertions), "artifacts": {"final_json": "ab" * 32}}
    s.update(over)
    return s


def submit(runner, sub, auth="auto", **kw):
    body = dict(sub)
    if auth == "auto":
        auth = cfr.sign_result(runner.seed, runner.tid, runner.rid, sub, **kw)
    if auth is not None:
        body["auth"] = auth
    return post("/cfr/results", runner.key, **body)


@pytest.fixture
def world(tenant):
    assert register(tenant).status_code == 200
    return tenant, Runner(tenant)


def run_of(tenant, **kw):
    r = issue(tenant, **kw)
    assert r.status_code == 200, r.text
    return r.json()


# ------------------------------------------------------------------ scoring (pure)
def norm():
    return cfr.validate_manifest(MANIFEST)


def test_score_known_answers():
    m = norm()
    assert cfr.score(m, PERFECT)["score"] == 1.0
    s = cfr.score(m, HALF)
    assert s["components"] == {"availability": 0.5, "latency": 0.5, "time_to_recover": 0.5, "blast_radius": 0.6}
    assert s["score"] == 0.515
    pen = cfr.score(m, {**HALF, "restarts": 2, "downtime_s": 61})
    assert pen["penalties"] == {"restarts": 0.04, "downtime": 0.1} and pen["score"] == 0.375
    assert cfr.score(m, {**HALF, "downtime_s": 60})["penalties"]["downtime"] == 0.0            # strictly over
    assert cfr.score(m, {**HALF, "restarts": 99})["penalties"]["restarts"] == 0.1              # capped
    never = cfr.score(m, {**PERFECT, "mttr_s": None})
    assert never["components"]["time_to_recover"] == 0.0 and never["score"] == 0.7
    worst = cfr.score(m, {"availability": 0.0, "latency_p95_ms": 9e5, "mttr_s": None, "blast_radius": 99,
                          "restarts": 99, "downtime_s": 1e5})
    assert worst["score"] == 0.0


def test_judge_never_passes_on_unknown_or_missing():
    m = norm()
    sc = {"score": 0.99}
    ok = {a["id"]: "pass" for a in ALL_PASS}
    assert cfr.judge(m, ok, sc)["state"] == "PASS" and cfr.judge(m, ok, sc)["tier"] == "elite"
    assert cfr.judge(m, {**ok, "x509_chain_ok": "unknown"}, sc) == {**cfr.judge(m, {**ok, "x509_chain_ok": "unknown"}, sc),
                                                                    "state": "UNKNOWN", "tier": "none"}
    missing = {k: v for k, v in ok.items() if k != "health_stable_60s"}
    assert cfr.judge(m, missing, sc)["state"] == "UNKNOWN" and cfr.judge(m, missing, sc)["required"]["health_stable_60s"] == "missing"
    no_hidden = {k: v for k, v in ok.items() if k != "HIDDEN-001"}
    assert cfr.judge(m, no_hidden, sc)["state"] == "UNKNOWN"
    assert cfr.judge(m, {**ok, "HIDDEN-001": "fail"}, sc)["state"] == "FAIL"
    assert cfr.judge(m, {**missing, "tls_handshake_ok": "fail"}, sc)["state"] == "FAIL"        # fail beats unknown
    assert cfr.judge(m, {}, sc)["state"] == "UNKNOWN"


@pytest.mark.parametrize("sc,tier", [(0.59, "none"), (0.6, "pass"), (0.79, "pass"), (0.8, "merit"), (0.919999, "merit"),
                                     (0.92, "elite"), (1.0, "elite")])
def test_tier_boundaries(sc, tier):
    ok = {a["id"]: "pass" for a in ALL_PASS}
    assert cfr.judge(norm(), ok, {"score": sc})["tier"] == tier


# ------------------------------------------------------------------ manifest
@pytest.mark.parametrize("mutate", [
    lambda m: m.pop("scoring"), lambda m: m.update(scenario_id=""), lambda m: m.update(version=5),
    lambda m: m["scoring"]["weights"].update(availability=0.5),
    lambda m: m["scoring"]["weights"].pop("latency"),
    lambda m: m["scoring"]["weights"].update(extra=0.0),
    lambda m: m["scoring"]["weights"].update(latency=True),
    lambda m: m["scoring"]["limits"].update(availability_zero=1.0),
    lambda m: m["scoring"]["limits"].update(latency_p95_ms_full=3000),
    lambda m: m["scoring"]["limits"].update(mttr_s_zero=60),
    lambda m: m["scoring"]["limits"].update(blast_radius_zero=1),
    lambda m: m["scoring"]["penalties"].update(downtime_penalty=1.5),
    lambda m: m["scoring"]["penalties"].update(per_restart=-1),
    lambda m: m["scoring"]["tiers"].update(merit=0.5),
    lambda m: m["scoring"]["tiers"].update(elite=1.1),
    lambda m: m["scoring"]["tiers"].pop("pass"),
    lambda m: m.update(required_assertions=[]),
    lambda m: m.update(required_assertions=["a", "a"]),
    lambda m: m.update(hidden_assertions=["tls_handshake_ok"]),
    lambda m: m.update(variants=[]),
    lambda m: m.update(variants=["v", "v"]),
    lambda m: m.update(variants=["bad id"]),
])
def test_bad_manifests_are_rejected_and_not_recorded(tenant, mutate):
    m = copy.deepcopy(MANIFEST)
    mutate(m)
    r = register(tenant, m)
    assert r.status_code == 400, r.text
    assert types(tenant[0]) == []


def test_register_needs_the_operator_token_and_is_first_wins(tenant):
    assert post("/cfr/scenarios", tenant[1], manifest=MANIFEST).status_code == 401
    assert post("/cfr/scenarios", tenant[1], "wrong", manifest=MANIFEST).status_code == 401
    assert types(tenant[0]) == []
    r = register(tenant)
    assert r.status_code == 200 and r.json()["manifest_sha256"] == cfr._sha(norm())
    changed = copy.deepcopy(MANIFEST)
    changed["scoring"]["tiers"]["pass"] = 0.1                                    # the easy way to hand out passes
    assert register(tenant, changed).status_code == 409
    assert types(tenant[0]) == ["cfr.scenario"]


def test_forged_cfr_records_cannot_be_posted(tenant):
    for t in ("cfr.scenario", "cfr.run", "cfr.result"):
        assert post("/evidence", tenant[1], record_type=t, payload={"schema": cfr.SCHEMA}).status_code == 400
    assert types(tenant[0]) == []


# ------------------------------------------------------------------ runs
def test_run_needs_a_server_secret(tenant, monkeypatch):
    register(tenant)
    for v in ("", "short"):
        monkeypatch.setenv("OLA_CFR_SEED_SECRET", v)
        assert issue(tenant).status_code == 503
    assert types(tenant[0]) == ["cfr.scenario"]


def test_run_issue_validation_and_digest_only_evidence(tenant):
    assert issue(tenant).status_code == 404                                       # no such scenario
    register(tenant)
    assert issue(tenant, scenario="nope").status_code == 404
    assert post("/cfr/runs", tenant[1], scenario_id="cfr-14", participant_id="bad id").status_code == 400
    assert post("/cfr/runs", tenant[1], scenario_id=None, participant_id="a").status_code == 400
    r = run_of(tenant)
    assert r["variant"] in MANIFEST["variants"] and len(r["seed"]) == 64
    payload = [x for x in pb.load_chain(tenant[0]) if x["record_type"] == "cfr.run"][0]["payload_json"]
    assert r["seed"] not in payload and r["variant"] not in payload                 # the chain keeps digests only
    d = json.loads(payload)
    assert d["seed_sha256"] == hashlib.sha256(bytes.fromhex(r["seed"])).hexdigest()
    assert d["variant_sha256"] == hashlib.sha256(r["variant"].encode()).hexdigest()


def test_runs_are_distinct_and_variants_spread(tenant):
    register(tenant)
    runs = [run_of(tenant) for _ in range(12)]
    assert len({r["run_id"] for r in runs}) == 12 and len({r["seed"] for r in runs}) == 12
    assert len({r["variant"] for r in runs}) >= 2                                   # per-run mutation, not one fixed fault


# ------------------------------------------------------------------ results: the happy path and what is computed
def test_signed_result_is_scored_by_the_server(world):
    tenant, runner = world
    run = run_of(tenant)
    r = submit(runner, submission(run, HALF, ALL_PASS))
    assert r.status_code == 200, r.text
    b = r.json()
    assert b["score"] == 0.515 and b["state"] == "PASS" and b["tier"] == "none" and b["attested_by_runner"] is True
    assert "not independently measured" in b["note"]
    rec = [x for x in pb.load_chain(tenant[0]) if x["record_type"] == "cfr.result"][0]
    p = json.loads(rec["payload_json"])
    assert p["identity"] == "verified" and p["auth"]["principal_id"] == "runner-1" and p["participant_id"] == "alice"
    assert "signature" not in p["auth"] and runner.seed not in rec["payload_json"]
    assert get(f"/cfr/results/{run['run_id']}", tenant[1]).json()["score"] == 0.515


def test_runner_cannot_supply_its_own_score_or_tier(world):
    tenant, runner = world
    run = run_of(tenant)
    for extra in ({"score": 1.0}, {"tier": "elite"}, {"state": "PASS"}, {"anything": 1}):
        r = submit(runner, submission(run, HALF, ALL_PASS, **extra))
        assert r.status_code == 400 and "computed by the server" in r.text
    assert "cfr.result" not in types(tenant[0])


@pytest.mark.parametrize("metrics,assertions,state,tier", [
    (PERFECT, ALL_PASS, "PASS", "elite"),
    ({**PERFECT, "latency_p95_ms": 500, "mttr_s": 200, "blast_radius": 2}, ALL_PASS, "PASS", "merit"),
    (HALF, ALL_PASS, "PASS", "none"),
    (PERFECT, ALL_PASS[:3], "UNKNOWN", "none"),                                    # hidden assertion not reported
    (PERFECT, [a for a in ALL_PASS if a["id"] != "x509_chain_ok"], "UNKNOWN", "none"),
    (PERFECT, [{"id": "tls_handshake_ok", "result": "unknown"}] + ALL_PASS[1:], "UNKNOWN", "none"),
    (PERFECT, [{"id": "tls_handshake_ok", "result": "fail"}] + ALL_PASS[1:], "FAIL", "none"),
    (PERFECT, ALL_PASS[:3] + [{"id": "HIDDEN-001", "result": "fail"}], "FAIL", "none"),
])
def test_state_and_tier(world, metrics, assertions, state, tier):
    tenant, runner = world
    run = run_of(tenant)
    r = submit(runner, submission(run, metrics, assertions))
    assert r.status_code == 200, r.text
    assert (r.json()["state"], r.json()["tier"]) == (state, tier)


# ------------------------------------------------------------------ who may submit
def test_unsigned_or_wrong_signer_is_denied(world):
    tenant, runner = world
    run = run_of(tenant)
    sub = submission(run)
    assert submit(runner, sub, auth=None).status_code == 401
    assert submit(runner, sub, auth="x").status_code == 401
    agent = Runner(tenant, "agent-1", role="agent")
    assert submit(agent, sub).status_code == 401                                   # an agent key is not a runner key
    ghost = Runner(tenant, "ghost", enroll=False)
    assert submit(ghost, sub).status_code == 401
    a = cfr.sign_result(runner.seed, runner.tid, "runner-1", sub)
    a.pop("runner_id")
    assert submit(runner, sub, auth=a).status_code == 401
    mallory_seed, _ = idn.generate_keypair()
    assert submit(runner, sub, auth=cfr.sign_result(mallory_seed, runner.tid, "runner-1", sub)).status_code == 401
    assert "cfr.result" not in types(tenant[0])


def test_signature_covers_the_whole_submission(world):
    tenant, runner = world
    run = run_of(tenant)
    sub = submission(run, HALF, ALL_PASS)
    auth = cfr.sign_result(runner.seed, runner.tid, "runner-1", sub)
    for tamper in ({"metrics": PERFECT}, {"assertions": ALL_PASS[:3]}, {"started_at": sub["started_at"] - 1},
                   {"ended_at": sub["ended_at"] - 1}, {"artifacts": {"final_json": "cd" * 32}}):
        r = submit(runner, {**sub, **tamper}, auth=auth)
        assert r.status_code == 401, tamper
    assert submit(runner, sub, auth=auth).status_code == 200


def test_replay_and_second_result(world):
    tenant, runner = world
    run = run_of(tenant)
    sub = submission(run)
    auth = cfr.sign_result(runner.seed, runner.tid, "runner-1", sub)
    assert submit(runner, sub, auth=auth).status_code == 200
    r = submit(runner, sub, auth=auth)
    assert r.status_code == 401 and "nonce" in r.text                              # replay
    r = submit(runner, sub)                                                         # fresh nonce, same run
    assert r.status_code == 409 and "already has a result" in r.text
    assert types(tenant[0]).count("cfr.result") == 1


def test_revoked_runner_is_locked_out(world):
    tenant, runner = world
    run = run_of(tenant)
    assert post("/identity/revoke", tenant[1], TOKEN, principal_id="runner-1", reason="rotated").status_code == 200
    assert submit(runner, submission(run)).status_code == 401


def test_other_tenants_runs_and_keys_do_not_work(world):
    tenant, runner = world
    run = run_of(tenant)
    other = make_tenant()
    register(other)
    assert get(f"/cfr/results/{run['run_id']}", other[1]).status_code == 404
    twin = Runner(other, "runner-1", enroll=False)
    twin.seed, twin.pub = runner.seed, runner.pub
    assert submit(twin, submission(run)).status_code == 401                         # not enrolled in that tenant
    post("/identity/enroll", other[1], TOKEN, principal_id="runner-1", role="runner", public_key=runner.pub)
    assert submit(twin, submission(run)).status_code == 404                         # enrolled, but the run is not theirs


# ------------------------------------------------------------------ validation of what the runner says
def test_unknown_run_and_manifest_mismatch(world):
    tenant, runner = world
    run = run_of(tenant)
    ghost = {**run, "run_id": "run_" + "0" * 24}
    assert submit(runner, submission(ghost)).status_code == 404
    assert submit(runner, submission(run, manifest_sha256="0" * 64)).status_code == 400
    assert submit(runner, {**submission(run), "run_id": "bad"}).status_code == 400
    assert C.post("/cfr/results", headers={"X-API-Key": tenant[1]}, json=["x"]).status_code == 422


@pytest.mark.parametrize("bad", [
    {"availability": 1.5}, {"availability": -0.1}, {"availability": True}, {"availability": "1"},
    {"latency_p95_ms": -1}, {"latency_p95_ms": 4e6}, {"mttr_s": -1}, {"mttr_s": "fast"},
    {"blast_radius": 1.5}, {"blast_radius": True}, {"blast_radius": -1},
    {"restarts": 2.0}, {"restarts": -1}, {"restarts": True},
    {"downtime_s": -1}, {"downtime_s": None},
])
def test_bad_metrics_are_rejected(world, bad):
    tenant, runner = world
    r = submit(runner, submission(run_of(tenant), {**PERFECT, **bad}))
    assert r.status_code == 400, (bad, r.text)


def test_metric_shape(world):
    tenant, runner = world
    run = run_of(tenant)
    assert submit(runner, submission(run, {k: v for k, v in PERFECT.items() if k != "restarts"})).status_code == 400
    assert submit(runner, submission(run, {**PERFECT, "extra": 1})).status_code == 400
    assert submit(runner, submission(run, None)).status_code == 400
    r = submit(runner, submission(run, {**PERFECT, "mttr_s": None}))
    assert r.status_code == 200 and r.json()["components"]["time_to_recover"] == 0.0


@pytest.mark.parametrize("bad", [
    [{"id": "nope", "result": "pass"}], [{"id": "tls_handshake_ok", "result": "pass"}] * 2,
    [{"id": "tls_handshake_ok", "result": "maybe"}], [{"id": "tls_handshake_ok"}], ["tls_handshake_ok"],
    [{"id": "tls_handshake_ok", "result": "pass", "extra": 1}], "pass", None, [{"id": 5, "result": "pass"}],
])
def test_bad_assertions_are_rejected(world, bad):
    tenant, runner = world
    r = submit(runner, submission(run_of(tenant), PERFECT, bad))
    assert r.status_code == 400, (bad, r.text)


@pytest.mark.parametrize("bad", [{"a": "xyz"}, {"bad id": "ab" * 32}, {"a": "AB" * 32}, [], {"a": 5}])
def test_bad_artifacts_are_rejected(world, bad):
    tenant, runner = world
    assert submit(runner, submission(run_of(tenant), artifacts=bad)).status_code == 400


def test_time_rules(world, monkeypatch):
    tenant, runner = world
    run = run_of(tenant)
    now = time.time()
    assert submit(runner, submission(run, started_at=now - 10, ended_at=now - 20)).status_code == 400
    assert submit(runner, submission(run, started_at="x")).status_code == 400
    assert submit(runner, submission(run, started_at=now - 90000, ended_at=now - 80000)).status_code == 400   # before issue
    assert submit(runner, submission(run, started_at=now, ended_at=now + 3600)).status_code == 400            # in the future
    monkeypatch.setattr(cfr, "_now", lambda: now + 99999)                                                     # run expired
    r = submit(runner, submission(run, started_at=now - 60, ended_at=now - 10))
    assert r.status_code == 409 and "expired" in r.text
    assert get(f"/cfr/results/{run['run_id']}", tenant[1]).json()["state"] == "EXPIRED"
    assert "cfr.result" not in types(tenant[0])


def test_ttl_configuration(tenant, monkeypatch):
    register(tenant)
    monkeypatch.setenv("OLA_CFR_RUN_TTL_S", "0")
    assert issue(tenant).status_code == 503
    monkeypatch.setenv("OLA_CFR_RUN_TTL_S", "60")
    assert run_of(tenant)["expires_in_s"] == 60


# ------------------------------------------------------------------ views
def test_pending_then_done(world):
    tenant, runner = world
    run = run_of(tenant)
    assert get(f"/cfr/results/{run['run_id']}", tenant[1]).json() == {
        "run_id": run["run_id"], "scenario_id": "cfr-14", "state": "PENDING", "tier": "none"}
    assert get("/cfr/results/nope", tenant[1]).status_code == 400
    assert get("/cfr/results/run_" + "1" * 24, tenant[1]).status_code == 404
    submit(runner, submission(run))
    assert get(f"/cfr/results/{run['run_id']}", tenant[1]).json()["state"] == "PASS"


def test_leaderboard_ranks_only_pass_best_per_participant(world):
    tenant, runner = world
    results = [("alice", PERFECT, ALL_PASS), ("alice", HALF, ALL_PASS), ("bob", {**PERFECT, "mttr_s": 400}, ALL_PASS),
               ("carol", PERFECT, ALL_PASS[:3]), ("dave", PERFECT, [{"id": "tls_handshake_ok", "result": "fail"}] + ALL_PASS[1:]),
               ("erin", {**PERFECT, "mttr_s": 400}, ALL_PASS)]
    for who, m, a in results:
        assert submit(runner, submission(run_of(tenant, participant=who), m, a)).status_code == 200
    lb = get("/cfr/leaderboard/cfr-14", tenant[1]).json()
    assert [(r["participant_id"], r["score"]) for r in lb["ranking"]] == [("alice", 1.0), ("bob", 0.878571), ("erin", 0.878571)]
    assert [r["participant_id"] for r in lb["ranking"]][1:] == ["bob", "erin"]           # tie: earlier record first
    assert get("/cfr/leaderboard/nope", tenant[1]).status_code == 404
    assert len(get("/cfr/leaderboard/cfr-14?limit=1", tenant[1]).json()["ranking"]) == 1


def test_broken_chain_refuses_everything(world):
    from sqlalchemy import text
    tenant, runner = world
    run = run_of(tenant)
    with SessionLocal() as db:
        db.execute(text("DROP TRIGGER IF EXISTS evidence_no_update"))
        db.execute(text("UPDATE evidence_records SET payload_json = payload_json || ' ' WHERE tenant_id = :t AND seq = 0"),
                   {"t": tenant[0]})
        db.commit()
    try:
        assert submit(runner, submission(run)).status_code == 503
        assert issue(tenant).status_code == 503
        assert get(f"/cfr/results/{run['run_id']}", tenant[1]).status_code == 503
        assert get("/cfr/leaderboard/cfr-14", tenant[1]).status_code == 503
    finally:
        with SessionLocal() as db:
            db.execute(text("CREATE TRIGGER IF NOT EXISTS evidence_no_update BEFORE UPDATE ON evidence_records "
                            "BEGIN SELECT RAISE(ABORT, 'evidence_records is append-only'); END;"))
            db.commit()


def test_scenario_records_with_a_wrong_digest_are_ignored_when_reading():
    good = cfr.validate_manifest(MANIFEST)
    forged = copy.deepcopy(good)
    forged["scoring"]["tiers"]["pass"] = 0.01
    chain = [{"seq": 0, "record_type": "cfr.scenario", "payload_json": json.dumps(
        {"schema": cfr.SCHEMA, "scenario_id": "cfr-14", "manifest": forged, "manifest_sha256": cfr._sha(good)})},
        {"seq": 1, "record_type": "cfr.scenario", "payload_json": json.dumps(
            {"schema": cfr.SCHEMA, "scenario_id": "cfr-14", "manifest": good, "manifest_sha256": cfr._sha(good)})},
        {"seq": 2, "record_type": "cfr.scenario", "payload_json": json.dumps(
            {"schema": cfr.SCHEMA, "scenario_id": "cfr-14", "manifest": forged, "manifest_sha256": cfr._sha(forged)})}]
    out = cfr._scenarios(chain)
    assert out["cfr-14"]["seq"] == 1 and out["cfr-14"]["manifest"] == good                  # digest mismatch skipped, first valid wins


def test_nan_and_infinite_times_are_rejected(world):
    """NaN slips through every `<` / `>` comparison, so it has to be refused by type, not by range."""
    tenant, runner = world
    run = run_of(tenant)
    for field, value in (("started_at", float("nan")), ("ended_at", float("nan")), ("ended_at", float("inf"))):
        sub = submission(run, **{field: value})
        body = dict(sub)
        body["auth"] = cfr.sign_result(runner.seed, runner.tid, runner.rid, sub)
        r = C.post("/cfr/results", headers={"X-API-Key": runner.key, "Content-Type": "application/json"},
                   content=json.dumps(body))
        assert r.status_code == 400, (field, value, r.text)
    assert "cfr.result" not in types(tenant[0])


def test_a_concurrent_earlier_result_wins(world, monkeypatch):
    tenant, runner = world
    run = run_of(tenant)
    real = cfr._results
    calls = {"n": 0}

    def racing(chain):
        calls["n"] += 1
        out = real(chain)
        if calls["n"] >= 2:                                   # the post-write re-read sees someone else's earlier record
            out = {**out, run["run_id"]: [({"seq": -1}, {})] + out.get(run["run_id"], [])}
        return out
    monkeypatch.setattr(cfr, "_results", racing)
    r = submit(runner, submission(run))
    assert r.status_code == 409 and "recorded first" in r.text
