"""Regression tests for the second independent security review (identity / firewall / hashchain / routes).
Each test reproduces a defect that was confirmed by a script before it was fixed (items refer to that report)."""
import hashlib
import json
import threading
import uuid
from collections import Counter

import pytest
from fastapi.testclient import TestClient

from app import firewall as fw
from app import identity as idn
from app.database import SessionLocal
from app.main import app
from app.models import ApiKey, Tenant

C = TestClient(app, raise_server_exceptions=False)
TOKEN = "operator-token-r2"
AKIA = "AKIAIOSFODNN7EXAMPLE"
STAGING = {"environment": "staging"}


def make_tenant():
    tid, key = str(uuid.uuid4()), "r2-" + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(Tenant(id=tid, name="r2"))
        db.add(ApiKey(id=str(uuid.uuid4()), tenant_id=tid, key_hash=hashlib.sha256(key.encode()).hexdigest()))
        db.commit()
    return tid, key


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.delenv("OLA_FIREWALL_AGENT_AUTH", raising=False)
    monkeypatch.setenv("OLA_IDENTITY_ENROLL_TOKEN_SHA256", hashlib.sha256(TOKEN.encode()).hexdigest())


@pytest.fixture
def tenant():
    return make_tenant()


def post(path, key, **body):
    return C.post(path, headers={"X-API-Key": key, "X-Enroll-Token": TOKEN}, json=body)


class Actor:
    def __init__(self, tenant, pid, role):
        self.tid, self.key, self.pid = tenant[0], tenant[1], pid
        self.seed, self.pub = idn.generate_keypair()
        r = post("/identity/enroll", self.key, principal_id=pid, role=role, public_key=self.pub)
        assert r.status_code == 200, r.text

    def sign(self, purpose, subject, **kw):
        return idn.sign_request(self.seed, self.tid, purpose, self.pid, subject, **kw)


@pytest.fixture
def required(monkeypatch):
    monkeypatch.setenv("OLA_FIREWALL_AGENT_AUTH", "required")


# ------------------------------------------------------------------ item 3: the signature covers the whole action
def test_item3a_a_relay_cannot_strip_the_flags_the_agent_signed(tenant, required):
    ag = Actor(tenant, "agent-1", "agent")
    signed = {"type": "mcp_tool", "target": "x", "environment": "production",
              "contains_secret": True, "external_side_effect": True}
    auth = ag.sign("firewall.authorize", fw.authorize_subject("agent-1", signed))
    r = post("/firewall/authorize", tenant[1], agent_id="agent-1", action=signed, auth=auth)
    assert r.status_code == 200 and r.json()["decision"] == "BLOCK"
    stripped = {k: v for k, v in signed.items() if k not in ("contains_secret", "external_side_effect")}
    assert fw.authorize_subject("agent-1", stripped) != fw.authorize_subject("agent-1", signed)
    auth2 = ag.sign("firewall.authorize", fw.authorize_subject("agent-1", signed))     # a fresh, valid signature
    r = post("/firewall/authorize", tenant[1], agent_id="agent-1", action=stripped, auth=auth2)
    assert r.status_code == 401


def test_item3a_context_flags_are_part_of_the_digest():
    a = {"type": "mcp_tool", "target": "x"}
    assert fw.authorize_subject("agent-1", a, {"environment": "production", "contains_secret": True}) != \
        fw.authorize_subject("agent-1", a, {"environment": "production"})


def test_item3b_approval_and_permit_are_bound_to_every_field(tenant, required):
    ag, ap = Actor(tenant, "agent-1", "agent"), Actor(tenant, "appr-1", "approver")
    A = {"type": "transfer", "value": 5000, "target": "treasury", "environment": "production",
         "destination_iban": "PL00GOOD"}
    r = post("/firewall/authorize", tenant[1], agent_id="agent-1", action=A,
             auth=ag.sign("firewall.authorize", fw.authorize_subject("agent-1", A)))
    assert r.json()["decision"] == "REVIEW"
    rid = r.json()["request_id"]
    why = "approved transfer to PL00GOOD"
    r = post("/firewall/approve", tenant[1], request_id=rid, approver_id="appr-1", reason=why,
             auth=ap.sign("firewall.approve", fw.approve_subject(rid, why)))
    assert r.status_code == 200
    B = {**A, "destination_iban": "RU99EVIL"}
    r = post("/firewall/consume", tenant[1], request_id=rid, agent_id="agent-1", action=B,
             auth=ag.sign("firewall.consume", fw.consume_subject(rid, "agent-1", B)))
    assert r.status_code == 200 and r.json()["permit"] is False and "differs" in r.json()["reason"]
    r = post("/firewall/consume", tenant[1], request_id=rid, agent_id="agent-1", action=A,
             auth=ag.sign("firewall.consume", fw.consume_subject(rid, "agent-1", A)))
    assert r.json()["permit"] is True                                           # the approved action still works


# ------------------------------------------------------------------ item 4: DLP covers every string, fails closed
@pytest.mark.parametrize("action", [
    {"type": "external_send", "target": "x", "body": AKIA},
    {"type": "external_send", "target": "x", "message": AKIA},
    {"type": "external_send", "target": AKIA},
    {"type": "external_send", "target": "x", "headers": {"X-Note": AKIA}},
    {"type": "external_send", "target": "x", "parts": [["a", ["b", {"c": AKIA}]]]},
    {"type": "external_send", "target": "x", "body": {"a": {"b": {"c": {"d": {"e": {"f": {"g": AKIA}}}}}}}},
    {"type": "external_send", "target": "x", AKIA: "value"},
])
def test_item4_secret_anywhere_in_the_action_blocks(tenant, action):
    r = post("/firewall/authorize", tenant[1], agent_id="a1", action={**action, "environment": "staging"})
    assert r.status_code == 200 and r.json()["decision"] == "BLOCK", r.text
    assert r.json()["policy_id"] == "DLP-SECRET-EXFIL-BLOCK"


def test_item4_a_secret_in_the_context_blocks_too(tenant):
    r = post("/firewall/authorize", tenant[1], agent_id="a1", action={"type": "external_send", "target": "x"},
             context={"environment": "staging", "note": AKIA})
    assert r.json()["decision"] == "BLOCK"


def test_item4_nesting_too_deep_to_scan_is_refused_not_ignored(tenant):
    deep = leaf = {}
    for _ in range(40):
        leaf["n"] = {}
        leaf = leaf["n"]
    leaf["s"] = AKIA
    r = post("/firewall/authorize", tenant[1], agent_id="a1",
             action={"type": "external_send", "target": "x", "environment": "staging", "body": deep})
    assert r.status_code == 400 and "nest" in r.text


def test_item4_oversized_action_is_refused(tenant):
    r = post("/firewall/authorize", tenant[1], agent_id="a1",
             action={"type": "external_send", "target": "x", "environment": "staging", "body": "a" * 300_000})
    assert r.status_code == 400


# ------------------------------------------------------------------ item 5: a nonce yields one decision
def _sign_authorize(ag, action):
    return ag.sign("firewall.authorize", fw.authorize_subject(ag.pid, action))


def test_item5_two_requests_that_both_passed_the_nonce_check_yield_one_decision(tenant, required, monkeypatch):
    ag = Actor(tenant, "agent-1", "agent")
    act = {"type": "write", "target": "file", "environment": "staging"}
    auth = _sign_authorize(ag, act)
    first = fw.authorize(tenant[0], "agent-1", act, None, auth)
    real = idn.nonce_used
    monkeypatch.setattr(idn, "nonce_used", lambda *a, **k: False)            # both requests passed the check first
    with pytest.raises(idn.IdentityDenied):
        fw.authorize(tenant[0], "agent-1", act, None, auth)
    monkeypatch.setattr(idn, "nonce_used", real)
    _, by_req = fw._events(tenant[0])
    assert list(by_req) == [first["request_id"]]                              # the orphan record is void


def test_item5_twelve_concurrent_identical_requests_give_one_permit(tenant, required):
    ag = Actor(tenant, "agent-1", "agent")
    act = {"type": "write", "target": "file", "environment": "staging"}
    auth = _sign_authorize(ag, act)
    codes, ids = [], []

    def go():
        r = post("/firewall/authorize", tenant[1], agent_id="agent-1", action=act, auth=auth)
        codes.append(r.status_code)
        if r.status_code == 200:
            ids.append(r.json()["request_id"])

    ths = [threading.Thread(target=go) for _ in range(12)]
    [t.start() for t in ths]
    [t.join() for t in ths]
    assert Counter(codes) == Counter({200: 1, 401: 11}), Counter(codes)
    permits = 0
    for rid in ids:
        a = ag.sign("firewall.consume", fw.consume_subject(rid, "agent-1", act))
        permits += post("/firewall/consume", tenant[1], request_id=rid, agent_id="agent-1", action=act,
                        auth=a).json()["permit"]
    assert permits == 1


# ------------------------------------------------------------------ item 9: no 500 on malformed input
def test_item9_lone_surrogate_is_a_400(tenant):
    for action in ({"type": "read", "target": "\ud800"}, {"type": "read", "command": "\ud800"}):
        r = C.post("/firewall/authorize", headers={"X-API-Key": tenant[1], "Content-Type": "application/json"},
                   content=json.dumps({"agent_id": "a1", "action": action}))
        assert r.status_code == 400, r.text


@pytest.mark.parametrize("bad", [["x"], {"a": 1}, 12, None])
def test_item9_request_id_must_be_a_string(tenant, bad):
    r = post("/firewall/consume", tenant[1], request_id=bad, agent_id="a1", action={"type": "read"})
    assert r.status_code == 400, r.text
    r = post("/firewall/approve", tenant[1], request_id=bad, approver_id="b1", reason="because")
    assert r.status_code == 400, r.text


# ------------------------------------------------------------------ item 11: `$` accepted a trailing newline
def test_item11_trailing_newline_is_not_part_of_an_id(tenant):
    _, pub = idn.generate_keypair()
    assert post("/identity/enroll", tenant[1], principal_id="runner-1\n", role="runner", public_key=pub).status_code == 400
    assert post("/identity/enroll", tenant[1], principal_id="runner-1", role="runner",
                public_key=pub + "\n").status_code == 400
    r = post("/firewall/authorize", tenant[1], agent_id="a1\n", action={"type": "read"})
    assert r.status_code == 400
    ag_seed, ag_pub = idn.generate_keypair()
    assert post("/identity/enroll", tenant[1], principal_id="agent-1", role="agent", public_key=ag_pub).status_code == 200
    bad = idn.sign_request(ag_seed, tenant[0], "firewall.authorize", "agent-1", "00" * 32, nonce="n" * 16 + "\n")
    with pytest.raises(idn.IdentityDenied):
        idn.verify(idn._chain(tenant[0]), tenant[0], "firewall.authorize", "agent-1", "agent", "00" * 32, bad)


# ------------------------------------------------------------------ items 7, 8, 9: /evidence robustness
H_JSON = lambda key: {"X-API-Key": key, "Content-Type": "application/json"}      # noqa: E731


def test_item8_non_finite_numbers_are_refused_not_stored(tenant):
    r = C.post("/evidence", headers=H_JSON(tenant[1]), content=b'{"payload":{"a":NaN,"c":1e400}}')
    assert r.status_code == 400
    from app import pipeline_bridge as pb
    assert pb.load_chain(tenant[0]) == []                                          # nothing was written
    r = C.post("/evidence", headers=H_JSON(tenant[1]), content=b'{"payload":{"a":1}}')
    assert r.status_code == 200
    assert C.get(f"/evidence/{r.json()['id']}", headers=H_JSON(tenant[1])).status_code == 200


def test_item9_evidence_lone_surrogate_is_a_400(tenant):
    r = C.post("/evidence", headers=H_JSON(tenant[1]), content=json.dumps({"payload": {"a": "\ud800"}}).encode())
    assert r.status_code == 400


def test_item9_evidence_payload_must_be_an_object_of_bounded_size(tenant):
    for bad in ('[1,2]', '"s"', '5'):
        r = C.post("/evidence", headers=H_JSON(tenant[1]), content=('{"payload":%s}' % bad).encode())
        assert r.status_code == 400, (bad, r.text)
    big = json.dumps({"payload": {"a": "x" * 2_000_000}}).encode()
    # 2 MB now trips the request-size guard (413) before the route's own payload bound (400): either way, refused
    assert C.post("/evidence", headers=H_JSON(tenant[1]), content=big).status_code in (400, 413)


def test_item7_concurrent_evidence_writes_all_succeed_and_the_chain_verifies(tenant):
    codes = []

    def go(i):
        codes.append(C.post("/evidence", headers=H_JSON(tenant[1]), content=json.dumps({"payload": {"i": i}}).encode()).status_code)

    ths = [threading.Thread(target=go, args=(i,)) for i in range(24)]
    [t.start() for t in ths]
    [t.join() for t in ths]
    assert Counter(codes) == Counter({200: 24}), Counter(codes)
    from app import pipeline_bridge as pb
    from app.hashchain import verify_chain
    chain = pb.load_chain(tenant[0])
    assert len(chain) == 24 and verify_chain(chain)[0]


# ------------------------------------------------------------------ item 10: hidden assertion ids are not a free oracle
def test_item10_a_probe_with_another_invalid_field_cannot_tell_hidden_from_unknown_ids(tenant, monkeypatch):
    import copy
    import time
    from app import cfr
    manifest = {
        "scenario_id": "cfr-14", "version": "1", "required_assertions": ["tls_handshake_ok", "x509_chain_ok"],
        "hidden_assertions": ["HIDDEN-001"], "variants": ["expired_leaf"],
        "scoring": {"weights": {"availability": 0.35, "latency": 0.2, "time_to_recover": 0.3, "blast_radius": 0.15},
                    "limits": {"availability_zero": 0.9, "latency_p95_ms_full": 200, "latency_p95_ms_zero": 2000,
                               "mttr_s_full": 60, "mttr_s_zero": 900, "blast_radius_full": 1, "blast_radius_zero": 6},
                    "penalties": {"per_restart": 0.02, "max_restarts_penalty": 0.1, "downtime_over_s": 60,
                                  "downtime_penalty": 0.1},
                    "tiers": {"pass": 0.6, "merit": 0.8, "elite": 0.92}}}
    monkeypatch.setenv("OLA_CFR_SEED_SECRET", "a-long-enough-server-secret")
    assert post("/cfr/scenarios", tenant[1], manifest=manifest).status_code == 200
    runner = Actor(tenant, "runner-1", "runner")
    run = post("/cfr/runs", tenant[1], scenario_id="cfr-14", participant_id="alice").json()
    now = time.time()
    base = {"run_id": run["run_id"], "manifest_sha256": run["manifest_sha256"], "started_at": now - 120,
            "ended_at": now - 5, "metrics": {"availability": 1.0, "latency_p95_ms": 150, "mttr_s": 30,
                                            "blast_radius": 1, "restarts": 0, "downtime_s": 0},
            "artifacts": {"bad name!": "zz"}}
    seen = set()
    for guess in ("HIDDEN-001", "HIDDEN-002"):
        sub = copy.deepcopy(base)
        sub["assertions"] = [{"id": guess, "result": "pass"}, {"id": "tls_handshake_ok", "result": "pass"},
                             {"id": "x509_chain_ok", "result": "pass"}]
        body = dict(sub)
        body["auth"] = cfr.sign_result(runner.seed, runner.tid, runner.pid, sub)
        r = post("/cfr/results", tenant[1], **body)
        assert r.status_code == 400
        seen.add(r.json()["detail"])
    assert len(seen) == 1, seen                      # the same answer for a hidden id and a made-up one


# ------------------------------------------------------------------ the point validator on its own
def test_point_validator_accepts_real_keys_and_refuses_the_identity_in_any_form():
    from app.ed25519_point import is_prime_order_point as ok
    for _ in range(5):
        assert ok(bytes.fromhex(idn.generate_keypair()[1]))
    assert not ok(bytes.fromhex("01" + "00" * 31))                  # the identity, canonical
    assert not ok(bytes.fromhex("00" * 32)) and not ok(b"short") and not ok(b"\xff" * 32)
    from tests.test_identity import _small_order_variants
    for raw in _small_order_variants():
        assert not ok(raw)


# ------------------------------------------------------------------ item 7 (agent runtime): same contention, same fix
def test_item7_agent_runtime_evidence_survives_concurrent_writers(tenant, monkeypatch):
    from app import agent_runtime as ar
    from app import pipeline_bridge as pb
    from app.hashchain import verify_chain
    errors = []

    def go(i):
        try:
            ar._append_agent_evidence(tenant[0], f"run-{i}", ar.AGENT_ROLES[0], "task", {"task": "t"}, [], "nonce")
        except Exception as exc:                                    # noqa: BLE001
            errors.append(type(exc).__name__)

    ths = [threading.Thread(target=go, args=(i,)) for i in range(12)]
    [t.start() for t in ths]
    [t.join() for t in ths]
    assert errors == []
    chain = pb.load_chain(tenant[0])
    assert len(chain) == 12 and verify_chain(chain)[0]
