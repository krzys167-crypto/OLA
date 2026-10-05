"""Per-agent / per-approver identity (app/identity.py) and its use by the Agent Firewall."""
import hashlib
import time
import uuid

import pytest
from fastapi.testclient import TestClient

from app import firewall as fw
from app import identity as idn
from app import pipeline_bridge as pb
from app.database import SessionLocal
from app.main import app
from app.models import ApiKey, Tenant
from ola_pipeline import ed25519 as pure

C = TestClient(app)
TOKEN = "operator-enroll-token"
TOKEN_SHA = hashlib.sha256(TOKEN.encode()).hexdigest()


def make_tenant():
    tid, key = str(uuid.uuid4()), "id-" + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(Tenant(id=tid, name="id"))
        db.add(ApiKey(id=str(uuid.uuid4()), tenant_id=tid, key_hash=hashlib.sha256(key.encode()).hexdigest()))
        db.commit()
    return tid, key


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for v in ("OLA_FIREWALL_AGENT_AUTH", "OLA_IDENTITY_ENROLL_TOKEN_SHA256", "OLA_IDENTITY_MAX_SKEW_S",
              "OLA_FIREWALL_APPROVAL_TTL_S"):
        monkeypatch.delenv(v, raising=False)


@pytest.fixture
def tenant():
    return make_tenant()


def post(path, key, token=None, **body):
    h = {"X-API-Key": key}
    if token:
        h["X-Enroll-Token"] = token
    return C.post(path, headers=h, json=body)


class Actor:
    def __init__(self, tenant, pid, role, enroll=True, token=None):
        self.tid, self.key = tenant
        self.pid, self.role = pid, role
        self.seed, self.pub = idn.generate_keypair()
        if enroll:
            r = post("/identity/enroll", self.key, token, principal_id=pid, role=role, public_key=self.pub)
            assert r.status_code == 200, r.text

    def auth(self, purpose, subject, **kw):
        return idn.sign_request(self.seed, self.tid, purpose, self.pid, subject, **kw)


SHELL = {"type": "shell", "command": "systemctl restart api"}
STAGING = {"environment": "production"}      # shell in production = REVIEW (85); in staging it would be ALLOW (55)


def authorize(actor, action=SHELL, auth="auto", agent=None, key=None):
    agent = agent or actor.pid
    body = {"agent_id": agent, "action": action, "context": STAGING}
    if auth == "auto":
        auth = actor.auth("firewall.authorize", fw.authorize_subject(agent, action, STAGING))
    if auth is not None:
        body["auth"] = auth
    return post("/firewall/authorize", key or actor.key, **body)


def approve(approver, request_id, reason="checked the change", auth="auto", approver_id=None):
    body = {"request_id": request_id, "approver_id": approver_id or approver.pid, "reason": reason}
    if auth == "auto":
        auth = approver.auth("firewall.approve", fw.approve_subject(request_id, reason))
    if auth is not None:
        body["auth"] = auth
    return post("/firewall/approve", approver.key, **body)


def consume(agent, request_id, action=SHELL, auth="auto", agent_id=None):
    aid = agent_id or agent.pid
    body = {"request_id": request_id, "agent_id": aid, "action": action, "context": STAGING}
    if auth == "auto":
        auth = agent.auth("firewall.consume", fw.consume_subject(request_id, aid, action, STAGING))
    if auth is not None:
        body["auth"] = auth
    return post("/firewall/consume", agent.key, **body)


def types(tid):
    return [r["record_type"] for r in pb.load_chain(tid)]


# ------------------------------------------------------------------ crypto plumbing
def test_signatures_interoperate_with_the_standalone_ed25519():
    seed, pub = idn.generate_keypair()
    msg = b"interop"
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sig = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)).sign(msg)
    assert pure.verify(bytes.fromhex(pub), msg, sig)
    assert bytes.fromhex(pub) == pure.public_key(bytes.fromhex(seed))
    assert pure.sign(bytes.fromhex(seed), msg) == sig


def test_small_order_constants_are_really_small_order_and_refused(tenant):
    for raw in idn.SMALL_ORDER_KEYS:
        r = post("/identity/enroll", tenant[1], principal_id="p" + raw.hex()[:8], role="agent", public_key=raw.hex())
        assert r.status_code == 400 and "small-order" in r.text
    assert len(idn.SMALL_ORDER_KEYS) == 8
    _, good = idn.generate_keypair()
    assert bytes.fromhex(good) not in idn.SMALL_ORDER_KEYS


def test_order_eight_check_with_the_independent_implementation():
    ident = pure._decompress(bytes.fromhex("01" + "00" * 31))
    for raw in idn.SMALL_ORDER_KEYS:
        pt = pure._decompress(raw)
        if pt is None:                       # non-decodable encodings are refused anyway
            continue
        assert pure._equal(pure._mul(8, pt), ident), raw.hex()
    seed, pub = idn.generate_keypair()
    assert not pure._equal(pure._mul(8, pure._decompress(bytes.fromhex(pub))), ident)


# ------------------------------------------------------------------ enrolment
@pytest.mark.parametrize("pid,role,pub", [
    (None, "agent", "a" * 64), ("", "agent", "a" * 64), ("a b", "agent", "a" * 64), ("x" * 65, "agent", "a" * 64),
    ("ok", "admin", "a" * 64), ("ok", None, "a" * 64), ("ok", "agent", "zz" * 32), ("ok", "agent", "ab" * 31),
    ("ok", "agent", None), ("ok", "agent", 5),
])
def test_enrol_rejects_malformed_input(tenant, pid, role, pub):
    r = post("/identity/enroll", tenant[1], principal_id=pid, role=role, public_key=pub)
    assert r.status_code == 400, r.text
    assert types(tenant[0]) == []


def test_enrol_lists_and_records_in_the_chain(tenant):
    a = Actor(tenant, "agent-1", "agent")
    b = Actor(tenant, "boss", "approver")
    assert types(tenant[0]) == ["identity.enroll", "identity.enroll"]
    r = C.get("/identity/principals", headers={"X-API-Key": tenant[1]}).json()
    assert r["mode"] == "off"
    assert [(p["principal_id"], p["role"], p["status"]) for p in r["principals"]] == \
        [("agent-1", "agent", "active"), ("boss", "approver", "active")]
    assert a.pub in str(r) and a.seed not in str(r) and b.seed not in str(r)


def test_one_key_one_principal_and_ids_are_never_reused(tenant):
    a = Actor(tenant, "agent-1", "agent")
    r = post("/identity/enroll", tenant[1], principal_id="boss", role="approver", public_key=a.pub)
    assert r.status_code == 409 and "already belongs" in r.text                 # agent key cannot become an approver
    r = post("/identity/enroll", tenant[1], principal_id="agent-1", role="agent", public_key=idn.generate_keypair()[1])
    assert r.status_code == 409 and "never reused" in r.text
    assert post("/identity/revoke", tenant[1], principal_id="agent-1", reason="rotated").status_code == 200
    r = post("/identity/enroll", tenant[1], principal_id="agent-1", role="agent", public_key=idn.generate_keypair()[1])
    assert r.status_code == 409                                                  # not even after revocation
    r = post("/identity/enroll", tenant[1], principal_id="agent-2", role="agent", public_key=a.pub)
    assert r.status_code == 409                                                  # revoked key cannot come back


def test_revoke_rules(tenant):
    Actor(tenant, "agent-1", "agent")
    assert post("/identity/revoke", tenant[1], principal_id="nobody", reason="x").status_code == 409
    assert post("/identity/revoke", tenant[1], principal_id="agent-1", reason="  ").status_code == 400
    assert post("/identity/revoke", tenant[1], principal_id="agent-1", reason="left").status_code == 200
    assert post("/identity/revoke", tenant[1], principal_id="agent-1", reason="again").status_code == 409
    assert types(tenant[0]).count("identity.revoke") == 1


def test_enrol_token_gate(tenant, monkeypatch):
    monkeypatch.setenv("OLA_IDENTITY_ENROLL_TOKEN_SHA256", TOKEN_SHA)
    pub = idn.generate_keypair()[1]
    for tok in (None, "wrong"):
        r = post("/identity/enroll", tenant[1], tok, principal_id="a1", role="agent", public_key=pub)
        assert r.status_code == 401
    assert types(tenant[0]) == []
    assert post("/identity/enroll", tenant[1], TOKEN, principal_id="a1", role="agent", public_key=pub).status_code == 200
    assert post("/identity/revoke", tenant[1], principal_id="a1", reason="x").status_code == 401
    assert post("/identity/revoke", tenant[1], TOKEN, principal_id="a1", reason="x").status_code == 200


def test_enrol_token_config_errors_fail_closed(tenant, monkeypatch):
    pub = idn.generate_keypair()[1]
    monkeypatch.setenv("OLA_IDENTITY_ENROLL_TOKEN_SHA256", "not-hex")
    assert post("/identity/enroll", tenant[1], "x", principal_id="a", role="agent", public_key=pub).status_code == 503
    monkeypatch.delenv("OLA_IDENTITY_ENROLL_TOKEN_SHA256")
    monkeypatch.setenv("OLA_FIREWALL_AGENT_AUTH", "required")           # required without a token: enrolment is off
    r = post("/identity/enroll", tenant[1], principal_id="a", role="agent", public_key=pub)
    assert r.status_code == 503 and "disabled" in r.text
    assert types(tenant[0]) == []


def test_invalid_mode_is_503_not_off(tenant, monkeypatch):
    monkeypatch.setenv("OLA_FIREWALL_AGENT_AUTH", "yes")
    r = post("/firewall/authorize", tenant[1], agent_id="a", action={"type": "read"})
    assert r.status_code == 503 and "OLA_FIREWALL_AGENT_AUTH" in r.text
    assert types(tenant[0]) == []


def test_forged_registry_records_cannot_be_posted(tenant):
    pub = idn.generate_keypair()[1]
    for rtype in ("identity.enroll", "identity.revoke"):
        r = post("/evidence", tenant[1], record_type=rtype, payload={"schema": idn.SCHEMA, "principal_id": "evil",
                                                                       "role": "approver", "public_key": pub})
        assert r.status_code == 400
    assert types(tenant[0]) == []


# ------------------------------------------------------------------ mode off: optional, but never ignored
def test_off_mode_unsigned_is_asserted(tenant):
    r = post("/firewall/authorize", tenant[1], agent_id="agent-1", action={"type": "read"}, context=STAGING)
    assert r.status_code == 200 and r.json()["identity"] == "asserted"


def test_off_mode_signed_is_verified_and_recorded(tenant):
    a = Actor(tenant, "agent-1", "agent")
    r = authorize(a)
    assert r.status_code == 200, r.text
    b = r.json()
    assert b["identity"] == "verified"
    st = C.get(f"/firewall/requests/{b['request_id']}", headers={"X-API-Key": tenant[1]}).json()
    assert st["identity"] == "verified" and st["agent_key_sha256"] == hashlib.sha256(bytes.fromhex(a.pub)).hexdigest()
    rec = [r for r in pb.load_chain(tenant[0]) if r["record_type"] == "firewall.decision"][0]
    assert a.seed not in rec["payload_json"] and "signature\"" not in rec["payload_json"]   # only a digest of it


def test_off_mode_bad_signature_is_denied_not_ignored(tenant):
    a = Actor(tenant, "agent-1", "agent")
    other_seed, _ = idn.generate_keypair()
    bad = idn.sign_request(other_seed, tenant[0], "firewall.authorize", "agent-1",
                           fw.authorize_subject("agent-1", SHELL, STAGING))
    assert authorize(a, auth=bad).status_code == 401
    assert authorize(a, auth="garbage").status_code == 401
    assert [t for t in types(tenant[0]) if t == "firewall.decision"] == []


# ------------------------------------------------------------------ mode required
@pytest.fixture
def strict(monkeypatch):
    monkeypatch.setenv("OLA_FIREWALL_AGENT_AUTH", "required")
    monkeypatch.setenv("OLA_IDENTITY_ENROLL_TOKEN_SHA256", TOKEN_SHA)


def two(tenant):
    return Actor(tenant, "agent-1", "agent", token=TOKEN), Actor(tenant, "boss", "approver", token=TOKEN)


def test_required_unsigned_requests_are_denied(tenant, strict):
    a, b = two(tenant)
    assert authorize(a, auth=None).status_code == 401
    rid = authorize(a).json()["request_id"]
    assert approve(b, rid, auth=None).status_code == 401
    assert consume(a, rid, auth=None).status_code == 401
    assert types(tenant[0]).count("firewall.decision") == 1
    assert "firewall.approval" not in types(tenant[0]) and "firewall.execution" not in types(tenant[0])


def test_required_full_flow_signed_approval_single_permit(tenant, strict):
    a, b = two(tenant)
    d = authorize(a).json()
    assert d["decision"] == "REVIEW" and d["identity"] == "verified"
    assert consume(a, d["request_id"]).json()["permit"] is False                      # not approved yet
    ap = approve(b, d["request_id"])
    assert ap.status_code == 200, ap.text
    c = consume(a, d["request_id"]).json()
    assert c["permit"] is True
    again = consume(a, d["request_id"]).json()
    assert again["permit"] is False and "already used" in again["reason"]
    st = C.get(f"/firewall/requests/{d['request_id']}", headers={"X-API-Key": tenant[1]}).json()
    assert st["approval"]["identity"] == "verified" and st["phase"] == "EXECUTED"


def test_signature_is_bound_to_the_exact_action(tenant, strict):
    a, _ = two(tenant)
    signed_for_read = a.auth("firewall.authorize", fw.authorize_subject("agent-1", {"type": "read"}, STAGING))
    assert authorize(a, SHELL, auth=signed_for_read).status_code == 401              # reused for a different action
    assert authorize(a, {"type": "read"}, auth=signed_for_read).status_code == 200


def test_signature_is_bound_to_purpose_and_tenant(tenant, strict):
    a, _ = two(tenant)
    sub = fw.authorize_subject("agent-1", SHELL, STAGING)
    wrong_purpose = a.auth("firewall.consume", sub)
    assert authorize(a, auth=wrong_purpose).status_code == 401
    other = make_tenant()
    foreign = idn.sign_request(a.seed, other[0], "firewall.authorize", "agent-1", sub)
    assert authorize(a, auth=foreign).status_code == 401


def test_agent_cannot_sign_as_someone_else(tenant, strict):
    a, _ = two(tenant)
    mallory = Actor(tenant, "agent-2", "agent", token=TOKEN)
    sub = fw.authorize_subject("agent-1", SHELL, STAGING)
    forged = idn.sign_request(mallory.seed, tenant[0], "firewall.authorize", "agent-1", sub)   # agent-2's key, agent-1's name
    assert authorize(a, auth=forged).status_code == 401
    r = authorize(a, agent="agent-9", auth=a.auth("firewall.authorize", fw.authorize_subject("agent-9", SHELL, STAGING)))
    assert r.status_code == 401                                                       # unknown principal


def test_roles_are_enforced(tenant, strict):
    a, b = two(tenant)
    r = authorize(b, agent="boss")                                                    # an approver cannot act as an agent
    assert r.status_code == 401 and "not enrolled as 'agent'" in r.text
    rid = authorize(a).json()["request_id"]
    r = approve(a, rid, approver_id="agent-1")                                        # an agent cannot approve
    assert r.status_code == 401
    assert "firewall.approval" not in types(tenant[0])


def test_agent_key_cannot_be_enrolled_as_its_own_approver(tenant, strict):
    a, _ = two(tenant)
    r = post("/identity/enroll", tenant[1], TOKEN, principal_id="agent-1-as-approver", role="approver", public_key=a.pub)
    assert r.status_code == 409


def test_approval_signature_is_bound_to_the_reason(tenant, strict):
    a, b = two(tenant)
    rid = authorize(a).json()["request_id"]
    sig_for_other_reason = b.auth("firewall.approve", fw.approve_subject(rid, "looks fine"))
    assert approve(b, rid, reason="rm -rf everything", auth=sig_for_other_reason).status_code == 401
    other_request = b.auth("firewall.approve", fw.approve_subject("req_other", "ok"))
    assert approve(b, rid, reason="ok", auth=other_request).status_code == 401
    assert approve(b, rid, reason="ok").status_code == 200


def test_consume_by_another_agent_is_denied(tenant, strict):
    a, b = two(tenant)
    m = Actor(tenant, "agent-2", "agent", token=TOKEN)
    rid = authorize(a).json()["request_id"]
    approve(b, rid)
    assert consume(m, rid, agent_id="agent-1").status_code == 401                     # signs as agent-2 for agent-1
    c = consume(m, rid)                                                               # signs as itself: different action digest
    assert c.status_code == 200 and c.json()["permit"] is False and "differs" in c.json()["reason"]
    assert consume(a, rid).json()["permit"] is True                                   # the real agent still can, once


def test_replay_stale_future_and_nonce_rules(tenant, strict, monkeypatch):
    a, _ = two(tenant)
    sub = fw.authorize_subject("agent-1", SHELL, STAGING)
    auth = a.auth("firewall.authorize", sub)
    assert authorize(a, auth=auth).status_code == 200
    r = authorize(a, auth=auth)                                                       # exact replay
    assert r.status_code == 401 and "nonce" in r.text
    assert types(tenant[0]).count("firewall.decision") == 1
    for ts in (time.time() - 3600, time.time() + 3600):
        r = authorize(a, auth=a.auth("firewall.authorize", sub, ts=ts))
        assert r.status_code == 401 and "skew" in r.text
    for bad in ({"ts": "now", "nonce": "n" * 20, "signature": "0" * 128}, {"ts": True, "nonce": "n" * 20, "signature": "0" * 128},
                {"ts": time.time(), "nonce": "short", "signature": "0" * 128},
                {"ts": time.time(), "nonce": "n" * 20, "signature": "zz"},
                {"ts": time.time(), "nonce": "n" * 20}, [], 7):
        assert authorize(a, auth=bad).status_code == 401, bad
    raw = ('{"agent_id":"agent-1","action":{"type":"read"},"auth":{"ts":NaN,"nonce":"' + "n" * 20 + '","signature":"'
           + "0" * 128 + '"}}')                                                   # NaN is not valid JSON but Python parses it
    r = C.post("/firewall/authorize", headers={"X-API-Key": tenant[1], "Content-Type": "application/json"}, content=raw)
    assert r.status_code == 401
    monkeypatch.setenv("OLA_IDENTITY_MAX_SKEW_S", "7200")                              # the window is configurable
    assert authorize(a, auth=a.auth("firewall.authorize", sub, ts=time.time() - 3600)).status_code == 200


def test_revoked_agent_is_locked_out_immediately(tenant, strict):
    a, b = two(tenant)
    rid = authorize(a).json()["request_id"]
    approve(b, rid)
    assert post("/identity/revoke", tenant[1], TOKEN, principal_id="agent-1", reason="compromised").status_code == 200
    assert consume(a, rid).status_code == 401
    assert authorize(a).status_code == 401
    assert "firewall.execution" not in types(tenant[0])


def test_revoked_approver_cannot_approve(tenant, strict):
    a, b = two(tenant)
    rid = authorize(a).json()["request_id"]
    post("/identity/revoke", tenant[1], TOKEN, principal_id="boss", reason="left the company")
    assert approve(b, rid).status_code == 401


def test_decision_made_before_required_cannot_be_approved_or_consumed(tenant, monkeypatch):
    monkeypatch.setenv("OLA_IDENTITY_ENROLL_TOKEN_SHA256", TOKEN_SHA)
    a, b = two(tenant)
    rid = post("/firewall/authorize", tenant[1], agent_id="agent-1", action=SHELL, context=STAGING).json()["request_id"]
    monkeypatch.setenv("OLA_FIREWALL_AGENT_AUTH", "required")
    r = approve(b, rid)
    assert r.status_code == 409 and "not made by a verified agent" in r.text
    # in off mode an (unsigned) approval is still possible, but then consume in required mode refuses
    monkeypatch.setenv("OLA_FIREWALL_AGENT_AUTH", "off")
    assert approve(b, rid, auth=None, approver_id="human").status_code == 200
    monkeypatch.setenv("OLA_FIREWALL_AGENT_AUTH", "required")
    c = consume(a, rid).json()
    assert c["permit"] is False and "not made by a verified agent" in c["reason"]


def test_same_key_check_in_the_firewall_itself(tenant, strict, monkeypatch):
    """Defense in depth: even if a registry let an approver key equal the agent key, approve() refuses it."""
    a, b = two(tenant)
    rid = authorize(a).json()["request_id"]
    real = idn.registry

    def merged(chain):
        reg, keys = real(chain)
        reg["boss"]["public_key"] = reg["agent-1"]["public_key"]
        return reg, keys
    monkeypatch.setattr(idn, "registry", merged)
    sig = a.auth("firewall.approve", fw.approve_subject(rid, "ok"))                    # agent signs as 'boss' with its own key
    sig_body = {"request_id": rid, "approver_id": "boss", "reason": "ok", "auth": sig}
    r = post("/firewall/approve", b.key, **sig_body)
    assert r.status_code == 401 or r.status_code == 409                                # principal id is part of the signed message
    r = post("/firewall/approve", b.key, request_id=rid, approver_id="boss", reason="ok",
             auth=idn.sign_request(a.seed, tenant[0], "firewall.approve", "boss", fw.approve_subject(rid, "ok")))
    assert r.status_code == 409 and "same key" in r.text
    assert "firewall.approval" not in types(tenant[0])


def test_tenants_have_separate_registries(tenant, strict):
    a, _ = two(tenant)
    other = make_tenant()
    ghost = Actor(other, "agent-1", "agent", enroll=False)
    ghost.seed, ghost.pub = a.seed, a.pub                                              # same key material, other tenant
    r = authorize(ghost)
    assert r.status_code == 401 and "unknown principal" in r.text


def test_broken_chain_refuses_identity_decisions(tenant, strict):
    from sqlalchemy import text
    a, _ = two(tenant)
    with SessionLocal() as db:
        db.execute(text("DROP TRIGGER IF EXISTS evidence_no_update"))
        db.execute(text("UPDATE evidence_records SET payload_json = payload_json || ' ' WHERE tenant_id = :t AND seq = 0"),
                   {"t": tenant[0]})
        db.commit()
    try:
        assert authorize(a).status_code == 503
        assert C.get("/identity/principals", headers={"X-API-Key": tenant[1]}).status_code == 503
    finally:
        with SessionLocal() as db:
            db.execute(text("CREATE TRIGGER IF NOT EXISTS evidence_no_update BEFORE UPDATE ON evidence_records "
                            "BEGIN SELECT RAISE(ABORT, 'evidence_records is append-only'); END;"))
            db.commit()


def test_principal_limit(tenant, monkeypatch):
    monkeypatch.setattr(idn, "MAX_PRINCIPALS", 2)
    Actor(tenant, "a1", "agent")
    Actor(tenant, "a2", "agent")
    r = post("/identity/enroll", tenant[1], principal_id="a3", role="agent", public_key=idn.generate_keypair()[1])
    assert r.status_code == 409 and "at most" in r.text


def test_policy_digest_unchanged_by_identity():
    assert fw.policy_digest() == "b3a548f3116560352c090594042a166451c147c267eeb11b03722201036fae42"


# ------------------------------------------------------------------ registry reading and message format
def _rec(seq, rtype, payload):
    import json
    return {"seq": seq, "record_type": rtype, "payload_json": json.dumps(payload)}


def _enroll(seq, pid, role, pub):
    return _rec(seq, "identity.enroll", {"schema": idn.SCHEMA, "principal_id": pid, "role": role, "public_key": pub})


def test_registry_first_enrolment_of_an_id_or_a_key_wins_when_reading():
    k1, k2, k3 = "11" * 32, "22" * 32, "33" * 32
    chain = [_enroll(0, "a", "agent", k1),
             _enroll(1, "a", "approver", k2),            # same id, other key: ignored
             _enroll(2, "b", "approver", k1),            # same key, other id: ignored
             _enroll(3, "c", "root", k3),                 # unknown role: ignored
             _enroll(4, "d", "agent", k3),
             _rec(5, "identity.revoke", {"schema": idn.SCHEMA, "principal_id": "ghost"}),
             _rec(6, "identity.enroll", {"schema": "other/1", "principal_id": "e", "role": "agent", "public_key": "44" * 32}),
             {"seq": 7, "record_type": "identity.enroll", "payload_json": "{not json"}]
    reg, keys = idn.registry(chain)
    assert sorted(reg) == ["a", "d"] and reg["a"]["role"] == "agent" and reg["a"]["public_key"] == k1
    assert keys == {k1: "a", k3: "d"}
    chain.append(_rec(8, "identity.revoke", {"schema": idn.SCHEMA, "principal_id": "a"}))
    reg, _ = idn.registry(chain)
    assert reg["a"]["status"] == "revoked" and reg["a"]["revoked_seq"] == 8 and reg["d"]["status"] == "active"


def test_signed_message_format_is_pinned():
    msg = idn.request_message("T", "firewall.authorize", "agent-1", "ab" * 32, 1700000000.5, "n" * 20)
    assert msg == (b'{"nonce":"nnnnnnnnnnnnnnnnnnnn","principal_id":"agent-1","purpose":"firewall.authorize",'
                   b'"schema":"ola.identity.request/1","subject_sha256":"' + b"ab" * 32 + b'","tenant_id":"T",'
                   b'"ts":1700000000.5}')


def test_properly_signed_but_malformed_fields_are_still_denied(tenant, strict):
    a, _ = two(tenant)
    sub = fw.authorize_subject("agent-1", SHELL, STAGING)
    short = idn.sign_request(a.seed, tenant[0], "firewall.authorize", "agent-1", sub, nonce="short")
    assert authorize(a, auth=short).status_code == 401                                  # valid signature, bad nonce shape
    import json as _json
    sig = idn.sign_request(a.seed, tenant[0], "firewall.authorize", "agent-1", sub, ts=float("nan"), nonce="n" * 20)
    raw = _json.dumps({"agent_id": "agent-1", "action": SHELL, "context": STAGING, "auth": sig})   # contains NaN
    assert "NaN" in raw
    r = C.post("/firewall/authorize", headers={"X-API-Key": tenant[1], "Content-Type": "application/json"}, content=raw)
    assert r.status_code == 401                          # NaN would sail through an `abs(now - ts) > skew` comparison
    booly = idn.sign_request(a.seed, tenant[0], "firewall.authorize", "agent-1", sub, ts=True, nonce="m" * 20)
    assert authorize(a, auth=booly).status_code == 401
    assert types(tenant[0]).count("firewall.decision") == 0
