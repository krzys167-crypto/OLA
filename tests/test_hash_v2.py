"""Hash format v2: the record type is part of the record hash (second security review, item 6)."""
import hashlib
import json
import subprocess
import sys
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app import business_runtime, identity as idn, pipeline_bridge as pb, stripe_webhook
from app.database import SessionLocal
from app.hashchain import GENESIS_HASH, canonical_json, compute_record_hash, verify_chain
from app.main import app
from app.models import ApiKey, Tenant

C = TestClient(app, raise_server_exceptions=False)
_TRIGGER = ("CREATE TRIGGER IF NOT EXISTS evidence_no_update BEFORE UPDATE ON evidence_records "
            "BEGIN SELECT RAISE(ABORT, 'evidence_records is append-only'); END;")


def make_tenant():
    tid, key = str(uuid.uuid4()), "h2-" + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(Tenant(id=tid, name="h2"))
        db.add(ApiKey(id=str(uuid.uuid4()), tenant_id=tid, key_hash=hashlib.sha256(key.encode()).hexdigest()))
        db.commit()
    return tid, key


def build(rows, v2_from=0):
    """rows: [(record_type, payload)] -> chain dicts, v1 before index `v2_from`, v2 from it on."""
    chain, prev = [], GENESIS_HASH
    for i, (rt, payload) in enumerate(rows):
        pj = canonical_json(payload)
        h = compute_record_hash("t", i, prev, pj, rt if i >= v2_from else None)
        chain.append({"tenant_id": "t", "seq": i, "record_type": rt, "prev_hash": prev, "record_hash": h,
                      "payload_json": pj})
        prev = h
    return chain


ROWS = [("generic", {"a": 1}), ("identity.enroll", {"b": 2}), ("firewall.decision", {"c": 3})]


def test_v2_covers_the_type_and_is_domain_separated():
    v1 = compute_record_hash("t", 0, GENESIS_HASH, "{}")
    a = compute_record_hash("t", 0, GENESIS_HASH, "{}", "generic")
    b = compute_record_hash("t", 0, GENESIS_HASH, "{}", "identity.enroll")
    assert len({v1, a, b}) == 3
    assert a == hashlib.sha256(f"ola.chain/2|t|0|{GENESIS_HASH}|7:generic|{{}}".encode()).hexdigest()
    # the type is length-prefixed: (type, payload) pairs cannot be re-split into one another
    assert compute_record_hash("t", 0, GENESIS_HASH, "x|{}", "a") != compute_record_hash("t", 0, GENESIS_HASH, "{}", "a|x")


def test_a_v2_chain_verifies_and_a_retyped_record_does_not():
    chain = build(ROWS)
    assert verify_chain(chain) == (True, "ok")
    for i in range(len(chain)):
        bad = [dict(r) for r in chain]
        bad[i]["record_type"] = "identity.enroll" if bad[i]["record_type"] != "identity.enroll" else "generic"
        assert verify_chain(bad)[0] is False, i


def test_a_record_without_a_type_cannot_pass_in_a_v2_chain():
    chain = build(ROWS)
    stripped = [{k: v for k, v in r.items() if k != "record_type"} for r in chain]
    assert verify_chain(stripped)[0] is False


def test_legacy_v1_chains_still_verify():
    assert verify_chain(build(ROWS, v2_from=99)) == (True, "ok")


def test_v1_prefix_then_v2_verifies_but_v1_after_v2_does_not():
    assert verify_chain(build(ROWS, v2_from=1))[0] is True
    chain = build(ROWS, v2_from=1)                   # seq 0 is v1, seq 1.. are v2
    pj = chain[2]["payload_json"]
    chain[2]["record_hash"] = compute_record_hash("t", 2, chain[2]["prev_hash"], pj)       # swap a v2 record for a v1 one
    assert verify_chain(chain)[0] is False


def test_known_limit_legacy_v1_records_are_not_type_bound():
    """Documented: a record written before v2 can still be retyped undetected (needs DB write access)."""
    chain = build(ROWS, v2_from=99)
    chain[0]["record_type"] = "identity.enroll"
    assert verify_chain(chain)[0] is True


def test_review_attack_a_generic_record_retyped_as_an_enrolment_is_detected():
    tid, key = make_tenant()
    _, pub = idn.generate_keypair()
    H = {"X-API-Key": key}
    r = C.post("/evidence", headers=H, json={"record_type": "generic", "payload": {
        "schema": idn.SCHEMA, "principal_id": "evil", "role": "approver", "public_key": pub}})
    assert r.status_code == 200
    assert C.get("/identity/principals", headers=H).json()["principals"] == []
    with SessionLocal() as db:
        db.execute(text("DROP TRIGGER IF EXISTS evidence_no_update"))
        db.execute(text("UPDATE evidence_records SET record_type='identity.enroll' WHERE tenant_id=:t"), {"t": tid})
        db.commit()
    try:
        assert verify_chain(pb.load_chain(tid))[0] is False
        r = C.get("/identity/principals", headers=H)
        assert r.status_code == 503                                # the forged approver is never listed
    finally:
        with SessionLocal() as db:
            db.execute(text(_TRIGGER))
            db.commit()


def _all_records_are_v2(tid):
    chain = pb.load_chain(tid)
    assert chain and verify_chain(chain) == (True, "ok")
    for r in chain:
        assert r["record_hash"] == compute_record_hash(r["tenant_id"], r["seq"], r["prev_hash"], r["payload_json"],
                                                       r["record_type"]), r["record_type"]


def test_every_writer_in_the_code_base_writes_v2():
    tid, key = make_tenant()
    C.post("/evidence", headers={"X-API-Key": key}, json={"record_type": "generic", "payload": {"a": 1}})   # route
    pb.append_evidence(tid, "pipeline.x", {"a": 1})                                                         # bridge
    business_runtime._append(tid, "run-1", "business.x", {"a": 1})                                          # business
    stripe_webhook._append_evidence(tid, "stripe.x", {"a": 1})                                              # stripe
    from app import agent_runtime as ar
    ar._append_agent_evidence(tid, "run-2", ar.AGENT_ROLES[0], "task", {"task": "t"}, [], "nonce")          # agents
    _all_records_are_v2(tid)
    assert len(pb.load_chain(tid)) == 5


def test_the_verify_endpoint_reports_a_retyped_record_as_fail():
    tid, key = make_tenant()
    H = {"X-API-Key": key}
    rid = C.post("/evidence", headers=H, json={"record_type": "generic", "payload": {"a": 1}}).json()["id"]
    assert C.post(f"/evidence/{rid}/verify", headers=H).json()["verification"] == "PASS"
    with SessionLocal() as db:
        db.execute(text("DROP TRIGGER IF EXISTS evidence_no_update"))
        db.execute(text("UPDATE evidence_records SET record_type='other' WHERE id=:i"), {"i": rid})
        db.commit()
    try:
        assert C.post(f"/evidence/{rid}/verify", headers=H).json()["verification"] == "FAIL"
    finally:
        with SessionLocal() as db:
            db.execute(text(_TRIGGER))
            db.commit()


def test_a_typeless_v1_record_cannot_follow_v2_records():
    chain = build(ROWS)
    pj = canonical_json({"d": 4})
    h = compute_record_hash("t", 3, chain[-1]["record_hash"], pj)                      # v1 hash, no record_type key
    chain.append({"tenant_id": "t", "seq": 3, "prev_hash": chain[-1]["record_hash"], "record_hash": h, "payload_json": pj})
    assert verify_chain(chain)[0] is False
