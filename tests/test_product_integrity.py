import json

from app.hashchain import GENESIS_HASH, compute_record_hash
from app.igor_evidence_verifier import verify_chain
from app.human_gate import HumanGate, ReviewDecision
from app.nina_igor import NinaIgorChain
from app.replay import build_replay


def make_record(tenant, seq, prev, payload, record_type="test"):
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return {
        "id": f"r{seq}",
        "tenant_id": tenant,
        "seq": seq,
        "record_type": record_type,
        "payload_json": payload_json,
        "prev_hash": prev,
        "record_hash": compute_record_hash(tenant, seq, prev, payload_json),
    }


def test_hash_chain_detects_payload_mutation():
    first = make_record("t1", 0, GENESIS_HASH, {"value": "original"})
    second = make_record("t1", 1, first["record_hash"], {"value": "next"})
    chain = [first, second]
    assert verify_chain(chain)[0] is True

    chain[0]["payload_json"] = chain[0]["payload_json"].replace("original", "tampered")
    assert verify_chain(chain) == (False, "record hash mismatch")


def test_replay_is_deterministic_and_ordered():
    records = [
        make_record("t1", 1, "x", {"run_id": "run-1", "tool": "b"}, "agent.b"),
        make_record("t1", 0, GENESIS_HASH, {"run_id": "run-1", "tool": "a"}, "agent.a"),
    ]
    replay = build_replay(records)
    assert [item["seq"] for item in replay] == [0, 1]
    assert [item["tool"] for item in replay] == ["a", "b"]


def test_human_gate_is_fail_closed():
    rejected = HumanGate.evaluate("VERIFIED", ReviewDecision(False, "human", "not approved"))
    assert rejected.status == "BLOCK"

    missing_actor = HumanGate.evaluate("VERIFIED", ReviewDecision(True, "", ""))
    assert missing_actor.status == "BLOCK"

    approved = HumanGate.evaluate("VERIFIED", ReviewDecision(True, "human", "approved"))
    assert approved.status == "VERIFIED"


def test_nina_igor_chain_blocks_unknown():
    result = NinaIgorChain.finalize(
        "VERIFIED",
        "UNKNOWN",
        ReviewDecision(True, "human", "approved"),
    )
    assert result["status"] == "BLOCK"
