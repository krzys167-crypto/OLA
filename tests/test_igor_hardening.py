"""Regression tests for gaps found by black-box probing of the upstream NINA/IGOR boundary.

Written against upstream PR #60 (which already rewrote IgorVerifier: agent.* records only, all() instead of any(),
source_commit, replay nonce). Each test was RED on the code it targets before its fix. None of them changes a
verdict that was correct before: a clean run still VERIFIES.
"""
import json

import pytest

from app.hashchain import GENESIS_HASH, canonical_json, compute_record_hash
from app.human_gate import HumanGate, ReviewDecision
from app.igor import IgorVerifier
from app.nina import NinaOrchestrator, NinaTask
from app.nina_igor import STATUS_FIELDS, NinaIgorChain


def chain(payloads, tenant="t1", types=None):
    out, prev = [], GENESIS_HASH
    for i, p in enumerate(payloads):
        pj = canonical_json(p)
        h = compute_record_hash(tenant, i, prev, pj)
        out.append({"id": f"r{i}", "tenant_id": tenant, "seq": i, "prev_hash": prev, "record_hash": h,
                    "record_type": (types[i] if types else f"agent.{p.get('agent', 'x') if isinstance(p, dict) else 'x'}"),
                    "payload_json": pj})
        prev = h
    return out


def verify(payloads, commit="c1", task="T", result="42", types=None, **kw):
    return IgorVerifier().verify_records(chain(payloads, types=types), commit, task, result, **kw)


GOOD = dict(run_id="A", agent="codeact", commit="c1", source_commit="c1", task="T", tool_output="42")


# ------------------------------------------------------------------ IGOR
def test_clean_evidence_still_verifies():
    r = verify([GOOD], expected_run_id="A")
    assert r.status == "VERIFIED" and r.evidence_ids == ("r0",)


def test_a_run_without_any_result_bearing_agent_is_not_verified():
    # upstream skipped the result comparison entirely when neither codeact nor multi_agent was present
    only_react = dict(run_id="A", agent="react", commit="c1", source_commit="c1", task="T")
    r = verify([only_react], result="whatever", expected_run_id="A")
    assert r.status == "BLOCK" and r.reason == "result mismatch"


@pytest.mark.parametrize("expected", ["None", None])
def test_a_missing_result_never_matches_str_of_the_expectation(expected):
    rec = dict(GOOD)
    del rec["tool_output"]                    # codeact record without a tool_output
    assert verify([rec], result=expected, expected_run_id="A").status == "BLOCK"
    rec["tool_output"] = None                 # or an explicit null
    assert verify([rec], result=expected, expected_run_id="A").status == "BLOCK"


def test_a_final_result_of_the_multi_agent_record_is_still_compared():
    final = dict(GOOD, agent="multi_agent", final_result="42")
    del final["tool_output"]
    assert verify([final], expected_run_id="A").status == "VERIFIED"
    assert verify([dict(final, final_result="43")], expected_run_id="A").status == "BLOCK"


def test_a_malformed_record_does_not_crash_the_verifier():
    good = chain([GOOD])
    junk_pj = "not json"
    junk = {"id": "j", "tenant_id": "t1", "seq": 1, "prev_hash": good[0]["record_hash"], "record_type": "agent.x",
            "payload_json": junk_pj, "record_hash": compute_record_hash("t1", 1, good[0]["record_hash"], junk_pj)}
    r = IgorVerifier().verify_records(good + [junk], "c1", "T", "42", expected_run_id="A")
    assert r.status == "VERIFIED"
    assert IgorVerifier().verify_records([junk], "c1", "T", "42").status in ("UNKNOWN", "BLOCK")


def test_non_object_payload_does_not_crash():
    pj = json.dumps([1, 2, 3])
    rec = {"id": "j", "tenant_id": "t1", "seq": 0, "prev_hash": GENESIS_HASH, "record_type": "agent.x", "payload_json": pj,
           "record_hash": compute_record_hash("t1", 0, GENESIS_HASH, pj)}
    assert IgorVerifier().verify_records([rec], "c1", "T", "42").status in ("UNKNOWN", "BLOCK")


def test_cross_run_evidence_without_a_run_id_is_blocked():
    other = dict(GOOD, run_id="B", task="other", tool_output="old")
    assert verify([other, GOOD]).status == "BLOCK"


def test_empty_expected_commit_is_BLOCK():
    assert verify([GOOD], commit="", expected_run_id="A").status == "BLOCK"


def test_unknown_run_id_is_UNKNOWN_not_BLOCK_or_VERIFIED():
    assert verify([GOOD], expected_run_id="nope").status == "UNKNOWN"


def test_a_tampered_chain_is_still_BLOCK():
    recs = chain([GOOD])
    recs[0]["payload_json"] = canonical_json(dict(GOOD, tool_output="43"))
    assert IgorVerifier().verify_records(recs, "c1", "T", "43", expected_run_id="A").status == "BLOCK"


# ------------------------------------------------------------------ NINA planner
@pytest.mark.parametrize("tools", [[1], [None], [["safe_expression"]], [{"a": 1}], ["safe_expression", 5]])
def test_non_string_tool_names_are_BLOCK_not_an_exception(tools):
    d = NinaOrchestrator().plan(NinaTask.create("t1", "task", tools))
    assert d.status == "BLOCK" and d.allowed_tools == ()


@pytest.mark.parametrize("tools", [5, None, {"safe_expression": 1}, 3.5])
def test_non_list_tool_container_is_a_ValueError(tools):
    with pytest.raises(ValueError):
        NinaTask.create("t1", "task", tools)


def test_registered_tools_still_allowed():
    d = NinaOrchestrator().plan(NinaTask.create("t1", "task", ["safe_expression"]))
    assert d.status == "ALLOW" and d.allowed_tools == ("safe_expression",)


# ------------------------------------------------------------------ status chain + human gate
OK = {f: "VERIFIED" for f in STATUS_FIELDS}


@pytest.mark.parametrize("bad", [["VERIFIED"], {"a": 1}, None, 1, b"VERIFIED"])
def test_non_string_status_value_is_BLOCK_not_an_exception(bad):
    assert NinaIgorChain.derive_status(dict(OK, POLICY=bad)) == "BLOCK"


@pytest.mark.parametrize("approved", ["false", "no", "0", 1, "True", [], None])
def test_only_a_real_boolean_true_approves(approved):
    assert HumanGate.evaluate("VERIFIED", ReviewDecision(approved, "h", "r")).status == "BLOCK"


def test_real_true_still_approves():
    assert HumanGate.evaluate("VERIFIED", ReviewDecision(True, "h", "r")).status == "VERIFIED"


@pytest.mark.parametrize("actor", [None, 5, ["h"]])
def test_non_string_actor_is_BLOCK_not_an_exception(actor):
    assert HumanGate.evaluate("VERIFIED", ReviewDecision(True, actor, "r")).status == "BLOCK"
