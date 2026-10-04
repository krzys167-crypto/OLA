"""Regression tests for gaps found by black-box probing of the upstream NINA/IGOR boundary (a59f8c1).

Each test was RED against the upstream code before the fix (see docs/pipeline-bridge.md, "Upstream IGOR
hardening"). None of them changes a verdict that was correct before: a clean run still VERIFIES.
"""
import json

import pytest

from app.hashchain import GENESIS_HASH, canonical_json, compute_record_hash
from app.human_gate import HumanGate, ReviewDecision
from app.igor import IgorVerifier
from app.nina import NinaOrchestrator, NinaTask
from app.nina_igor import STATUS_FIELDS, NinaIgorChain


def chain(payloads, tenant="t1"):
    out, prev = [], GENESIS_HASH
    for i, p in enumerate(payloads):
        pj = canonical_json(p)
        h = compute_record_hash(tenant, i, prev, pj)
        out.append({"id": f"r{i}", "tenant_id": tenant, "seq": i, "prev_hash": prev, "record_hash": h,
                    "record_type": "agent.x", "payload_json": pj})
        prev = h
    return out


def verify(payloads, commit="c1", task="T", result="42", **kw):
    return IgorVerifier().verify_records(chain(payloads), commit, task, result, **kw)


GOOD = dict(run_id="A", commit="c1", task="T", result="42")


# ------------------------------------------------------------------ IGOR: one record must carry the claim
def test_clean_evidence_still_verifies():
    r = verify([GOOD], expected_run_id="A")
    assert r.status == "VERIFIED" and r.evidence_ids == ("r0",)


def test_commit_task_and_result_must_come_from_ONE_record():
    spliced = [dict(run_id="A", commit="c1"), dict(run_id="A", task="T"), dict(run_id="A", result="42")]
    assert verify(spliced, expected_run_id="A").status == "BLOCK"


def test_task_from_one_record_result_from_another_is_blocked():
    spliced = [dict(run_id="A", commit="c1", task="T", result="old"), dict(run_id="A", commit="c1", task="other", result="42")]
    r = verify(spliced, expected_run_id="A")
    assert r.status == "BLOCK"


def test_cross_run_splice_without_a_run_id_is_blocked():
    spliced = [dict(run_id="A", commit="c1", task="T", result="old"), dict(run_id="B", commit="c1", task="other", result="42")]
    assert verify(spliced).status == "BLOCK"


def test_without_a_run_id_one_complete_run_is_enough_and_only_its_records_are_evidence():
    recs = [dict(run_id="B", commit="c1", task="x", result="y"), GOOD]
    r = verify(recs)
    assert r.status == "VERIFIED" and r.evidence_ids == ("r1",)


def test_provider_and_model_must_come_from_the_record_that_carries_the_claim():
    prov = dict(GOOD, provider="ollama", invocation_type="real_llm", model="evil", response_ids=["x"])
    other = dict(run_id="A", provider="openai", invocation_type="local", model="good")
    r = verify([prov, other], expected_run_id="A", expected_provider="ollama", expected_model="good")
    assert r.status == "BLOCK"


def test_real_run_shape_provenance_record_plus_agent_records_still_verifies():
    prov = dict(GOOD, provider="ollama", invocation_type="real_llm", model="m", response_ids=["ollama:1"])
    agent = dict(run_id="A", agent="react", provider="ollama", invocation_type="real_llm", model="m", tool_output="42")
    r = verify([agent, prov], expected_run_id="A", expected_provider="ollama", expected_model="m")
    assert r.status == "VERIFIED" and r.checks["provider"] and r.checks["model"]


@pytest.mark.parametrize("expected", [None, "None", 42, ["42"], ""])
def test_a_missing_result_never_matches_str_of_the_expectation(expected):
    r = verify([dict(run_id="A", commit="c1", task="T")], result=expected, expected_run_id="A")
    assert r.status == "BLOCK"


def test_result_comparison_is_type_strict():
    assert verify([dict(GOOD, result=42)], result="42", expected_run_id="A").status == "BLOCK"
    assert verify([dict(GOOD, result="42")], result=42, expected_run_id="A").status == "BLOCK"


def test_tool_output_can_carry_the_result():
    rec = dict(run_id="A", commit="c1", task="T", tool_output="42")
    assert verify([rec], expected_run_id="A").status == "VERIFIED"


def test_a_malformed_record_is_not_evidence_and_does_not_crash():
    good = chain([GOOD])
    junk_pj = "not json"
    junk = {"id": "j", "tenant_id": "t1", "seq": 1, "prev_hash": good[0]["record_hash"], "record_type": "x",
            "payload_json": junk_pj, "record_hash": compute_record_hash("t1", 1, good[0]["record_hash"], junk_pj)}
    r = IgorVerifier().verify_records(good + [junk], "c1", "T", "42", expected_run_id="A")
    assert r.status == "VERIFIED"
    only_junk = IgorVerifier().verify_records([junk], "c1", "T", "42")
    assert only_junk.status in ("UNKNOWN", "BLOCK")


def test_non_object_payload_does_not_crash():
    pj = json.dumps([1, 2, 3])
    rec = {"id": "j", "tenant_id": "t1", "seq": 0, "prev_hash": GENESIS_HASH, "record_type": "x", "payload_json": pj,
           "record_hash": compute_record_hash("t1", 0, GENESIS_HASH, pj)}
    assert IgorVerifier().verify_records([rec], "c1", "T", "42").status in ("UNKNOWN", "BLOCK")


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


def test_empty_expected_commit_is_BLOCK_even_if_the_evidence_has_an_empty_commit():
    assert verify([dict(GOOD, commit="")], commit="", expected_run_id="A").status == "BLOCK"
    assert verify([GOOD], commit="", expected_run_id="A").status == "BLOCK"


def test_unknown_run_id_is_UNKNOWN_not_BLOCK_or_VERIFIED():
    assert verify([GOOD], expected_run_id="nope").status == "UNKNOWN"


def test_a_tampered_chain_is_still_BLOCK():
    recs = chain([GOOD])
    recs[0]["payload_json"] = canonical_json(dict(GOOD, result="43"))
    assert IgorVerifier().verify_records(recs, "c1", "T", "43", expected_run_id="A").status == "BLOCK"


def test_task_and_result_from_a_record_that_does_not_carry_the_commit_is_blocked():
    recs = [dict(run_id="A", commit="c1"), dict(run_id="A", task="T", result="42")]
    assert verify(recs, expected_run_id="A").status == "BLOCK"
