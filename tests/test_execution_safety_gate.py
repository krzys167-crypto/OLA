import pytest


def test_unknown_action_is_blocked_without_side_effect():
    from app.execution_safety_gate import ExecutionSafetyGate

    gate = ExecutionSafetyGate()
    effects = []

    decision = gate.execute(
        agent_id="agent-001",
        action="delete_external_data",
        effect=lambda: effects.append("MUST_NOT_RUN"),
    )

    assert decision.status == "BLOCK"
    assert decision.policy == "deny-by-default"
    assert decision.side_effect_count == 0
    assert effects == []


def test_high_risk_action_requires_human_owner():
    from app.execution_safety_gate import ExecutionSafetyGate

    gate = ExecutionSafetyGate()
    effects = []

    decision = gate.execute(
        agent_id="agent-001",
        action="send_external_message",
        effect=lambda: effects.append("MUST_NOT_RUN"),
        risk="HIGH",
        human_approved=False,
    )

    assert decision.status == "REVIEW"
    assert decision.required_approval == "HUMAN_OWNER"
    assert decision.side_effect_count == 0
    assert effects == []


def test_explicitly_allowed_action_executes_once_and_is_observable():
    from app.execution_safety_gate import ExecutionSafetyGate

    gate = ExecutionSafetyGate(allowed_actions={"read_local_evidence"})
    effects = []

    decision = gate.execute(
        agent_id="agent-001",
        action="read_local_evidence",
        effect=lambda: effects.append("EXECUTED") or "evidence",
    )

    assert decision.status == "ALLOW"
    assert decision.side_effect_count == 1
    assert effects == ["EXECUTED"]
    assert decision.result == "evidence"


# ---------------------------------------------------------------- agent identity is enforced, not just carried
import pytest as _pytest
from app.execution_safety_gate import ExecutionSafetyGate as _Gate


def _run(gate, agent_id, action="read_local_evidence", **kw):
    hits = []
    d = gate.execute(agent_id=agent_id, action=action, effect=lambda: hits.append(1) or "done", **kw)
    return d.status, len(hits)


@_pytest.mark.parametrize("agent_id", ["", "   ", None, 7, ["a"], b"a"])
def test_a_missing_or_malformed_agent_id_never_executes(agent_id):
    assert _run(_Gate({"read_local_evidence"}), agent_id) == ("BLOCK", 0)


def test_a_str_subclass_cannot_pose_as_an_agent():
    class Liar(str):
        pass
    gate = _Gate({"read_local_evidence"}, agent_actions={"agent-001": {"read_local_evidence"}})
    assert _run(gate, Liar("agent-001")) == ("BLOCK", 0)


def test_an_anonymous_agent_is_blocked_even_for_a_high_risk_review():
    # no REVIEW route for an unidentified agent: it would ask a human to approve nothing in particular
    assert _run(_Gate({"read_local_evidence"}), "", risk="HIGH") == ("BLOCK", 0)


def test_without_agent_actions_any_named_agent_keeps_the_old_behaviour():
    assert _run(_Gate({"read_local_evidence"}), "agent-001") == ("ALLOW", 1)


def test_agent_actions_narrow_each_agent_to_its_own_list():
    gate = _Gate({"read_local_evidence", "wire_transfer"},
                 agent_actions={"reader": {"read_local_evidence"}, "payer": {"wire_transfer"}})
    assert _run(gate, "reader", "read_local_evidence") == ("ALLOW", 1)
    assert _run(gate, "reader", "wire_transfer") == ("BLOCK", 0)
    assert _run(gate, "payer", "wire_transfer") == ("ALLOW", 1)
    assert _run(gate, "payer", "read_local_evidence") == ("BLOCK", 0)


def test_an_unlisted_agent_runs_nothing_when_agent_actions_is_set():
    gate = _Gate({"read_local_evidence"}, agent_actions={"reader": {"read_local_evidence"}})
    assert _run(gate, "stranger") == ("BLOCK", 0)
    assert _run(gate, "stranger", risk="HIGH") == ("BLOCK", 0)


def test_an_agent_cannot_exceed_the_global_allow_list():
    gate = _Gate({"read_local_evidence"}, agent_actions={"reader": {"read_local_evidence", "wire_transfer"}})
    assert _run(gate, "reader", "wire_transfer") == ("BLOCK", 0)


def test_a_listed_agent_still_needs_human_approval_for_high_risk():
    gate = _Gate({"wire_transfer"}, agent_actions={"payer": {"wire_transfer"}})
    assert _run(gate, "payer", "wire_transfer", risk="HIGH") == ("REVIEW", 0)
    assert _run(gate, "payer", "wire_transfer", risk="HIGH", human_approved=True) == ("ALLOW", 1)


@_pytest.mark.parametrize("bad", [["a"], "agent", 5])
def test_agent_actions_must_be_a_mapping(bad):
    with _pytest.raises(TypeError):
        _Gate({"x"}, agent_actions=bad)


@_pytest.mark.parametrize("bad", [{"": {"x"}}, {1: {"x"}}, {"a": "x"}, {"a": [1]}])
def test_agent_actions_entries_are_validated(bad):
    with _pytest.raises(TypeError):
        _Gate({"x"}, agent_actions=bad)
