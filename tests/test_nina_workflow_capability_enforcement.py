import pytest

from app.nina_workflow import run_nina_workflow
from app.workflow_engine import WorkflowNode, WorkflowPlanError


def _plan(_goal, _tools):
    return (
        WorkflowNode("first", "safe_expression", "first bounded task", ()),
        WorkflowNode("second", "safe_expression", "second bounded task", ("first",)),
    ), {"provider": "test", "model": "planner-contract", "response_id": "test-plan-1", "attempts": 1}


def test_nina_dag_nodes_consume_vouchers_before_effects(monkeypatch):
    monkeypatch.setenv("OLA_ENVIRONMENT", "test")
    monkeypatch.setenv("OLA_CAPABILITY_VOUCHER_KEY_HEX", "33" * 32)
    effects = []
    records = []

    def execute(node, deps):
        effects.append(node.id)
        return {"node": node.id, "dependency_count": len(deps)}

    def append(tenant_id, record_type, payload):
        records.append({"tenant_id": tenant_id, "record_type": record_type, "payload": payload})
        return {"id": f"evidence-{len(records)}"}

    result = run_nina_workflow(
        tenant_id="tenant-test",
        requester_id="principal-test",
        goal="bounded test workflow",
        allowed_tools=["safe_expression"],
        append=append,
        planner=_plan,
        executor=execute,
    )

    authorizations = [
        item for item in records if item["record_type"] == "execution.capability.authorized"
    ]
    assert result["status"] == "COMPLETED_UNVERIFIED"
    assert result["verified"] is False
    assert effects == ["first", "second"]
    assert len(authorizations) == 2
    assert all(item["payload"]["requester_id"] == "principal-test" for item in authorizations)
    assert all(item["payload"]["voucher_id"] for item in authorizations)
    assert all(item["payload"]["arguments_digest"] for item in authorizations)
    assert all(item["payload"]["policy_version"] == "nina-workflow-capability-v1" for item in authorizations)


def test_nina_dag_fails_closed_before_planning_when_voucher_key_missing(monkeypatch):
    monkeypatch.setenv("OLA_ENVIRONMENT", "test")
    monkeypatch.delenv("OLA_CAPABILITY_VOUCHER_KEY_HEX", raising=False)
    planner_calls = []
    effects = []
    records = []

    def planner(*args):
        planner_calls.append(args)
        return _plan(*args)

    def execute(node, deps):
        effects.append(node.id)
        return "effect"

    def append(tenant_id, record_type, payload):
        records.append((record_type, payload))
        return {"id": f"evidence-{len(records)}"}

    with pytest.raises(WorkflowPlanError, match="voucher key unavailable"):
        run_nina_workflow(
            tenant_id="tenant-test",
            requester_id="principal-test",
            goal="blocked workflow",
            allowed_tools=["safe_expression"],
            append=append,
            planner=planner,
            executor=execute,
        )

    assert planner_calls == []
    assert effects == []
    assert records == []
