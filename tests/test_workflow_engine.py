import threading
import time

import pytest

from app.workflow_engine import WorkflowEngine, WorkflowPlanError, validate_plan


def test_parallel_independent_nodes_and_dependency_barrier():
    plan = validate_plan({"nodes": [
        {"id": "a", "tool": "safe_expression", "task": "1+2", "needs": []},
        {"id": "b", "tool": "safe_expression", "task": "4*5", "needs": []},
        {"id": "join", "tool": "sha256", "task": "all done", "needs": ["a", "b"]},
    ]}, allowed_tools={"safe_expression", "sha256"})
    barrier = threading.Barrier(2, timeout=2)
    observed = []
    lock = threading.Lock()

    def execute(node, dependencies):
        if node.id in ("a", "b"):
            barrier.wait()
            time.sleep(0.02)
        with lock:
            observed.append((node.id, set(dependencies)))
        return "ok:" + node.id

    events = []
    result = WorkflowEngine(max_workers=2).run(plan, execute, events.append)
    assert result["status"] == "COMPLETED_UNVERIFIED"
    assert result["results"] == {"a": "ok:a", "b": "ok:b", "join": "ok:join"}
    assert observed[-1] == ("join", {"a", "b"})
    assert len([x for x in events if x["event"] == "task.completed"]) == 3
    assert events[-1]["event"] == "workflow.completed"


def test_invalid_dag_is_blocked_before_any_execution():
    invalid = [
        {"nodes": [{"id": "a", "task": "x", "tool": "shell", "needs": []}]},
        {"nodes": [{"id": "a", "task": "x", "tool": "sha256", "needs": ["b"]}]},
        {"nodes": [{"id": "a", "task": "x", "tool": "sha256", "needs": ["b"]},
                   {"id": "b", "task": "x", "tool": "sha256", "needs": ["a"]}]},
        {"nodes": [{"id": "a", "task": "x", "tool": "sha256", "needs": []},
                   {"id": "a", "task": "y", "tool": "sha256", "needs": []}]},
    ]
    for plan in invalid:
        with pytest.raises(WorkflowPlanError):
            validate_plan(plan, allowed_tools={"sha256"})


def test_failure_blocks_dependants_and_never_claims_verified():
    plan = validate_plan({"nodes": [
        {"id": "a", "tool": "sha256", "task": "x", "needs": []},
        {"id": "b", "tool": "sha256", "task": "y", "needs": ["a"]},
    ]}, allowed_tools={"sha256"})
    executed = []

    def execute(node, dependencies):
        executed.append(node.id)
        raise RuntimeError("boom")

    events = []
    result = WorkflowEngine(max_workers=2).run(plan, execute, events.append)
    assert result["status"] == "BLOCK"
    assert executed == ["a"]
    assert "b" not in result["results"]
    assert any(x["event"] == "task.failed" for x in events)


def test_rejects_extra_fields_and_oversized_plans():
    with pytest.raises(WorkflowPlanError):
        validate_plan({"nodes": [
            {"id": "a", "tool": "sha256", "task": "x", "needs": [], "unsafe": True}
        ]}, allowed_tools={"sha256"})
    with pytest.raises(WorkflowPlanError):
        validate_plan({"nodes": [
            {"id": f"a{i}", "tool": "sha256", "task": "x", "needs": []}
            for i in range(17)
        ]}, allowed_tools={"sha256"})
