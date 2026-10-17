import pytest
from app.workflow_engine import WorkflowPlanError, validate_plan
from app.nina_workflow import run_nina_workflow


def test_end_to_end_workflow_service_records_every_step():
    nodes = validate_plan({"nodes": [
        {"id": "first", "tool": "safe_expression", "task": "2+3", "needs": []},
        {"id": "next", "tool": "local_mcp_tool_registry.sha256", "task": "hash", "needs": ["first"]},
    ]}, allowed_tools={"safe_expression", "local_mcp_tool_registry.sha256"})
    writes = []

    def append(tenant, kind, payload):
        writes.append((tenant, kind, payload))
        return {"id": str(len(writes))}

    def execute(node, dependencies):
        return str(len(dependencies))

    result = run_nina_workflow(tenant_id="tenantA", requester_id="u1", goal="test",
        allowed_tools=["safe_expression", "local_mcp_tool_registry.sha256"], append=append,
        planner=lambda goal, tools: (nodes, {"provider": "ollama", "model": "test", "response_id": "abc"}),
        executor=execute)
    assert result["status"] == "COMPLETED_UNVERIFIED"
    assert result["verified"] is False
    assert len(result["evidence_ids"]) == 6
    assert writes[0][1] == "workflow.planned"
    assert writes[-1][1] == "workflow.completed"
    assert all(item[0] == "tenantA" for item in writes)


def test_evidence_sink_error_never_reports_success():
    nodes = validate_plan({"nodes": [
        {"id": "a", "tool": "safe_expression", "task": "1+1", "needs": []}
    ]}, allowed_tools={"safe_expression"})
    with pytest.raises(RuntimeError, match="evidence write"):
        run_nina_workflow(tenant_id="t", requester_id="u", goal="g",
            allowed_tools=["safe_expression"],
            append=lambda *args: {"status": "fake"},
            planner=lambda g, tools: (nodes, {"provider": "ollama", "model": "test", "response_id": "abc"}),
            executor=lambda node, deps: "2")


def test_reject_unregistered_tool_before_planning():
    with pytest.raises(WorkflowPlanError):
        run_nina_workflow(tenant_id="t", requester_id="u", goal="g",
            allowed_tools=["shell"], append=lambda *args: None,
            planner=lambda *args: (_ for _ in ()).throw(AssertionError("called")))
