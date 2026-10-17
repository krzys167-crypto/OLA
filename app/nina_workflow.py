"""Feature-gated autonomous workflow planning for the existing NINA runtime.

No implicit deterministic fallback: planning requires a real configured LLM.
All executable capabilities are already allowlisted by NINA.
"""
import json
import os

from .workflow_engine import WorkflowEngine, WorkflowPlanError, validate_plan


def model_plan(goal, tools):
    from .agent_runtime import _invoke_llm

    if not isinstance(goal, str) or not goal.strip() or len(goal) > 2000:
        raise WorkflowPlanError("invalid goal")
    contract = (
        'Respond with ONLY JSON: {"nodes":[{"id":"short_unique_id",'
        '"tool":"one_allowed_tool","task":"bounded instruction",'
        '"needs":["predecessor_id"]}]}. Generate 1 to 16 useful nodes. '
        'Use dependencies only when needed and parallel independent work. '
        'No code fences, no prose. Never request tools outside allowed_tools.'
    )
    try:
        response = _invoke_llm("nina_dag_planner", goal, {"contract": contract, "allowed_tools": list(tools)})
    except Exception as exc:
        raise WorkflowPlanError(f"planner failed: {type(exc).__name__}") from exc
    if (not response or response.get("invocation_type") != "real_llm"
            or not response.get("response_id") or not response.get("output")):
        raise WorkflowPlanError("real LLM planning and response provenance required")
    try:
        data = json.loads(response["output"])
    except (ValueError, TypeError) as exc:
        raise WorkflowPlanError("planner output is not strict JSON") from exc
    return validate_plan(data, allowed_tools=set(tools)), {
        "provider": response["provider"], "model": response["model"],
        "response_id": response["response_id"], "prompt_digest": response.get("prompt_digest"),
    }


def execute_registered_node(node, deps):
    if node.tool == "safe_expression":
        from .agent_runtime import _safe_expression
        return _safe_expression(node.task)
    if node.tool == "local_mcp_tool_registry.sha256":
        from .agent_runtime import _mcp_tool_call
        value = json.dumps(deps, sort_keys=True) if deps else node.task
        return _mcp_tool_call("sha256", {"value": value})
    if node.tool == "llm_agent":
        from .agent_runtime import _invoke_llm
        response = _invoke_llm(node.id, node.task, {"upstream_results": deps})
        if (not response or response.get("invocation_type") != "real_llm"
                or not response.get("response_id") or not response.get("output")):
            raise WorkflowPlanError("real subagent execution and response provenance required")
        return {"output": response["output"], "provider": response["provider"],
                "model": response["model"], "response_id": response["response_id"]}
    raise WorkflowPlanError("tool not permitted by workflow executor")


def run_nina_workflow(*, tenant_id, requester_id, goal, allowed_tools, append,
                      planner=model_plan, executor=execute_registered_node):
    # The route checks NINA policy before calling this service. Defence in depth.
    supported = {"safe_expression", "local_mcp_tool_registry.sha256", "llm_agent"}
    if not set(allowed_tools) <= supported:
        raise WorkflowPlanError("unregistered workflow tool")
    nodes, provenance = planner(goal, tuple(allowed_tools))
    nodes = validate_plan({"nodes": [
        {"id": n.id, "tool": n.tool, "task": n.task, "needs": list(n.needs)}
        for n in nodes]}, allowed_tools=set(allowed_tools))
    evidence_ids = []

    def record(event):
        payload = {**event, "requester_id": requester_id, "planner": provenance,
                   "commit": os.getenv("OLA_RUNTIME_COMMIT", "UNKNOWN")}
        saved = append(tenant_id, event["event"], payload)
        if not isinstance(saved, dict) or not saved.get("id"):
            raise RuntimeError("evidence write was not confirmed")
        evidence_ids.append(saved["id"])

    result = WorkflowEngine(max_workers=4).run(nodes, executor, record)
    return {**result, "tenant_id": tenant_id, "planner": provenance,
            "evidence_ids": evidence_ids, "human_gate": "NOT_APPROVED",
            "verified": False}
