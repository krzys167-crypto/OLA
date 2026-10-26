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


def test_llm_agent_never_accepts_a_deterministic_stub(monkeypatch):
    import sys
    from types import ModuleType
    from app.nina_workflow import execute_registered_node
    from app.workflow_engine import WorkflowNode
    mod = ModuleType("app.agent_runtime")
    mod._invoke_llm = lambda *args: None
    monkeypatch.setitem(sys.modules, "app.agent_runtime", mod)
    with pytest.raises(WorkflowPlanError, match="real subagent"):
        execute_registered_node(WorkflowNode("worker1", "llm_agent", "analysis", ()), {})


def test_llm_agent_attaches_model_provenance(monkeypatch):
    import sys
    from types import ModuleType
    from app.nina_workflow import execute_registered_node
    from app.workflow_engine import WorkflowNode
    mod = ModuleType("app.agent_runtime")
    mod._invoke_llm = lambda *args: {"invocation_type": "real_llm", "response_id": "id42", "output": "answer", "provider": "ollama", "model": "qwen"}
    monkeypatch.setitem(sys.modules, "app.agent_runtime", mod)
    result = execute_registered_node(WorkflowNode("worker2", "llm_agent", "analysis", ()), {})
    assert result == {"output": "answer", "provider": "ollama", "model": "qwen", "response_id": "id42"}


def test_planner_requires_real_model_and_json(monkeypatch):
    import sys
    from types import ModuleType
    from app.nina_workflow import model_plan
    mod = ModuleType("app.agent_runtime")
    mod._invoke_llm = lambda *args: None
    monkeypatch.setitem(sys.modules, "app.agent_runtime", mod)
    with pytest.raises(WorkflowPlanError, match="real LLM"):
        model_plan("plan", ["llm_agent"])
    mod._invoke_llm = lambda *args: {"invocation_type": "real_llm", "response_id": "id", "output": "not-json"}
    with pytest.raises(WorkflowPlanError, match="strict JSON"):
        model_plan("plan", ["llm_agent"])


def test_planner_makes_real_model_plan_with_provenance(monkeypatch):
    import sys
    from types import ModuleType
    from app.nina_workflow import model_plan
    mod = ModuleType("app.agent_runtime")
    mod._invoke_llm = lambda *args: {"invocation_type": "real_llm", "response_id": "id",
        "output": '{"nodes":[{"id":"worker","tool":"llm_agent","task":"analyse","needs":[]}]}',
        "provider": "ollama", "model": "qwen"}
    monkeypatch.setitem(sys.modules, "app.agent_runtime", mod)
    nodes, provenance = model_plan("plan", ["llm_agent"])
    assert nodes[0].id == "worker"
    assert provenance["response_id"] == "id"



def test_live_ollama_planner_uses_json_format_and_sufficient_token_budget(monkeypatch):
    """Real planner JSON is not subject to the 64-token worker response budget."""
    import httpx
    from app.agent_runtime import _invoke_llm

    monkeypatch.setenv("OLA_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("OLA_LLM_MODE", "required")
    monkeypatch.setenv("OLA_LLM_MODEL", "qwen2.5:0.5b-instruct")
    monkeypatch.setenv("OLA_OLLAMA_NUM_PREDICT", "64")
    calls = []

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"message": {"content": '{"nodes":[]}'}, "done": True}

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse()

    monkeypatch.setattr(httpx, "post", fake_post)
    response = _invoke_llm("nina_dag_planner", "Review resilience",
                           {"contract": "strict DAG JSON", "allowed_tools": ["llm_agent"]})
    assert response["invocation_type"] == "real_llm"
    assert len(calls) == 1
    schema = calls[0][1]["json"]["format"]
    assert schema["type"] == "object"
    assert schema["required"] == ["nodes"]
    assert schema["additionalProperties"] is False
    node_schema = schema["properties"]["nodes"]["items"]
    assert node_schema["required"] == ["id", "tool", "task", "needs"]
    assert node_schema["additionalProperties"] is False
    assert node_schema["properties"]["tool"]["enum"] == ["llm_agent"]
    assert calls[0][1]["json"]["options"]["num_predict"] >= 192
    _invoke_llm("nina_dag_planner", "Two independent topics",
                {"contract": "independent only", "allowed_tools": ["llm_agent"],
                 "independent_only": True})
    independent = calls[1][1]["json"]["format"]["properties"]["nodes"]
    assert independent["minItems"] == 2
    assert independent["maxItems"] == 4
    assert independent["items"]["properties"]["needs"]["maxItems"] == 0




def test_planner_replans_rejected_dependency_but_never_executes_it(monkeypatch):
    """A malformed model DAG is rejected; only a second valid model plan runs."""
    import sys
    from types import ModuleType
    from app.nina_workflow import model_plan
    mod = ModuleType("app.agent_runtime")
    requests = []

    def fake_llm(agent, task, context):
        requests.append(context)
        invalid = '{"nodes":[{"id":"analyst","tool":"llm_agent","task":"check TLS","needs":["missing"]}]}'
        valid = ('{"nodes":[{"id":"analyst","tool":"llm_agent",'
                 '"task":"check TLS","needs":[]},{"id":"auditor","tool":"llm_agent",'
                 '"task":"check backups","needs":[]}]}')
        return {"invocation_type": "real_llm", "response_id": f"planner-{len(requests)}",
                "output": invalid if len(requests) == 1 else valid,
                "provider": "ollama", "model": "qwen"}

    mod._invoke_llm = fake_llm
    monkeypatch.setitem(sys.modules, "app.agent_runtime", mod)
    nodes, provenance = model_plan("Check two independent risks", ["llm_agent"])
    assert len(nodes) == 2
    assert len(requests) == 2
    assert "revision" not in requests[0]
    assert '"needs":[]' in requests[0]["contract"]
    assert "predecessor_id" not in requests[0]["contract"]
    assert "unknown dependency" in requests[1]["revision"]
    assert provenance["response_id"] == "planner-2"
    assert provenance["attempts"] == 2


def test_planner_exhaustion_blocks_without_static_fallback(monkeypatch):
    import sys
    from types import ModuleType
    from app.nina_workflow import model_plan
    mod = ModuleType("app.agent_runtime")
    calls = []

    def bad_llm(agent, task, context):
        calls.append(context)
        return {"invocation_type": "real_llm", "response_id": f"bad-{len(calls)}",
                "provider": "ollama", "model": "qwen",
                "output": '{"nodes":[{"id":"analyst","tool":"llm_agent","task":"x","needs":["unknown"]}]}'}

    mod._invoke_llm = bad_llm
    monkeypatch.setitem(sys.modules, "app.agent_runtime", mod)
    with pytest.raises(WorkflowPlanError, match="after 3 attempts"):
        model_plan("Check", ["llm_agent"])
    assert len(calls) == 3



def test_independent_goal_requires_model_chosen_parallel_nodes(monkeypatch):
    import sys
    from types import ModuleType
    from app.nina_workflow import model_plan
    mod = ModuleType("app.agent_runtime")
    requests = []

    def fake_planner(agent, goal, context):
        requests.append(context)
        invalid = ('{"nodes":[{"id":"first","tool":"llm_agent",'
                   '"task":"TLS risk","needs":["missing"]}]}')
        valid = ('{"nodes":[{"id":"tls","tool":"llm_agent","task":"TLS",'
                 '"needs":[]},{"id":"backups","tool":"llm_agent",'
                 '"task":"backup recovery","needs":[]}]}')
        return {"invocation_type": "real_llm", "response_id": f"plan-{len(requests)}",
                "provider": "ollama", "model": "qwen", "output":
                invalid if len(requests) == 1 else valid}

    mod._invoke_llm = fake_planner
    monkeypatch.setitem(sys.modules, "app.agent_runtime", mod)
    nodes, provenance = model_plan("Two independent issues", ["llm_agent"],
                                   independent_only=True)
    assert [node.id for node in nodes] == ["tls", "backups"]
    assert all(not node.needs for node in nodes)
    assert len(requests) == 2 and all(req["independent_only"] is True for req in requests)
    assert provenance["attempts"] == 2
    assert provenance["response_id"] == "plan-2"
