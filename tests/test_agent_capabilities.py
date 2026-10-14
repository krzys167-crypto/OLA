import uuid

from app.agent_runtime import run_agent_task
from app.database import SessionLocal
from app.models import Tenant


def _tenant():
    tenant_id = str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="capability-test"))
        db.commit()
    return tenant_id


def test_six_agents_perform_distinct_runtime_capabilities():
    result = run_agent_task(_tenant(), "calculate 2+3 and preserve the result", allowed_tools=("safe_expression", "local_mcp_tool_registry.sha256"))
    assert result["status"] == "VERIFIED"
    capabilities = {item["agent"]: item["capability"] for item in result["execution"]}

    assert capabilities["codeact"] == "executed_safe_expression"
    assert capabilities["react"] == "reason_act_observe"
    assert capabilities["agentic_rag"] == "retrieved_prior_evidence"
    assert capabilities["mcp_tool_use"] == "invoked_tool"
    assert capabilities["self_reflection"] == "checked_previous_output"
    assert capabilities["multi_agent"] == "aggregated_agent_outputs"


def test_agent_results_are_not_deterministic_placeholder_strings():
    result = run_agent_task(_tenant(), "calculate 2+3", allowed_tools=("safe_expression", "local_mcp_tool_registry.sha256"))
    assert all("deterministic runtime contract" not in item["result"] for item in result["execution"])
    assert result["execution"][0]["tool_output"] == "5"
