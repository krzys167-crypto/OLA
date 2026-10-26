"""Two independent Ollama proofs for NINA DAG.

The fixed DAG measures repeatable parallel LLM execution. A separate run uses
the live Ollama planner to generate its OWN DAG before parallel execution.
Both are verified against independently read evidence by IGOR.
"""
import json
import os
import uuid

from app.database import SessionLocal
from app.models import Tenant
from app.main import append_record, read_tenant_evidence
from app.workflow_engine import validate_plan
from app.nina_workflow import model_plan, run_nina_workflow
from app.igor_workflow import verify_dag_records


def main():
    assert os.getenv("OLA_LLM_PROVIDER") == "ollama"
    assert os.getenv("OLA_LLM_MODE") == "required"
    commit = os.environ["OLA_RUNTIME_COMMIT"]
    tenant_id = str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="isolated-parallel-dag-ollama"))
        db.commit()
    nodes = validate_plan({"nodes": [
        {"id": "analyst", "tool": "llm_agent",
         "task": "Return exactly one short sentence describing a reliable backup.", "needs": []},
        {"id": "auditor", "tool": "llm_agent",
         "task": "Return exactly one short sentence describing why TLS is important.", "needs": []},
        {"id": "merge", "tool": "local_mcp_tool_registry.sha256",
         "task": "Hash the two independent outputs.", "needs": ["analyst", "auditor"]},
    ]}, allowed_tools={"llm_agent", "local_mcp_tool_registry.sha256"})

    result = run_nina_workflow(
        tenant_id=tenant_id, requester_id="ci-requester", goal="live parallel agents",
        allowed_tools=["llm_agent", "local_mcp_tool_registry.sha256"],
        append=append_record, fetch_records=read_tenant_evidence,
        planner=lambda goal, tools: (nodes, {
            "provider": "static-ci-dag-only", "model": "fixed-fixture",
            "response_id": "ci-plan-defined-in-source-" + commit[:12],
        }),
        require_overlap=True, expected_provider="ollama",
    )
    evidence = read_tenant_evidence(tenant_id)
    igor = verify_dag_records(evidence, tenant_id=tenant_id, run_id=result["run_id"],
                              expected_commit=commit, require_overlap=True,
                              expected_provider="ollama")
    assert result["status"] == "COMPLETED_UNVERIFIED", result
    assert igor["status"] == "VERIFIED", igor
    assert igor["overlap_ns"] > 0, igor
    assert result["igor"]["status"] == "VERIFIED"
    assert result["verified"] is False and result["human_gate"] == "NOT_APPROVED"
    for worker in ("analyst", "auditor"):
        output = result["results"][worker]
        assert output["provider"] == "ollama"
        assert output["model"] == os.environ["OLA_LLM_MODEL"]
        assert output["response_id"]
    assert result["results"]["analyst"]["response_id"] != result["results"]["auditor"]["response_id"]
    mutated = [dict(row) for row in evidence]
    mutated[1]["payload_json"] = "{}"
    assert verify_dag_records(mutated, tenant_id=tenant_id, run_id=result["run_id"])["status"] == "BLOCK"

    # Proof 2: the planner generates the DAG from a goal using a real model.
    # No hard-coded nodes, mocked planner, or deterministic fallback are used.
    autonomous_tenant_id = str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(Tenant(id=autonomous_tenant_id, name="isolated-autonomous-dag-ollama"))
        db.commit()
    autonomous_result = run_nina_workflow(
        tenant_id=autonomous_tenant_id, requester_id="ci-requester",
        goal=("Assess two independent operational risks for an online service: "
              "TLS-encrypted network transport and backup recovery. "
              "Both assessments can run in parallel using independent LLM agents. "
              "Provide a brief practical recommendation for each."),
        allowed_tools=["llm_agent"],
        append=append_record, fetch_records=read_tenant_evidence,
        planner=lambda goal, tools: model_plan(goal, tools, independent_only=True),
        require_overlap=True, expected_provider="ollama",
    )
    autonomous_evidence = read_tenant_evidence(autonomous_tenant_id)
    autonomous_igor = verify_dag_records(
        autonomous_evidence, tenant_id=autonomous_tenant_id,
        run_id=autonomous_result["run_id"], expected_commit=commit,
        require_overlap=True, expected_provider="ollama",
    )
    plan_events = [json.loads(row["payload_json"]) for row in autonomous_evidence
                   if row["record_type"] == "workflow.planned"
                   and json.loads(row["payload_json"]).get("run_id") == autonomous_result["run_id"]]
    assert len(plan_events) == 1, "no unique model-generated plan in evidence"
    generated_nodes = plan_events[0]["nodes"]
    independent_llm_nodes = [node for node in generated_nodes
                             if node["tool"] == "llm_agent" and not node["needs"]]
    assert len(independent_llm_nodes) >= 2, (
        "model did not independently generate at least two concurrently runnable LLM nodes",
        generated_nodes,
    )
    assert autonomous_result["planner"]["provider"] == "ollama"
    assert autonomous_result["planner"]["model"] == os.environ["OLA_LLM_MODEL"]
    assert autonomous_result["planner"]["response_id"]
    assert autonomous_result["status"] == "COMPLETED_UNVERIFIED", autonomous_result
    assert autonomous_igor["status"] == "VERIFIED", autonomous_igor
    assert autonomous_igor["overlap_ns"] > 0, autonomous_igor
    assert autonomous_result["verified"] is False
    assert autonomous_result["human_gate"] == "NOT_APPROVED"
    autonomous_proof = {
        "kind": "LIVE_MODEL_PLANNED_PARALLEL_DAG",
        "plan_source": "REAL_OLLAMA_JSON_NOT_STATIC",
        "source_sha": commit, "run_id": autonomous_result["run_id"],
        "tenant_id": autonomous_tenant_id,
        "planner": autonomous_result["planner"],
        "model_generated_nodes": generated_nodes,
        "independent_llm_workers": len(independent_llm_nodes),
        "igor": autonomous_igor, "overlap_ns": autonomous_igor["overlap_ns"],
        "evidence_count": len(autonomous_evidence),
        "human_gate": autonomous_result["human_gate"],
    }
    with open("nina-autonomous-ollama-evidence.json", "w", encoding="utf-8") as out:
        json.dump(autonomous_evidence, out, indent=2, sort_keys=True)
    with open("nina-autonomous-ollama-proof.json", "w", encoding="utf-8") as out:
        json.dump(autonomous_proof, out, indent=2, sort_keys=True)

    proof = {
        "status": "VERIFIED", "kind": "REAL_OLLAMA_PARALLEL_DAG",
        "commit": commit, "run_id": result["run_id"], "tenant_id": tenant_id,
        "model": os.environ["OLA_LLM_MODEL"],
        "planner": "STATIC_CI_DAG_NOT_LIVE_AUTONOMOUS_PLANNER",
        "llm_workers": 2, "overlap_ns": igor["overlap_ns"],
        "igor": igor, "human_gate": result["human_gate"],
        "tamper_rejected": True, "evidence_count": len(evidence),
        "response_ids": {key: result["results"][key]["response_id"]
                         for key in ("analyst", "auditor")},
    }
    with open("nina-parallel-ollama-proof.json", "w", encoding="utf-8") as out:
        json.dump(proof, out, indent=2, sort_keys=True)
    with open("nina-parallel-ollama-evidence.json", "w", encoding="utf-8") as out:
        json.dump(evidence, out, indent=2, sort_keys=True)
    print(json.dumps(proof, sort_keys=True))


if __name__ == "__main__":
    main()
