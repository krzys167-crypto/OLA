"""Real two-worker Ollama proof for the *new* NINA DAG, not /agent-run.

The DAG structure is fixed for reproducible concurrency measurement; individual
agents invoke the configured live Ollama model. Autonomous planner JSON generation
is tested separately and is NOT claimed to be live-proven by this script.
"""
import json
import os
import uuid

from app.database import SessionLocal
from app.models import Tenant
from app.main import append_record, read_tenant_evidence
from app.workflow_engine import validate_plan
from app.nina_workflow import run_nina_workflow
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
