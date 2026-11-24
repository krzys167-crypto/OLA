import hashlib
import os
import uuid

import app.agent_runtime as agent_runtime
from app.pipeline_bridge import load_chain

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import ApiKey, Tenant


def test_nina_run_route_exists():
    routes = {route.path for route in app.routes}
    assert "/nina-run" in routes


def test_nina_run_executes_chain_but_does_not_self_approve():
    commit = "TEST_NINA_E2E_COMMIT"
    os.environ["OLA_SOURCE_COMMIT"] = commit
    os.environ["OLA_RUNTIME_COMMIT"] = commit

    tenant_id = str(uuid.uuid4())
    api_key = "nina-test-" + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="nina-e2e"))
        db.add(ApiKey(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            key_hash=hashlib.sha256(api_key.encode()).hexdigest(),
        ))
        db.commit()

    client = TestClient(app)
    response = client.post(
        "/nina-run",
        headers={"X-API-Key": api_key},
        json={
            "task": "Calculate 17 * 23 and return the verified result.",
            "requested_tools": ["safe_expression"],
            "human_approved": True,
            "human_actor": "e2e-human",
            "human_reason": "approved after independent verification",
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["nina"]["status"] == "VERIFIED", body
    assert body["igor"]["status"] == "VERIFIED", body
    assert body["igor"]["checks"]["commit"] is True, body
    assert body["igor"]["checks"]["task"] is True, body
    assert body["igor"]["checks"]["result"] is True, body
    assert body["provenance"]["status"] == "VERIFIED", body
    assert body["provenance"]["commit"] == commit, body
    assert body["provenance"]["invocation_type"] == "local_deterministic_model", body
    assert body["replay_verification"]["status"] == "VERIFIED", body
    # A caller-provided approval flag must not bypass the independent Human Gate.
    assert body["decision_report"]["human_review"]["approved"] is False, body
    assert body["decision_report"]["human_review"]["actor"] == "pending-human-approval", body
    assert body["human_gate"]["status"] == "BLOCK", body
    assert body["status_fields"]["HUMAN_GATE"] == "REVIEW", body
    assert body["status_fields"]["EXECUTION_ALLOWED"] == "REVIEW", body
    assert body["status"] == "REVIEW", body
    assert body["replay_verification"]["status"] == "VERIFIED", body
    replay_for_run = [event for event in body["replay"] if event.get("run_id") == body["run_id"]]
    assert [event["record_type"] for event in replay_for_run[:8]] == [
        "run.start",
        "agent.codeact",
        "agent.react",
        "agent.agentic_rag",
        "agent.mcp_tool_use",
        "agent.self_reflection",
        "agent.multi_agent",
        "run.end",
    ]
    assert body["replay_verification"]["execution_status"] == "SUCCEEDED"
    assert body["replay_verification"]["lifecycle"]["status"] == "VERIFIED"
    assert body["igor"]["checks"]["lifecycle"] is True
    assert body["igor"]["checks"]["execution_status"] == "SUCCEEDED"


def test_nina_run_reports_agent_failure_with_verified_audit_but_blocked_execution(monkeypatch):
    commit = "TEST_NINA_FAILURE_COMMIT"
    os.environ["OLA_SOURCE_COMMIT"] = commit
    os.environ["OLA_RUNTIME_COMMIT"] = commit
    tenant_id = str(uuid.uuid4())
    api_key = "nina-failure-" + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="nina-failure-e2e"))
        db.add(ApiKey(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            key_hash=hashlib.sha256(api_key.encode()).hexdigest(),
        ))
        db.commit()

    original_execute = agent_runtime._execute_agent

    def fail_react(agent, *args, **kwargs):
        if agent == "react":
            raise TimeoutError("provider timeout secret=do-not-store")
        return original_execute(agent, *args, **kwargs)

    monkeypatch.setattr(agent_runtime, "_execute_agent", fail_react)
    response = TestClient(app).post(
        "/nina-run",
        headers={"X-API-Key": api_key},
        json={
            "task": "Calculate 17 * 23 and return the verified result.",
            "requested_tools": ["safe_expression"],
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["nina"]["status"] == "BLOCK", body
    assert body["igor"]["status"] == "BLOCK", body
    assert body["igor"]["checks"]["lifecycle"] is True, body
    assert body["igor"]["checks"]["execution_status"] == "FAILED", body
    assert body["replay_verification"]["status"] == "VERIFIED", body
    assert body["replay_verification"]["execution_status"] == "FAILED", body
    assert body["human_gate"]["status"] == "BLOCK", body
    assert body["status"] == "BLOCK", body
    assert "do-not-store" not in response.text

    rows = load_chain(tenant_id)
    run_events = []
    for record in rows:
        try:
            payload = json.loads(record["payload_json"])
        except json.JSONDecodeError:
            continue
        if payload.get("run_id") == body["run_id"] and (
            record["record_type"] in {"run.start", "run.end"}
            or record["record_type"].startswith("agent.")
        ):
            run_events.append((record["record_type"], payload))
    assert [record_type for record_type, _ in run_events] == [
        "run.start", "agent.codeact", "agent.react", "run.end"
    ]
    failure = run_events[-2][1]
    assert failure["execution_status"] == "FAILED"
    assert failure["status"] == "BLOCK"
    assert failure["error_type"] == "TimeoutError"
