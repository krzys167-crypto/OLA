import hashlib
import os
import uuid

import pytest

from fastapi.testclient import TestClient

from app.api_key_crypto import hash_api_key
from app.database import SessionLocal
from app.main import app
from app.models import ApiKey, Tenant


def test_nina_run_route_exists():
    routes = {route.path for route in app.routes}
    assert "/nina-run" in routes


def test_nina_run_executes_chain_but_does_not_self_approve(local_binding_source):
    commit = local_binding_source["sha"]

    tenant_id = str(uuid.uuid4())
    api_key = "nina-test-" + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="nina-e2e"))
        db.add(ApiKey(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            key_hash=hash_api_key(api_key),
        ))
        db.commit()

    client = TestClient(app)
    response = client.post(
        "/nina-run",
        headers={"X-API-Key": api_key},
        json={
            "task": "Calculate 17 * 23 and return the verified result.",
            "requested_tools": ["safe_expression", "local_mcp_tool_registry.sha256"],
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
    assert len(body["replay"]) == 8

    v2 = body["decision_report_v2"]
    assert v2["assurance"]["status"] == "UNKNOWN"
    assert v2["production_eligible"] is False
    assert v2["bindings"]["source_sha"] == commit
    assert len(v2["bindings"]["policy_digest"]) == 64
    assert v2["bindings"]["human_approval_digest"] is None
    from app.decision_report_v2 import inspect_decision_report_v2
    assert inspect_decision_report_v2(v2)["integrity"] == "LOCAL"
