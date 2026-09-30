import hashlib
import os
import uuid

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import ApiKey, Tenant


def test_nina_run_route_exists():
    routes = {route.path for route in app.routes}
    assert "/nina-run" in routes


def test_nina_run_executes_chain_but_does_not_self_approve():
    commit = "TEST_NINA_E2E_COMMIT"
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
    assert len(body["replay"]) == 7
