from app.api_key_hashing import api_key_fingerprint
import json
import hashlib
import os
import uuid

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import ApiKey, Tenant, EvidenceRecord
from sqlalchemy import select


def test_nina_run_route_exists():
    routes = {route.path for route in app.routes}
    assert "/nina-run" in routes


def test_nina_run_executes_chain_but_does_not_self_approve():
    commit = "a" * 40
    os.environ["OLA_RUNTIME_COMMIT"] = commit

    tenant_id = str(uuid.uuid4())
    api_key = "nina-test-" + uuid.uuid4().hex
    requester_id = str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="nina-e2e"))
        db.add(ApiKey(
            id=requester_id,
            tenant_id=tenant_id,
            key_hash=api_key_fingerprint(api_key),
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
    replay_types = [record.get("record_type") for record in body["replay"]]
    assert len(body["replay"]) == 15  # start + six voucher authorizations + six agents + end
    assert replay_types.count("execution.run.start") == 1
    assert replay_types.count("execution.capability.authorized") == 6
    assert replay_types.count("execution.run.end") == 1
    assert sum(isinstance(item, str) and item.startswith("agent.") for item in replay_types) == 6
    with SessionLocal() as db:
        rows = db.scalars(
            select(EvidenceRecord)
            .where(EvidenceRecord.tenant_id == tenant_id)
            .order_by(EvidenceRecord.seq.asc())
        ).all()
    authorizations = [
        json.loads(row.payload_json)
        for row in rows
        if row.record_type == "execution.capability.authorized"
    ]
    assert len(authorizations) == 6
    assert all(item["principal_id"] == requester_id for item in authorizations)


def test_nina_run_explicit_llm_does_not_promote_deterministic_fallback(monkeypatch):
    # No real provider credential: the existing agent runtime uses a local
    # deterministic fallback, which must not be labeled as LLM execution.
    monkeypatch.setenv("OLA_LLM_PROVIDER", "openai")
    monkeypatch.setenv("OLA_LLM_MODE", "deterministic")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("OLA_RUNTIME_COMMIT", "b" * 40)

    tenant_id = str(uuid.uuid4())
    api_key = "nina-no-fallback-" + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="nina-llm-fallback"))
        db.add(ApiKey(id=str(uuid.uuid4()), tenant_id=tenant_id,
                      key_hash=api_key_fingerprint(api_key)))
        db.commit()
    response = TestClient(app).post("/nina-run",
        headers={"X-API-Key": api_key}, json={
            "task": "Calculate 17 * 23 and verify it",
            "requested_tools": ["llm_agent"],
        })
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["nina"]["status"] == "BLOCK", payload
    assert payload["provenance"]["status"] == "BLOCK", payload
    assert payload["status_fields"]["EXECUTION_ALLOWED"] == "BLOCK", payload
    assert payload["status"] == "BLOCK", payload
    assert payload["human_gate"]["status"] == "BLOCK", payload
