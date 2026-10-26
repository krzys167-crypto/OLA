import hashlib
import json
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

import app.main as main_module
from app.database import SessionLocal
from app.hashchain import verify_chain
from app.execution_safety_gate import ExecutionDecision
from app.models import ApiKey, EvidenceRecord, Tenant


def _tenant():
    tenant_id = str(uuid.uuid4())
    key = f"gate-key-{tenant_id}"
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="agent-run-gate-test"))
        db.flush()
        db.add(ApiKey(id=str(uuid.uuid4()), tenant_id=tenant_id,
                      key_hash=hashlib.sha256(key.encode()).hexdigest()))
        db.commit()
    return tenant_id, {"X-API-Key": key}


def _evidence(tenant_id):
    with SessionLocal() as db:
        rows = db.scalars(select(EvidenceRecord).where(
            EvidenceRecord.tenant_id == tenant_id
        ).order_by(EvidenceRecord.seq.asc())).all()
        return [(row.record_type, json.loads(row.payload_json), {
            "tenant_id": row.tenant_id, "seq": row.seq,
            "prev_hash": row.prev_hash, "record_hash": row.record_hash,
            "payload_json": row.payload_json,
        }) for row in rows]


def test_registered_low_risk_agent_is_allowed_and_decision_is_chained(monkeypatch):
    monkeypatch.setenv("OLA_LLM_PROVIDER", "none")
    monkeypatch.setenv("OLA_LLM_MODE", "deterministic")
    tenant_id, headers = _tenant()

    response = TestClient(main_module.app).post(
        "/agent-run", headers=headers,
        json={"agent_id": "agent-001", "risk": "LOW", "task": "Calculate 17 * 23"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "VERIFIED"
    assert all(item["invocation_type"] == "local_deterministic_model"
               for item in response.json()["execution"])
    rows = _evidence(tenant_id)
    assert len(rows) == 7  # gate decision followed by six existing agent records
    assert rows[0][0] == "execution.safety_gate"
    assert rows[0][1]["decision"] == "ALLOW"
    assert rows[0][1]["agent_id"] == "agent-001"
    assert rows[0][1]["risk"] == "LOW"
    assert rows[0][1]["reason"] == "allowlisted_action"
    assert rows[0][1]["task_sha256"] == hashlib.sha256(
        json.dumps("Calculate 17 * 23", separators=(",", ":")).encode()
    ).hexdigest()
    assert verify_chain([row[2] for row in rows]) == (True, "ok")


def test_unknown_agent_is_denied_without_execution(monkeypatch):
    tenant_id, headers = _tenant()
    monkeypatch.setattr(main_module, "run_agent_task", lambda *_: 1 / 0)

    response = TestClient(main_module.app).post(
        "/agent-run", headers=headers,
        json={"agent_id": "unregistered", "task": "do not execute"},
    )

    assert response.status_code == 403
    assert [row[0] for row in _evidence(tenant_id)] == ["execution.safety_gate"]
    assert _evidence(tenant_id)[0][1]["reason"] == "unregistered_agent"


@pytest.mark.parametrize("claimed_approval", [None, True])
def test_high_risk_requires_verified_human_approval(monkeypatch, claimed_approval):
    tenant_id, headers = _tenant()
    monkeypatch.setattr(main_module, "run_agent_task", lambda *_: 1 / 0)

    body = {"agent_id": "agent-001", "risk": "HIGH", "task": "do not execute"}
    if claimed_approval is not None:
        body["human_approved"] = claimed_approval
    response = TestClient(main_module.app).post(
        "/agent-run", headers=headers,
        json=body,
    )

    assert response.status_code == 403
    assert _evidence(tenant_id)[0][1]["decision"] == "DENY"
    assert _evidence(tenant_id)[0][1]["risk"] == "HIGH"
    assert _evidence(tenant_id)[0][1]["reason"] == "human_owner_approval_required"
    assert len(_evidence(tenant_id)) == 1


def test_gate_exception_is_denied_without_execution(monkeypatch):
    tenant_id, headers = _tenant()
    monkeypatch.setattr(main_module, "run_agent_task", lambda *_: 1 / 0)

    def broken_gate(**_kwargs):
        raise RuntimeError("gate failed")

    monkeypatch.setattr(main_module.AGENT_RUN_GATE, "execute", broken_gate)
    response = TestClient(main_module.app).post(
        "/agent-run", headers=headers,
        json={"agent_id": "agent-001", "task": "do not execute"},
    )

    assert response.status_code == 403
    assert _evidence(tenant_id)[0][1]["reason"] == "gate_exception"
    assert len(_evidence(tenant_id)) == 1


def test_high_risk_stays_denied_even_if_gate_returns_allow(monkeypatch):
    tenant_id, headers = _tenant()
    monkeypatch.setattr(main_module, "run_agent_task", lambda *_: 1 / 0)
    monkeypatch.setattr(main_module.AGENT_RUN_GATE, "execute",
                        lambda **_: ExecutionDecision(status="ALLOW"))

    response = TestClient(main_module.app).post(
        "/agent-run", headers=headers,
        json={"agent_id": "agent-001", "risk": "HIGH",
              "human_approved": True, "task": "do not execute"},
    )

    assert response.status_code == 403
    assert _evidence(tenant_id)[0][1]["decision"] == "DENY"


def test_missing_gate_decision_is_denied_without_execution(monkeypatch):
    tenant_id, headers = _tenant()
    monkeypatch.setattr(main_module, "run_agent_task", lambda *_: 1 / 0)
    monkeypatch.setattr(main_module.AGENT_RUN_GATE, "execute", lambda **_: None)

    response = TestClient(main_module.app).post(
        "/agent-run", headers=headers,
        json={"agent_id": "agent-001", "task": "do not execute"},
    )

    assert response.status_code == 403
    assert _evidence(tenant_id)[0][1]["reason"] == "gate_denied_or_missing_decision"


def test_evidence_write_failure_blocks_runtime(monkeypatch):
    _, headers = _tenant()
    monkeypatch.setattr(main_module, "run_agent_task", lambda *_: 1 / 0)

    def broken_evidence(*_args):
        raise RuntimeError("evidence write failed")

    monkeypatch.setattr(main_module, "append_record", broken_evidence)
    response = TestClient(main_module.app).post(
        "/agent-run", headers=headers,
        json={"agent_id": "agent-001", "task": "do not execute"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "gate evidence unavailable"
