import hashlib
import json
import uuid

from app.agent_runtime import AGENT_ROLES, run_agent_task, verify_agent_run
from app.database import SessionLocal
from app.models import ApiKey, Tenant
from app.pipeline_bridge import load_chain
from app.replay import verify_replay


def _seed_tenant():
    tenant_id = str(uuid.uuid4())
    key = "run-lifecycle-" + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="run-lifecycle-test"))
        db.add(ApiKey(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            key_hash=hashlib.sha256(key.encode()).hexdigest(),
        ))
        db.commit()
    return tenant_id


def _run_events(tenant_id, run_id):
    rows = load_chain(tenant_id)
    events = []
    for row in rows:
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, json.JSONDecodeError):
            continue
        if payload.get("run_id") == run_id:
            events.append((row["record_type"], payload))
    return rows, events


def test_successful_run_has_one_start_and_end_and_replay_verifies(monkeypatch):
    monkeypatch.setenv("OLA_SOURCE_COMMIT", "test-source-commit")
    monkeypatch.setenv("OLA_LLM_MODE", "deterministic")
    tenant_id = _seed_tenant()

    result = run_agent_task(tenant_id, "Calculate 17 * 23")

    rows, events = _run_events(tenant_id, result["run_id"])
    event_types = [record_type for record_type, _ in events]
    assert event_types == ["run.start", *[f"agent.{role}" for role in AGENT_ROLES], "run.end"]

    start = events[0][1]
    end = events[-1][1]
    assert start["schema_version"] == "ola.run-lifecycle/v1"
    assert end["schema_version"] == "ola.run-lifecycle/v1"
    assert start["status"] == "STARTED"
    assert end["status"] == "COMPLETED"
    assert end["completed_agent_count"] == len(AGENT_ROLES)
    assert start["run_id"] == end["run_id"] == result["run_id"]
    assert start["source_commit"] == end["source_commit"] == "test-source-commit"
    assert start["replay_nonce"] == end["replay_nonce"] == result["replay_nonce"]
    assert start["task_digest"] == end["task_digest"]

    audit = verify_agent_run(tenant_id, result["run_id"])
    assert audit["status"] == "VERIFIED"
    assert audit["audit_status"] == "VERIFIED"
    assert audit["run_status"] == "COMPLETED"

    replay = verify_replay(
        rows,
        expected_run_id=result["run_id"],
        expected_tenant_id=tenant_id,
        expected_record_count=len(rows),
        expected_tip_hash=rows[-1]["record_hash"],
        require_lifecycle=True,
    )
    assert replay["status"] == "VERIFIED"
    assert replay["run_status"] == "COMPLETED"
    assert replay["run_event_count"] == len(AGENT_ROLES) + 2


def test_agent_exception_is_sealed_and_never_leaks_raw_exception(monkeypatch):
    import app.agent_runtime as runtime

    monkeypatch.setenv("OLA_SOURCE_COMMIT", "test-source-commit")
    monkeypatch.setenv("OLA_LLM_MODE", "deterministic")
    tenant_id = _seed_tenant()
    original_execute = runtime._execute_agent

    def fail_second_agent(agent, *args, **kwargs):
        if agent == "react":
            raise RuntimeError("private-token=do-not-persist")
        return original_execute(agent, *args, **kwargs)

    monkeypatch.setattr(runtime, "_execute_agent", fail_second_agent)
    result = run_agent_task(tenant_id, "Calculate 17 * 23")

    assert result["status"] == "BLOCK"
    assert result["run_status"] == "FAILED"
    assert result["run_id"]
    assert result["audit_verification"]["status"] == "BLOCK"
    assert result["audit_verification"]["audit_status"] == "VERIFIED"
    assert result["audit_verification"]["run_status"] == "FAILED"

    rows, events = _run_events(tenant_id, result["run_id"])
    event_types = [record_type for record_type, _ in events]
    assert event_types == ["run.start", "agent.codeact", "run.end"]
    end = events[-1][1]
    assert end["status"] == "FAILED"
    assert end["completed_agent_count"] == 1
    assert end["failure"]["agent"] == "react"
    assert end["failure"]["exception_type"] == "RuntimeError"
    assert end["failure"]["error_fingerprint"]
    assert "private-token" not in json.dumps(end)
    assert "do-not-persist" not in json.dumps(end)

    replay = verify_replay(
        rows,
        expected_run_id=result["run_id"],
        expected_tenant_id=tenant_id,
        expected_record_count=len(rows),
        expected_tip_hash=rows[-1]["record_hash"],
        require_lifecycle=True,
    )
    assert replay["status"] == "VERIFIED"
    assert replay["run_status"] == "FAILED"
