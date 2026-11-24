import hashlib
import json
import uuid

import app.agent_runtime as agent_runtime
from app.database import SessionLocal
from app.igor import IgorVerifier
from app.hashchain import compute_record_hash
from app.models import EvidenceRecord, Tenant
from app.pipeline_bridge import load_chain
from app.replay import verify_replay


def _tenant():
    tenant_id = str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="run-lifecycle-test"))
        db.commit()
    return tenant_id


def _run_events(chain, run_id):
    events = []
    for record in chain:
        payload = json.loads(record["payload_json"])
        if payload.get("run_id") == run_id and (
            record["record_type"] in {"run.start", "run.end"}
            or record["record_type"].startswith("agent.")
        ):
            events.append((record, payload))
    return events


def _replay(chain, run_id, tenant_id):
    return verify_replay(
        chain,
        expected_run_id=run_id,
        expected_tenant_id=tenant_id,
        expected_record_count=len(chain),
        expected_tip_hash=chain[-1]["record_hash"] if chain else None,
    )


def test_successful_run_has_auditable_start_end_and_replay(monkeypatch):
    monkeypatch.setenv("OLA_LLM_MODE", "deterministic")
    monkeypatch.setenv("OLA_SOURCE_COMMIT", "test-source-commit")
    monkeypatch.delenv("OLA_REPLAY_NONCE", raising=False)
    tenant_id = _tenant()

    result = agent_runtime.run_agent_task(tenant_id, "calculate 6 * 7")
    chain = load_chain(tenant_id)
    events = _run_events(chain, result["run_id"])
    types = [record["record_type"] for record, _ in events]

    assert types == [
        "run.start",
        *[f"agent.{role}" for role in agent_runtime.AGENT_ROLES],
        "run.end",
    ]
    start_record, start = events[0]
    end_record, end = events[-1]
    assert start["schema"] == "ola.run-lifecycle/v1"
    assert end["schema"] == "ola.run-lifecycle/v1"
    assert start["source_commit"] == "test-source-commit"
    assert start["replay_nonce"] == result["replay_nonce"]
    assert end["start_record_hash"] == start_record["record_hash"]
    assert end["outcome"] == "SUCCEEDED"
    assert end["completed_agent_roles"] == agent_runtime.AGENT_ROLES
    assert end["agent_event_count"] == len(agent_runtime.AGENT_ROLES)
    assert end["run_event_digest"]
    assert end_record["seq"] > events[-2][0]["seq"]
    assert result["status"] == "VERIFIED"

    verified = agent_runtime.verify_agent_run(tenant_id, result["run_id"])
    replay = _replay(chain, result["run_id"], tenant_id)
    assert verified["status"] == "VERIFIED"
    assert verified["lifecycle"]["status"] == "VERIFIED"
    assert replay["status"] == "VERIFIED"
    assert replay["execution_status"] == "SUCCEEDED"
    assert replay["run_event_count"] == len(agent_runtime.AGENT_ROLES) + 2


    igor = IgorVerifier().verify_records(
        rows,
        "test-source-commit",
        "calculate 6 * 7",
        "42",
        expected_run_id=result["run_id"],
        expected_nonce=result["replay_nonce"],
        require_lifecycle=True,
    )
    assert igor.status == "VERIFIED", igor
    assert igor.checks["lifecycle"] is True
    assert igor.checks["execution_status"] == "SUCCEEDED"


def test_agent_exception_is_recorded_and_run_closes_as_failed(monkeypatch):
    monkeypatch.setenv("OLA_LLM_MODE", "deterministic")
    monkeypatch.delenv("OLA_REPLAY_NONCE", raising=False)
    tenant_id = _tenant()
    original = agent_runtime._execute_agent

    def fail_react(agent, *args, **kwargs):
        if agent == "react":
            raise TimeoutError("provider timeout with secret=do-not-store")
        return original(agent, *args, **kwargs)

    monkeypatch.setattr(agent_runtime, "_execute_agent", fail_react)
    result = agent_runtime.run_agent_task(tenant_id, "calculate 6 * 7")
    chain = load_chain(tenant_id)
    events = _run_events(chain, result["run_id"])
    types = [record["record_type"] for record, _ in events]
    failure = events[-2][1]
    end = events[-1][1]

    assert types == ["run.start", "agent.codeact", "agent.react", "run.end"]
    assert result["status"] == "BLOCK"
    assert failure["status"] == "BLOCK"
    assert failure["execution_status"] == "FAILED"
    assert failure["error_type"] == "TimeoutError"
    assert failure["error_digest"] == hashlib.sha256(
        f"ola.agent-failure/v1|{result['run_id']}|react|TimeoutError".encode()
    ).hexdigest()
    assert "do-not-store" not in failure.values()
    assert end["outcome"] == "FAILED"
    assert end["error_digest"] == failure["error_digest"]
    assert end["failed_agent"] == "react"
    assert end["completed_agent_roles"] == ["codeact"]
    assert agent_runtime.verify_agent_run(tenant_id, result["run_id"])["status"] == "BLOCK"

    replay = _replay(chain, result["run_id"], tenant_id)
    assert replay["status"] == "VERIFIED"
    assert replay["execution_status"] == "FAILED"
    assert replay["failed_agent"] == "react"


    igor = IgorVerifier().verify_records(
        chain,
        "test-source-commit",
        "calculate 6 * 7",
        "42",
        expected_run_id=result["run_id"],
        expected_nonce=result["replay_nonce"],
        require_lifecycle=True,
    )
    assert igor.status == "BLOCK"
    assert igor.checks["lifecycle"] is True
    assert igor.checks["execution_status"] == "FAILED"


def test_replay_rejects_a_missing_run_end_record(monkeypatch):
    monkeypatch.setenv("OLA_LLM_MODE", "deterministic")
    tenant_id = _tenant()
    result = agent_runtime.run_agent_task(tenant_id, "calculate 2 + 2")
    chain = load_chain(tenant_id)
    without_end = [
        record for record in chain
        if not (
            record["record_type"] == "run.end"
            and json.loads(record["payload_json"]).get("run_id") == result["run_id"]
        )
    ]

    replay = verify_replay(
        without_end,
        expected_run_id=result["run_id"],
        expected_tenant_id=tenant_id,
        expected_record_count=len(without_end),
        expected_tip_hash=without_end[-1]["record_hash"],
    )
    assert replay["status"] == "BLOCK"
    assert replay["reason"] == "run lifecycle end missing or duplicated"


def test_replay_rejects_a_resealed_but_inconsistent_run_event_digest(monkeypatch):
    monkeypatch.setenv("OLA_LLM_MODE", "deterministic")
    tenant_id = _tenant()
    result = agent_runtime.run_agent_task(tenant_id, "calculate 3 * 3")
    chain = load_chain(tenant_id)
    end_record = next(
        record for record in chain
        if record["record_type"] == "run.end"
        and json.loads(record["payload_json"]).get("run_id") == result["run_id"]
    )
    end_payload = json.loads(end_record["payload_json"])
    end_payload["run_event_digest"] = "f" * 64
    end_record["payload_json"] = json.dumps(end_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    end_record["record_hash"] = compute_record_hash(
        end_record["tenant_id"],
        end_record["seq"],
        end_record["prev_hash"],
        end_record["payload_json"],
        end_record["record_type"],
    )

    replay = _replay(chain, result["run_id"], tenant_id)
    assert replay["status"] == "BLOCK"
    assert replay["reason"] == "run event digest mismatch"


def test_malformed_tenant_payload_fails_closed_during_run_verification(monkeypatch):
    monkeypatch.setenv("OLA_LLM_MODE", "deterministic")
    tenant_id = _tenant()
    result = agent_runtime.run_agent_task(tenant_id, "calculate 2 + 2")
    chain = load_chain(tenant_id)
    previous = chain[-1]
    payload_json = "{malformed-json"
    record_type = "diagnostic.invalid"
    row = EvidenceRecord(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        seq=previous["seq"] + 1,
        record_type=record_type,
        payload_json=payload_json,
        prev_hash=previous["record_hash"],
        record_hash=compute_record_hash(
            tenant_id,
            previous["seq"] + 1,
            previous["record_hash"],
            payload_json,
            record_type,
        ),
    )
    with SessionLocal() as db:
        db.add(row)
        db.commit()

    verified = agent_runtime.verify_agent_run(tenant_id, result["run_id"])
    assert verified["status"] == "BLOCK"
    assert "payload" in verified["reason"]
