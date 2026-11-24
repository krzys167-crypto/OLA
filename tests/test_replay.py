import hashlib
import json
from datetime import datetime, timedelta, timezone

from app.hashchain import GENESIS_HASH, compute_record_hash
from app.replay import build_replay, run_event_digest, verify_replay


def _append(records, record_type, payload, tenant_id="tenant-1"):
    seq = len(records)
    prev_hash = GENESIS_HASH if not records else records[-1]["record_hash"]
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    record = {
        "id": f"e{seq}",
        "tenant_id": tenant_id,
        "seq": seq,
        "record_type": record_type,
        "payload_json": payload_json,
        "prev_hash": prev_hash,
    }
    record["record_hash"] = compute_record_hash(
        tenant_id, seq, prev_hash, payload_json, record_type
    )
    records.append(record)
    return record


def _chain(count=2, run_id="r1", tenant_id="tenant-1"):
    roles = ["codeact", "react", "agentic_rag", "mcp_tool_use", "self_reflection", "multi_agent"][:count]
    records = []
    task = "calculate 2 + 2"
    nonce = "a" * 64
    source_commit = "test-commit"
    started_at = "2026-11-24T19:00:00+00:00"
    _append(records, "run.start", {
        "schema": "ola.run-lifecycle/v1",
        "run_id": run_id,
        "started_at": started_at,
        "task_digest": hashlib.sha256(task.encode()).hexdigest(),
        "source_commit": source_commit,
        "replay_nonce": nonce,
        "expected_agent_roles": roles,
    }, tenant_id)
    for index, role in enumerate(roles):
        base = datetime(2026, 11, 24, 19, 0, 0, tzinfo=timezone.utc)
        agent_started_at = (base + timedelta(milliseconds=100 + index * 200)).isoformat()
        agent_ended_at = (base + timedelta(milliseconds=150 + index * 200)).isoformat()
        _append(records, f"agent.{role}", {
            "run_id": run_id,
            "agent": role,
            "task": task,
            "status": "VERIFIED",
            "replay_nonce": nonce,
            "source_commit": source_commit,
            "tool": "safe_expression",
            "input_digest": hashlib.sha256(f"in-{role}".encode()).hexdigest(),
            "started_at": agent_started_at,
            "ended_at": agent_ended_at,
            "agent_instance_id": f"instance-{role}",
            "context_digest": hashlib.sha256(role.encode()).hexdigest(),
            "execution_boundary": "independent",
            "provider": "local",
            "model": "deterministic-runtime-v1",
            "invocation_type": "local_deterministic_model",
        }, tenant_id)
    start_record = records[0]
    pre_end = list(records)
    _append(records, "run.end", {
        "schema": "ola.run-lifecycle/v1",
        "run_id": run_id,
        "started_at": started_at,
        "ended_at": "2026-11-24T19:00:03+00:00",
        "task_digest": __import__("hashlib").sha256(task.encode()).hexdigest(),
        "source_commit": source_commit,
        "replay_nonce": nonce,
        "expected_agent_roles": roles,
        "outcome": "SUCCEEDED",
        "completed_agent_roles": roles,
        "failed_agent": None,
        "error_type": None,
        "error_digest": None,
        "start_record_id": start_record["id"],
        "start_record_hash": start_record["record_hash"],
        "agent_event_count": count,
        "run_event_count": len(pre_end),
        "run_event_digest": run_event_digest(pre_end),
    }, tenant_id)
    return records


def _reseal(records):
    previous = GENESIS_HASH
    for seq, record in enumerate(records):
        record["seq"] = seq
        record["prev_hash"] = previous
        record["record_hash"] = compute_record_hash(
            record["tenant_id"], seq, previous, record["payload_json"], record["record_type"]
        )
        previous = record["record_hash"]


def _verify(rows, run_id="r1", tenant_id="tenant-1"):
    return verify_replay(
        rows,
        expected_run_id=run_id,
        expected_tenant_id=tenant_id,
        expected_record_count=len(rows),
        expected_tip_hash=rows[-1]["record_hash"] if rows else None,
    )


def test_replay_verifies_raw_records_full_hash_chain_and_run_lifecycle():
    rows = _chain(count=2)
    result = _verify(rows)

    assert result["status"] == "VERIFIED"
    assert result["event_count"] == len(rows)
    assert result["run_event_count"] == 4
    assert result["execution_status"] == "SUCCEEDED"
    assert result["lifecycle"]["status"] == "VERIFIED"
    assert result["first_seq"] == 0
    assert result["last_seq"] == len(rows) - 1
    assert result["tip_hash"] == rows[-1]["record_hash"]
    assert len(build_replay(rows)) == len(rows)


def test_completed_policy_block_has_verified_integrity_but_blocked_execution():
    rows = _chain(count=6)
    self_reflection = json.loads(rows[5]["payload_json"])
    self_reflection["status"] = "BLOCK"
    self_reflection["execution_status"] = "VERIFIED"
    rows[5]["payload_json"] = json.dumps(
        self_reflection, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    end = json.loads(rows[-1]["payload_json"])
    end["outcome"] = "COMPLETED_BLOCKED"
    end["blocked_agent_roles"] = ["self_reflection"]
    end["failed_agent"] = None
    end["completed_agent_roles"] = [
        "codeact", "react", "agentic_rag", "mcp_tool_use", "self_reflection", "multi_agent"
    ]
    rows[-1]["payload_json"] = json.dumps(end, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    _reseal(rows)
    end = json.loads(rows[-1]["payload_json"])
    end["run_event_digest"] = run_event_digest(rows[:-1])
    rows[-1]["payload_json"] = json.dumps(end, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    _reseal(rows)

    result = _verify(rows)
    assert result["status"] == "VERIFIED"
    assert result["execution_status"] == "BLOCKED"
    assert result["blocked_agent_roles"] == ["self_reflection"]


def test_replay_requires_expected_tip_hash():
    rows = _chain(count=2)
    result = verify_replay(
        rows, expected_run_id="r1", expected_tenant_id="tenant-1",
        expected_record_count=len(rows), expected_tip_hash="f" * 64,
    )
    assert result["status"] == "BLOCK"
    assert result["reason"] == "tip hash mismatch"


def test_replay_rejects_agent_type_and_status_mutations():
    rows = _chain(count=2)
    rows[1]["record_type"] = "agent.tampered"
    result = _verify(rows)
    assert result["status"] == "BLOCK"
    assert result["reason"] == "record hash mismatch"

    rows = _chain(count=2)
    payload = json.loads(rows[2]["payload_json"])
    payload["status"] = "BLOCK"
    rows[2]["payload_json"] = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    end_payload = json.loads(rows[-1]["payload_json"])
    end_payload["run_event_digest"] = run_event_digest(rows[:-1])
    rows[-1]["payload_json"] = json.dumps(end_payload, sort_keys=True, separators=(",", ":"))
    _reseal(rows)
    result = _verify(rows)
    assert result["status"] == "BLOCK"
    assert result["reason"] == "successful run has incomplete agent evidence"


def test_replay_blocks_agent_record_type_payload_mismatch_after_valid_reseal():
    rows = _chain(count=2)
    rows[1]["record_type"] = "agent.react"
    _reseal(rows)
    result = _verify(rows)
    assert result["status"] == "BLOCK"
    assert result["reason"] == "run agent record type mismatch"


def test_replay_blocks_non_object_payload_without_exception():
    rows = _chain(count=1)
    rows[1]["payload_json"] = json.dumps(["not", "an", "object"])
    _reseal(rows)
    result = _verify(rows)
    assert result["status"] == "BLOCK"
    assert result["reason"] == "payload must be a JSON object"


def test_replay_uses_existing_verify_chain(monkeypatch):
    rows = _chain(count=2)

    def reject_chain(_records):
        return False, "forced verify_chain failure"

    monkeypatch.setattr("app.replay.verify_chain", reject_chain)
    result = _verify(rows)
    assert result["status"] == "BLOCK"
    assert result["reason"] == "forced verify_chain failure"


def test_replay_blocks_tampered_record_hash():
    rows = _chain(count=2)
    rows[2]["record_hash"] = "f" * 64
    result = _verify(rows)
    assert result["status"] == "BLOCK"
    assert result["reason"] == "record hash mismatch"


def test_replay_blocks_tampered_predecessor_hash():
    rows = _chain(count=2)
    rows[2]["prev_hash"] = "e" * 64
    result = _verify(rows)
    assert result["status"] == "BLOCK"
    assert result["reason"] == "sequence or predecessor mismatch"


def test_replay_requires_genesis_hash_at_sequence_zero():
    rows = _chain(count=2)
    rows[0]["prev_hash"] = "1" * 64
    result = _verify(rows)
    assert result["status"] == "BLOCK"
    assert result["reason"] == "sequence or predecessor mismatch"


def test_replay_requires_sequence_to_start_at_zero():
    rows = _chain(count=2)
    rows[0]["seq"] = 1
    result = _verify(rows)
    assert result["status"] == "BLOCK"
    assert result["reason"] == "sequence or predecessor mismatch"


def test_replay_blocks_wrong_tenant():
    rows = _chain(count=2)
    result = verify_replay(
        rows, expected_run_id="r1", expected_tenant_id="tenant-other",
        expected_record_count=len(rows), expected_tip_hash=rows[-1]["record_hash"],
    )
    assert result["status"] == "BLOCK"
    assert result["reason"] == "tenant provenance mismatch"


def test_replay_blocks_wrong_expected_record_count():
    rows = _chain(count=2)
    result = verify_replay(
        rows, expected_run_id="r1", expected_tenant_id="tenant-1",
        expected_record_count=len(rows) + 1, expected_tip_hash=rows[-1]["record_hash"],
    )
    assert result["status"] == "BLOCK"
    assert result["reason"] == "record count mismatch"


def test_replay_blocks_wrong_run_id():
    rows = _chain(count=2, run_id="actual-run")
    result = _verify(rows, run_id="expected-run")
    assert result["status"] == "BLOCK"
    assert result["reason"] == "run lifecycle start missing or duplicated"


def test_replay_rejects_empty_records():
    result = verify_replay(
        [], expected_run_id="r1", expected_tenant_id="tenant-1",
        expected_record_count=0, expected_tip_hash=None,
    )
    assert result["status"] == "UNKNOWN"
    assert result["reason"] == "replay is empty"
