import hashlib
import json
import re
from datetime import datetime

from .hashchain import canonical_json, verify_chain


RUN_LIFECYCLE_SCHEMA = "ola.run-lifecycle/v1"


def _payload(record):
    try:
        value = json.loads(record["payload_json"])
    except (KeyError, TypeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _run_lifecycle_records(records, expected_run_id):
    selected = []
    for record in records:
        payload = _payload(record)
        record_type = record.get("record_type", "")
        if payload and payload.get("run_id") == expected_run_id and (
            record_type in {"run.start", "run.end"} or record_type.startswith("agent.")
        ):
            selected.append((record, payload))
    return selected


def run_event_digest(records):
    """Digest the immutable identities of all run events preceding run.end."""
    projection = [
        {
            "id": record["id"],
            "seq": record["seq"],
            "record_type": record["record_type"],
            "record_hash": record["record_hash"],
        }
        for record in sorted(records, key=lambda item: item["seq"])
    ]
    return hashlib.sha256(canonical_json(projection).encode("utf-8")).hexdigest()


def _parse_timestamp(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def build_replay(records):
    replay = []
    for record in sorted(records, key=lambda item: item["seq"]):
        payload = _payload(record)
        if payload is not None:
            replay.append({
                "id": record.get("id"),
                "tenant_id": record.get("tenant_id"),
                "seq": record["seq"],
                "record_type": record.get("record_type"),
                "run_id": payload.get("run_id"),
                "agent": payload.get("agent"),
                "input_digest": payload.get("input_digest"),
                "tool": payload.get("tool"),
                "status": payload.get("status"),
                "outcome": payload.get("outcome"),
                "started_at": payload.get("started_at"),
                "ended_at": payload.get("ended_at"),
                "error_type": payload.get("error_type"),
                "replay_nonce": payload.get("replay_nonce"),
            })
        else:
            replay.append({
                "id": record.get("id"),
                "tenant_id": record.get("tenant_id"),
                "seq": record.get("seq"),
                "record_type": record.get("record_type"),
                "run_id": None,
                "agent": None,
                "input_digest": None,
                "tool": None,
                "status": None,
                "outcome": None,
                "started_at": None,
                "ended_at": None,
                "error_type": None,
                "replay_nonce": None,
            })
    return replay


def verify_replay(records, expected_run_id, expected_tenant_id,
                  expected_record_count=None, expected_tip_hash=None):
    """Verify the tenant chain and a complete, independently replayable run lifecycle.

    A replay status of VERIFIED means the evidence is internally consistent. The
    separate execution_status field can still be FAILED; integrity never promotes
    a failed agent run into successful work.
    """
    if not records:
        return {"status": "UNKNOWN", "reason": "replay is empty", "event_count": 0}

    if expected_record_count is not None and len(records) != expected_record_count:
        return {
            "status": "BLOCK",
            "reason": "record count mismatch",
            "event_count": len(records),
            "expected_record_count": expected_record_count,
        }

    for record in records:
        if not isinstance(record, dict):
            return {"status": "BLOCK", "reason": "record must be a dict", "event_count": len(records)}
        required = {"tenant_id", "seq", "prev_hash", "record_hash", "record_type", "payload_json"}
        if not required.issubset(record):
            return {"status": "BLOCK", "reason": "evidence record is incomplete", "event_count": len(records)}
        if record.get("tenant_id") != expected_tenant_id:
            return {"status": "BLOCK", "reason": "tenant provenance mismatch", "event_count": len(records)}
        if not isinstance(record.get("record_type"), str) or not record["record_type"]:
            return {"status": "BLOCK", "reason": "record type is missing", "event_count": len(records)}
        if not isinstance(record.get("payload_json"), str):
            return {"status": "BLOCK", "reason": "missing payload_json", "event_count": len(records)}
        if _payload(record) is None:
            return {"status": "BLOCK", "reason": "payload must be a JSON object", "event_count": len(records)}

    chain_ok, reason = verify_chain(records)
    if not chain_ok:
        return {"status": "BLOCK", "reason": reason, "event_count": len(records)}

    if expected_tip_hash is not None and records[-1].get("record_hash") != expected_tip_hash:
        return {
            "status": "BLOCK",
            "reason": "tip hash mismatch",
            "event_count": len(records),
            "tip_hash": records[-1].get("record_hash"),
        }

    run_events = _run_lifecycle_records(records, expected_run_id)
    starts = [(record, payload) for record, payload in run_events if record["record_type"] == "run.start"]
    ends = [(record, payload) for record, payload in run_events if record["record_type"] == "run.end"]
    if len(starts) != 1:
        return {
            "status": "BLOCK",
            "reason": "run lifecycle start missing or duplicated",
            "event_count": len(records),
        }
    if len(ends) != 1:
        return {
            "status": "BLOCK",
            "reason": "run lifecycle end missing or duplicated",
            "event_count": len(records),
        }

    start_record, start = starts[0]
    end_record, end = ends[0]
    run_records = [record for record, _ in run_events]
    if run_records[0]["record_type"] != "run.start" or run_records[-1]["record_type"] != "run.end":
        return {"status": "BLOCK", "reason": "run lifecycle ordering mismatch", "event_count": len(records)}
    if start_record["seq"] >= end_record["seq"]:
        return {"status": "BLOCK", "reason": "run lifecycle ordering mismatch", "event_count": len(records)}

    for payload in (start, end):
        if payload.get("schema") != RUN_LIFECYCLE_SCHEMA:
            return {"status": "BLOCK", "reason": "run lifecycle schema mismatch", "event_count": len(records)}
        if payload.get("run_id") != expected_run_id:
            return {"status": "BLOCK", "reason": "run lifecycle run id mismatch", "event_count": len(records)}

    expected_roles = start.get("expected_agent_roles")
    if (
        not isinstance(expected_roles, list)
        or not expected_roles
        or any(not isinstance(role, str) or not role for role in expected_roles)
        or len(set(expected_roles)) != len(expected_roles)
    ):
        return {"status": "BLOCK", "reason": "run lifecycle agent roster invalid", "event_count": len(records)}
    if end.get("expected_agent_roles") != expected_roles:
        return {"status": "BLOCK", "reason": "run lifecycle agent roster mismatch", "event_count": len(records)}

    agent_events = [(record, payload) for record, payload in run_events if record["record_type"].startswith("agent.")]
    agent_roles = [payload.get("agent") for _, payload in agent_events]
    if len(agent_events) > len(expected_roles) or agent_roles != expected_roles[:len(agent_roles)]:
        return {"status": "BLOCK", "reason": "run agent order mismatch", "event_count": len(records)}

    agent_instance_ids = set()
    context_digests = set()
    real_llm_events = []
    for record, payload in agent_events:
        role = payload.get("agent")
        if record["record_type"] != f"agent.{role}":
            return {"status": "BLOCK", "reason": "run agent record type mismatch", "event_count": len(records)}
        required_agent_fields = {
            "agent_instance_id", "execution_boundary", "context_digest",
            "input_digest", "task", "started_at", "ended_at",
            "source_commit", "replay_nonce", "status",
        }
        if not required_agent_fields.issubset(payload):
            return {"status": "BLOCK", "reason": "run agent evidence incomplete", "event_count": len(records)}
        if payload.get("execution_boundary") != "independent":
            return {"status": "BLOCK", "reason": "run agent execution boundary mismatch", "event_count": len(records)}
        instance_id = payload.get("agent_instance_id")
        context_digest = payload.get("context_digest")
        input_digest = payload.get("input_digest")
        if not isinstance(instance_id, str) or not instance_id:
            return {"status": "BLOCK", "reason": "run agent instance identity missing", "event_count": len(records)}
        if not isinstance(context_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", context_digest):
            return {"status": "BLOCK", "reason": "run agent context digest malformed", "event_count": len(records)}
        if not isinstance(input_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", input_digest):
            return {"status": "BLOCK", "reason": "run agent input digest malformed", "event_count": len(records)}
        agent_instance_ids.add(instance_id)
        context_digests.add(context_digest)
        if payload.get("invocation_type") == "real_llm":
            real_llm_events.append(payload)
            if not (payload.get("response_id") or payload.get("response_digest")):
                return {"status": "BLOCK", "reason": "real LLM response identity missing", "event_count": len(records)}
    if len(agent_instance_ids) != len(agent_events) or len(context_digests) != len(agent_events):
        return {"status": "BLOCK", "reason": "run agent identities or contexts are not unique", "event_count": len(records)}

    statuses = [payload.get("status") for _, payload in agent_events]
    invocation_statuses = [payload.get("execution_status", "VERIFIED") for _, payload in agent_events]
    outcome = end.get("outcome")
    if outcome == "SUCCEEDED":
        if agent_roles != expected_roles or any(status != "VERIFIED" for status in statuses):
            return {"status": "BLOCK", "reason": "successful run has incomplete agent evidence", "event_count": len(records)}
        if any(status != "VERIFIED" for status in invocation_statuses):
            return {"status": "BLOCK", "reason": "successful run contains failed agent invocation", "event_count": len(records)}
        failed_agent = None
        completed_roles = expected_roles
        blocked_roles = []
        execution_status = "SUCCEEDED"
    elif outcome == "COMPLETED_BLOCKED":
        if agent_roles != expected_roles:
            return {"status": "BLOCK", "reason": "blocked run has incomplete agent evidence", "event_count": len(records)}
        if any(status != "VERIFIED" for status in invocation_statuses):
            return {"status": "BLOCK", "reason": "blocked decision contains failed agent invocation", "event_count": len(records)}
        blocked_roles = [role for role, status in zip(agent_roles, statuses) if status == "BLOCK"]
        if not blocked_roles or any(status not in {"VERIFIED", "BLOCK"} for status in statuses):
            return {"status": "BLOCK", "reason": "blocked run agent status sequence invalid", "event_count": len(records)}
        failed_agent = None
        completed_roles = expected_roles
        execution_status = "BLOCKED"
    elif outcome == "FAILED":
        if not agent_events or agent_roles != expected_roles[:len(agent_roles)]:
            return {"status": "BLOCK", "reason": "failed run agent order mismatch", "event_count": len(records)}
        if statuses[-1] != "BLOCK" or invocation_statuses[-1] != "FAILED":
            return {"status": "BLOCK", "reason": "failed run agent status sequence invalid", "event_count": len(records)}
        if any(status != "VERIFIED" for status in statuses[:-1]):
            return {"status": "BLOCK", "reason": "failed run prior agent status invalid", "event_count": len(records)}
        if any(status != "VERIFIED" for status in invocation_statuses[:-1]):
            return {"status": "BLOCK", "reason": "failed run prior invocation status invalid", "event_count": len(records)}
        failed_agent = agent_roles[-1]
        completed_roles = agent_roles[:-1]
        blocked_roles = []
        failure_payload = agent_events[-1][1]
        if (
            failure_payload.get("error_type") is None
            or not isinstance(failure_payload.get("error_digest"), str)
            or len(failure_payload["error_digest"]) != 64
            or end.get("failed_agent") != failed_agent
            or end.get("error_type") != failure_payload.get("error_type")
            or end.get("error_digest") != failure_payload.get("error_digest")
        ):
            return {"status": "BLOCK", "reason": "failed agent evidence is incomplete", "event_count": len(records)}
        execution_status = "FAILED"
    else:
        return {"status": "BLOCK", "reason": "run lifecycle outcome invalid", "event_count": len(records)}

    if end.get("completed_agent_roles") != completed_roles:
        return {"status": "BLOCK", "reason": "run lifecycle completion roster mismatch", "event_count": len(records)}
    if end.get("failed_agent") != failed_agent:
        return {"status": "BLOCK", "reason": "run lifecycle failure roster mismatch", "event_count": len(records)}
    if end.get("blocked_agent_roles", []) != blocked_roles:
        return {"status": "BLOCK", "reason": "run lifecycle blocked-agent roster mismatch", "event_count": len(records)}
    if end.get("agent_event_count") != len(agent_events):
        return {"status": "BLOCK", "reason": "run lifecycle agent event count mismatch", "event_count": len(records)}

    start_nonce = start.get("replay_nonce")
    start_commit = start.get("source_commit")
    if not isinstance(start_nonce, str) or not start_nonce:
        return {"status": "BLOCK", "reason": "run lifecycle replay nonce missing", "event_count": len(records)}
    if not isinstance(start_commit, str) or not start_commit:
        return {"status": "BLOCK", "reason": "run lifecycle source commit missing", "event_count": len(records)}
    if not isinstance(start.get("task_digest"), str) or not re.fullmatch(r"[0-9a-f]{64}", start["task_digest"]):
        return {"status": "BLOCK", "reason": "run lifecycle task digest missing or malformed", "event_count": len(records)}
    if real_llm_events and (
        start_commit.upper() == "UNKNOWN" or not re.fullmatch(r"[0-9a-f]{64}", start_nonce)
    ):
        return {"status": "BLOCK", "reason": "real LLM run source or replay challenge missing", "event_count": len(records)}
    if end.get("replay_nonce") != start_nonce or end.get("source_commit") != start_commit:
        return {"status": "BLOCK", "reason": "run lifecycle provenance mismatch", "event_count": len(records)}
    for _, payload in agent_events:
        if payload.get("replay_nonce") != start_nonce or payload.get("source_commit") != start_commit:
            return {"status": "BLOCK", "reason": "run agent provenance mismatch", "event_count": len(records)}
        if payload.get("task") is None or hashlib.sha256(str(payload["task"]).encode("utf-8")).hexdigest() != start.get("task_digest"):
            return {"status": "BLOCK", "reason": "run task digest mismatch", "event_count": len(records)}

    started_at = _parse_timestamp(start.get("started_at"))
    ended_at = _parse_timestamp(end.get("ended_at"))
    if started_at is None or ended_at is None or ended_at < started_at:
        return {"status": "BLOCK", "reason": "run lifecycle timestamps invalid", "event_count": len(records)}
    if end.get("started_at") != start.get("started_at"):
        return {"status": "BLOCK", "reason": "run lifecycle start timestamp mismatch", "event_count": len(records)}
    previous_agent_end = started_at
    for record, payload in agent_events:
        agent_started = _parse_timestamp(payload.get("started_at"))
        agent_ended = _parse_timestamp(payload.get("ended_at"))
        if agent_started is None or agent_ended is None or agent_ended < agent_started:
            return {"status": "BLOCK", "reason": "agent lifecycle timestamps invalid", "event_count": len(records)}
        if agent_started < previous_agent_end or agent_ended > ended_at:
            return {"status": "BLOCK", "reason": "agent lifecycle timing/order mismatch", "event_count": len(records)}
        previous_agent_end = agent_ended
    if end.get("start_record_id") != start_record.get("id") or end.get("start_record_hash") != start_record.get("record_hash"):
        return {"status": "BLOCK", "reason": "run lifecycle start anchor mismatch", "event_count": len(records)}

    pre_end_records = [record for record in run_records if record["record_type"] != "run.end"]
    if end.get("run_event_count") != len(pre_end_records):
        return {"status": "BLOCK", "reason": "run lifecycle event count mismatch", "event_count": len(records)}
    if end.get("run_event_digest") != run_event_digest(pre_end_records):
        return {"status": "BLOCK", "reason": "run event digest mismatch", "event_count": len(records)}

    return {
        "status": "VERIFIED",
        "reason": (
            "tenant hash-chain and run lifecycle verified; execution ended "
            + execution_status
        ),
        "event_count": len(records),
        "run_event_count": len(run_events),
        "run_id": expected_run_id,
        "tenant_id": expected_tenant_id,
        "execution_status": execution_status,
        "completed_agent_roles": completed_roles,
        "failed_agent": failed_agent,
        "blocked_agent_roles": blocked_roles,
        "lifecycle": {
            "status": "VERIFIED",
            "start_record_id": start_record.get("id"),
            "end_record_id": end_record.get("id"),
            "start_seq": start_record.get("seq"),
            "end_seq": end_record.get("seq"),
            "run_event_digest": end.get("run_event_digest"),
        },
        "first_seq": records[0]["seq"],
        "last_seq": records[-1]["seq"],
        "tip_hash": records[-1]["record_hash"],
    }
