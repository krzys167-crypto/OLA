"""Shared NINA execution service for public and paid-order entry points."""
import json

from sqlalchemy import select

from .database import SessionLocal, append_evidence_atomic
from .models import EvidenceRecord
from .nina import NinaOrchestrator, NinaTask
from .runtime_provenance import runtime_source_commit
from .igor import IgorVerifier
from .replay import build_replay, verify_replay
from .human_gate import ReviewDecision
from .nina_igor import NinaIgorChain
from .decision_report import build_decision_report


def append_record(tenant_id, record_type, payload, *, deduplicate=False):
    return append_evidence_atomic(tenant_id, record_type, payload, deduplicate=deduplicate)


def run_nina_task(tenant_id, requester_id, task_text, requested_tools, *, execution_context=None):
    if not isinstance(task_text, str) or not task_text.strip():
        raise ValueError("task is required")
    if not isinstance(requested_tools, list):
        raise ValueError("requested_tools must be a list")
    execution_context = dict(execution_context or {})
    nina_task = NinaTask.create(tenant_id, task_text, requested_tools, requester_id)
    nina = NinaOrchestrator()
    plan = nina.plan(nina_task)
    if plan.status != "ALLOW":
        return {
            "task_id": nina_task.task_id,
            "nina": {"status": plan.status, "reason": plan.reason},
            "igor": {"status": "UNKNOWN", "reason": "execution did not start"},
            "provenance": {"status": "NOT_CREATED"},
            "replay": [],
            "replay_verification": {"status": "UNKNOWN", "reason": "execution did not start"},
            "human_gate": {"status": "BLOCK", "reason": "NINA blocked execution"},
            "status": "BLOCK",
        }

    runtime = nina.execute(nina_task)
    run_id = runtime["runtime"]["run_id"]
    execution = runtime["runtime"].get("execution", [])
    runtime_commit = runtime_source_commit()
    provider = execution[0].get("provider") if execution else None
    model = execution[0].get("model") if execution else None
    invocation_type = execution[0].get("invocation_type") if execution else None
    response_ids = [item.get("response_id") for item in execution if item.get("response_id")]
    append_record(
        tenant_id,
        "provenance.runtime",
        {
            "run_id": run_id,
            "commit": runtime_commit or "UNKNOWN",
            "task": task_text,
            "result": runtime["runtime"].get("final_result"),
            "provider": provider,
            "model": model,
            "invocation_type": invocation_type,
            "llm_invocations": len(execution),
            "response_ids": response_ids,
            "requester_id": requester_id,
            **execution_context,
        },
    )

    with SessionLocal() as db:
        rows = db.scalars(
            select(EvidenceRecord)
            .where(EvidenceRecord.tenant_id == tenant_id)
            .order_by(EvidenceRecord.seq.asc())
        ).all()

    record_dicts = [
        {
            "id": row.id,
            "tenant_id": row.tenant_id,
            "seq": row.seq,
            "prev_hash": row.prev_hash,
            "record_hash": row.record_hash,
            "record_type": row.record_type,
            "payload_json": row.payload_json,
        }
        for row in rows
    ]
    run_record_dicts = []
    for record in record_dicts:
        try:
            payload = json.loads(record["payload_json"])
        except json.JSONDecodeError:
            continue
        if payload.get("run_id") == run_id:
            run_record_dicts.append(record)

    expected_provider = provider if invocation_type == "real_llm" else None
    expected_model = model if invocation_type == "real_llm" else None
    expected_result = execution[0].get("tool_output", "") if execution else ""
    igor = IgorVerifier().verify_records(
        record_dicts,
        runtime_commit,
        task_text,
        expected_result,
        expected_provider=expected_provider,
        expected_model=expected_model,
        expected_run_id=run_id,
    )
    replay = build_replay(record_dicts)
    replay_verification = verify_replay(
        record_dicts,
        expected_run_id=run_id,
        expected_tenant_id=tenant_id,
        expected_record_count=len(record_dicts),
        expected_tip_hash=record_dicts[-1]["record_hash"] if record_dicts else None,
    )

    review = ReviewDecision(
        False,
        "pending-human-approval",
        "human approval required before promotion",
    )
    terminal = NinaIgorChain.finalize(runtime.get("status", "UNKNOWN"), igor.status, review)
    nina_summary = {
        "status": runtime.get("status", "UNKNOWN"),
        "decision": plan.reason,
        "provider": provider,
        "model": model,
        "invocation_type": invocation_type,
        "llm_invocations": len(execution),
    }
    igor_summary = {"status": igor.status, "reason": igor.reason, "checks": igor.checks}
    provenance = {
        "status": "VERIFIED" if (
            runtime.get("status") == "VERIFIED"
            and runtime_commit
            and provider
            and model
            and invocation_type
            and (
                invocation_type != "real_llm"
                or len(response_ids) == len(execution)
            )
        ) else "BLOCK",
        "commit": runtime_commit or "UNKNOWN",
        "provider": provider,
        "model": model,
        "invocation_type": invocation_type,
        "llm_invocations": len(execution),
        "response_ids": response_ids,
    }
    report = build_decision_report(
        task_id=nina_task.task_id,
        run_id=run_id,
        task=task_text,
        nina=nina_summary,
        igor=igor_summary,
        replay={"status": replay_verification["status"], "events": replay, "verification": replay_verification},
        human_gate=terminal,
        evidence_ids=[record["id"] for record in run_record_dicts],
        human_approved=review.approved,
        human_actor=review.actor,
        human_reason=review.reason,
    )

    replay_integrity_status = (
        "VERIFIED"
        if replay_verification["status"] == "VERIFIED"
        else replay_verification["status"]
    )
    status_fields = {
        "RUNTIME": nina_summary["status"],
        "EVIDENCE": provenance["status"],
        "REPLAY_INTEGRITY": replay_integrity_status,
        "POLICY": report["policy"]["status"],
        "HUMAN_GATE": "REVIEW",
    }
    execution_allowed_status = NinaIgorChain.derive_status(status_fields)
    status_fields["EXECUTION_ALLOWED"] = execution_allowed_status
    derived_status = execution_allowed_status
    candidate_record = append_record(
        tenant_id,
        "decision.candidate",
        {
            "run_id": run_id,
            "requester_id": requester_id,
            "status_fields": status_fields,
            "candidate_status": derived_status,
            "decision_report_sha256": report["report_sha256"],
            "source_commit": runtime_commit or "UNKNOWN",
            **execution_context,
        },
    )
    tip_hash = candidate_record["record_hash"]

    return {
        "task_id": nina_task.task_id,
        "run_id": run_id,
        "tip_hash": tip_hash,
        "nina": nina_summary,
        "igor": igor_summary,
        "provenance": provenance,
        "replay": replay,
        "replay_verification": replay_verification,
        "human_gate": terminal,
        "policy": report["policy"],
        "status_fields": status_fields,
        "decision_report": report,
        "status": derived_status,
    }
