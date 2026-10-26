"""Atomic, tip-bound review of a completed NINA DAG.

Two distinct API key identities are required; this is NOT GitHub PR approval
and does not grant deployment privileges.
"""
import json
import os
import uuid

from sqlalchemy import select
from .database import SessionLocal
from .models import EvidenceRecord
from .hashchain import sealed_payload_json, compute_record_hash_v2
from .igor_workflow import verify_dag_records
from .human_gate import HumanGate, ReviewDecision


class WorkflowApprovalRejected(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def approve_workflow(*, tenant_id, approver_id, run_id, tip_hash, report_digest, reason):
    if not all(isinstance(x, str) and x.strip() for x in (
            tenant_id, approver_id, run_id, tip_hash, report_digest, reason)):
        raise WorkflowApprovalRejected(400, "approval requires tip, report digest and reason")
    expected_commit = os.getenv("OLA_RUNTIME_COMMIT")
    if not expected_commit:
        raise WorkflowApprovalRejected(409, "runtime source commit unknown")

    # Read and verify outside the SQLite database-wide writer reservation.
    # An independent tenant writer remains free while IGOR scans the evidence.
    with SessionLocal() as db:
        if db.bind.dialect.name != "sqlite":
            raise WorkflowApprovalRejected(503, "approval transaction policy missing for this database")
        rows = db.scalars(
            select(EvidenceRecord)
            .where(EvidenceRecord.tenant_id == tenant_id)
            .order_by(EvidenceRecord.seq.asc())
        ).all()
        if not rows or rows[-1].record_hash != tip_hash:
            raise WorkflowApprovalRejected(409, "tip hash is stale or unknown")
        records = [{
            "tenant_id": row.tenant_id, "seq": row.seq,
            "record_hash": row.record_hash, "prev_hash": row.prev_hash,
            "record_type": row.record_type, "payload_json": row.payload_json,
        } for row in rows]
        if any(row["record_type"] == "human.workflow_approval"
               and json.loads(row["payload_json"]).get("run_id") == run_id for row in records):
            raise WorkflowApprovalRejected(409, "run already reviewed")
        plan_events = [json.loads(row["payload_json"]) for row in records
                       if row["record_type"] == "workflow.planned"
                       and json.loads(row["payload_json"]).get("run_id") == run_id]
        if len(plan_events) != 1:
            raise WorkflowApprovalRejected(409, "unique DAG plan evidence required")
        if plan_events[0].get("requester_id") == approver_id:
            raise WorkflowApprovalRejected(403, "requester cannot approve own workflow")
        report = verify_dag_records(
            records, tenant_id=tenant_id, run_id=run_id, expected_commit=expected_commit,
        )
        if report["status"] != "VERIFIED" or report.get("report_digest") != report_digest:
            raise WorkflowApprovalRejected(409, "independent IGOR report does not match approved tip")

    review = HumanGate.evaluate("VERIFIED", ReviewDecision(True, approver_id, reason))
    if review.status != "VERIFIED":
        raise WorkflowApprovalRejected(409, "human review gate denied")

    # Reacquire only the immutable chain tip under BEGIN IMMEDIATE.
    # Any concurrent evidence or approval append invalidates the old consent.
    with SessionLocal() as db:
        if db.bind.dialect.name != "sqlite":
            raise WorkflowApprovalRejected(503, "approval transaction policy missing for this database")
        db.connection().exec_driver_sql("BEGIN IMMEDIATE")
        latest = db.scalar(
            select(EvidenceRecord)
            .where(EvidenceRecord.tenant_id == tenant_id)
            .order_by(EvidenceRecord.seq.desc())
        )
        if latest is None or latest.record_hash != tip_hash:
            raise WorkflowApprovalRejected(409, "tip changed during independent review")
        payload = {
            "event": "human.workflow_approval", "run_id": run_id,
            "tenant_id": tenant_id, "approver_id": approver_id,
            "requester_id": plan_events[0]["requester_id"],
            "reason": reason, "approved_tip_hash": tip_hash,
            "approved_report_digest": report_digest,
            "commit": expected_commit,
            "decision": "APPROVED_FOR_REVIEW_ONLY",
        }
        raw = sealed_payload_json("human.workflow_approval", payload)
        next_seq = latest.seq + 1
        next_hash = compute_record_hash_v2(
            tenant_id, next_seq, tip_hash, "human.workflow_approval", "ola_runtime", raw
        )
        db.add(EvidenceRecord(
            id=str(uuid.uuid4()), tenant_id=tenant_id, seq=next_seq,
            record_type="human.workflow_approval", payload_json=raw,
            prev_hash=tip_hash, record_hash=next_hash,
        ))
        db.commit()
        return {
            "status": "APPROVED_FOR_REVIEW_ONLY", "run_id": run_id,
            "approved_tip_hash": tip_hash, "approved_report_digest": report_digest,
            "approval_record_hash": next_hash, "approver_id": approver_id,
            "production_authorized": False,
        }
