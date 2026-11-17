"""Atomic, tip-bound review of a completed NINA DAG.

Two distinct API key identities are required; this is NOT GitHub PR approval
and does not grant deployment privileges.
"""
import json

from sqlalchemy import select
from .database import SessionLocal, begin_write_transaction
from .runtime_provenance import runtime_source_commit
from .models import EvidenceRecord
from .evidence_writer import append_evidence_v4_locked
from .igor_evidence_verifier import verify_chain, trusted_record
from .igor_workflow import verify_dag_records
from .human_gate import HumanGate, ReviewDecision
from .nina_igor import NinaIgorChain, STATUS_FIELDS


class WorkflowApprovalRejected(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def approve_workflow(*, tenant_id, approver_id, run_id, tip_hash, report_digest, reason):
    if not all(isinstance(x, str) and x.strip() for x in (
            tenant_id, approver_id, run_id, tip_hash, report_digest, reason)):
        raise WorkflowApprovalRejected(400, "approval requires tip, report digest and reason")
    expected_commit = runtime_source_commit()
    if not expected_commit:
        raise WorkflowApprovalRejected(409, "runtime source commit unknown")

    # Read and verify outside the tenant-scoped write lock; IGOR can scan
    # without blocking unrelated evidence writers.
    with SessionLocal() as db:
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

    # Reacquire the tenant chain lock and recheck the tip before writing.
    with SessionLocal() as db:
        begin_write_transaction(db, tenant_id=tenant_id)
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
        approval = append_evidence_v4_locked(
            db, tenant_id, "human.workflow_approval", payload,
        )
        next_hash = approval["record_hash"]
        db.commit()
        return {
            "status": "APPROVED_FOR_REVIEW_ONLY", "run_id": run_id,
            "approved_tip_hash": tip_hash, "approved_report_digest": report_digest,
            "approval_record_hash": next_hash, "approver_id": approver_id,
            "production_authorized": False,
        }


def approve_nina_candidate(*, tenant_id, approver_id, run_id, tip_hash,
                           report_sha256, reason):
    """One-time, report-bound second-identity review; never a deploy permit."""
    if not isinstance(reason, str) or not reason.strip():
        raise WorkflowApprovalRejected(400, "nonempty review reason is required")
    if not all(isinstance(value, str) and value.strip() for value in (
            tenant_id, approver_id, run_id, tip_hash, report_sha256)):
        raise WorkflowApprovalRejected(400, "run, tip and report digest are required")
    expected_commit = runtime_source_commit()
    if not expected_commit:
        raise WorkflowApprovalRejected(409, "runtime source identity unavailable")

    with SessionLocal() as db:
        rows = db.scalars(
            select(EvidenceRecord)
            .where(EvidenceRecord.tenant_id == tenant_id)
            .order_by(EvidenceRecord.seq.asc())
        ).all()
        if not rows or rows[-1].record_hash != tip_hash:
            raise WorkflowApprovalRejected(409, "stale or unknown evidence tip")
        records = [{
            "tenant_id": row.tenant_id, "seq": row.seq,
            "record_hash": row.record_hash, "prev_hash": row.prev_hash,
            "record_type": row.record_type, "payload_json": row.payload_json,
        } for row in rows]
        if not verify_chain(records)[0]:
            raise WorkflowApprovalRejected(409, "evidence chain verification failed")

        candidates = []
        for row in records:
            if row["record_type"] not in {"decision.candidate", "human.approval"}:
                continue
            payload = json.loads(row["payload_json"])
            if payload.get("run_id") != run_id:
                continue
            if not trusted_record(row):
                raise WorkflowApprovalRejected(409, "untrusted decision evidence")
            if row["record_type"] == "human.approval":
                raise WorkflowApprovalRejected(409, "run already reviewed")
            candidates.append(payload)

        if len(candidates) != 1:
            raise WorkflowApprovalRejected(409, "unique decision candidate required")
        candidate = candidates[0]
        requester_id = candidate.get("requester_id")
        if not isinstance(requester_id, str) or not requester_id:
            raise WorkflowApprovalRejected(409, "requester identity missing")
        if requester_id == approver_id:
            raise WorkflowApprovalRejected(403, "requester cannot approve own run")
        if candidate.get("decision_report_sha256") != report_sha256:
            raise WorkflowApprovalRejected(409, "independent report digest mismatch")
        if candidate.get("source_commit") != expected_commit:
            raise WorkflowApprovalRejected(409, "candidate source commit mismatch")

        fields = candidate.get("status_fields")
        if not isinstance(fields, dict) or set(fields) != {*STATUS_FIELDS, "EXECUTION_ALLOWED"}:
            raise WorkflowApprovalRejected(409, "invalid candidate status fields")
        scoped_fields = {name: fields[name] for name in STATUS_FIELDS}
        if (candidate.get("candidate_status") != "REVIEW"
                or scoped_fields["HUMAN_GATE"] != "REVIEW"
                or fields["EXECUTION_ALLOWED"] != NinaIgorChain.derive_status(scoped_fields)):
            raise WorkflowApprovalRejected(409, "candidate status is inconsistent")
        scoped_fields["HUMAN_GATE"] = "VERIFIED"
        if NinaIgorChain.derive_status(scoped_fields) != "VERIFIED":
            raise WorkflowApprovalRejected(409, "candidate is not eligible for review")

    with SessionLocal() as db:
        begin_write_transaction(db, tenant_id=tenant_id)
        latest = db.scalar(
            select(EvidenceRecord)
            .where(EvidenceRecord.tenant_id == tenant_id)
            .order_by(EvidenceRecord.seq.desc())
        )
        if latest is None or latest.record_hash != tip_hash:
            raise WorkflowApprovalRejected(409, "evidence tip changed during review")
        payload = {
            "event": "human.approval", "run_id": run_id,
            "tenant_id": tenant_id, "requester_id": requester_id,
            "approver_id": approver_id, "reason": reason.strip(),
            "approved_tip_hash": tip_hash,
            "approved_report_sha256": report_sha256,
            "commit": expected_commit,
            "decision": "APPROVED_FOR_REVIEW_ONLY",
            "production_authorized": False,
        }
        approval = append_evidence_v4_locked(
            db, tenant_id, "human.approval", payload,
        )
        next_hash = approval["record_hash"]
        record_id = approval["id"]
        db.commit()
        return {
            "status": "APPROVED_FOR_REVIEW_ONLY", "run_id": run_id,
            "tip_hash": next_hash, "approved_tip_hash": tip_hash,
            "approved_report_sha256": report_sha256,
            "record_id": record_id, "record_type": "human.approval",
            "approver_id": approver_id, "production_authorized": False,
        }
