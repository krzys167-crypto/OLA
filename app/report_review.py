"""Independent report review and authenticated customer delivery for paid OLA orders."""
import hashlib
import json
import re
import time
import uuid

from sqlalchemy import select

from .database import SessionLocal, begin_write_transaction
from .hashchain import canonical_json
from .evidence_writer import append_evidence_v4_locked
from .igor_evidence_verifier import verify_chain, trusted_record
from .models import (
    CheckoutExecutionJob,
    CheckoutOrder,
    CheckoutOrderControl,
    CheckoutReportReview,
    EvidenceRecord,
    ApiKey,
)


class PaidReportReviewRejected(ValueError):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


def _tenant_records(db, tenant_id):
    rows = db.scalars(
        select(EvidenceRecord)
        .where(EvidenceRecord.tenant_id == tenant_id)
        .order_by(EvidenceRecord.seq.asc())
    ).all()
    records = [{
        "id": row.id,
        "tenant_id": row.tenant_id,
        "seq": row.seq,
        "record_type": row.record_type,
        "prev_hash": row.prev_hash,
        "record_hash": row.record_hash,
        "payload_json": row.payload_json,
    } for row in rows]
    return rows, records


def _append_locked(db, tenant_id, record_type, payload):
    return append_evidence_v4_locked(
        db, tenant_id, record_type, payload, producer_id="ola_runtime",
    )


def _verified_report_digest(report):
    if not isinstance(report, dict):
        return None
    decision_report = report.get("decision_report")
    if not isinstance(decision_report, dict):
        return None
    material = dict(decision_report)
    supplied = material.pop("report_sha256", None)
    computed = hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()
    return computed if supplied == computed else None


def _trusted_review_evidence(records, review, order_id):
    matches = [row for row in records if row["id"] == review.approval_evidence_id]
    if len(matches) != 1:
        return False
    row = matches[0]
    if row["record_type"] != "human.customer_report_approval" or not trusted_record(row):
        return False
    try:
        payload = json.loads(row["payload_json"])
    except (ValueError, TypeError):
        return False
    return (
        isinstance(payload, dict)
        and payload.get("order_id") == order_id
        and payload.get("reviewer_id") == review.reviewer_id
        and payload.get("report_sha256") == review.report_sha256
        and payload.get("decision") == "REPORT_APPROVED"
    )

def approve_paid_order_report(*, tenant_id: str, reviewer_id: str, order_id: str,
                              tip_hash: str, report_sha256: str, reason: str) -> dict:
    if not all(isinstance(value, str) and value.strip() for value in (
        tenant_id, reviewer_id, order_id, tip_hash, report_sha256, reason
    )):
        raise PaidReportReviewRejected(400, "order, reviewer, report digest, evidence tip and reason are required")
    if re.fullmatch(r"[0-9a-f]{64}", tip_hash) is None or re.fullmatch(r"[0-9a-f]{64}", report_sha256) is None:
        raise PaidReportReviewRejected(400, "report_sha256 and tip_hash must be lowercase SHA-256 digests")
    if len(reason.strip()) > 1000:
        raise PaidReportReviewRejected(400, "review reason exceeds 1000 characters")

    with SessionLocal() as db:
        begin_write_transaction(db, tenant_id=tenant_id)
        order = db.scalar(select(CheckoutOrder).where(
            CheckoutOrder.id == order_id,
            CheckoutOrder.tenant_id == tenant_id,
        ).with_for_update())
        if order is None:
            raise PaidReportReviewRejected(404, "paid order not found")
        control = db.scalar(select(CheckoutOrderControl).where(
            CheckoutOrderControl.order_id == order_id,
            CheckoutOrderControl.tenant_id == tenant_id,
        ).with_for_update())
        reviewer = db.get(ApiKey, reviewer_id)
        if reviewer is None or reviewer.tenant_id != tenant_id or reviewer.role != "report_reviewer":
            raise PaidReportReviewRejected(403, "a tenant-scoped report_reviewer API identity is required")
        job = db.scalar(select(CheckoutExecutionJob).where(
            CheckoutExecutionJob.order_id == order_id,
            CheckoutExecutionJob.tenant_id == tenant_id,
        ).with_for_update())
        if control is None or job is None:
            raise PaidReportReviewRejected(409, "execution or Human Gate record is missing")
        if reviewer_id in {control.requester_id, control.approver_id}:
            raise PaidReportReviewRejected(403, "report reviewer must be distinct from requester and execution approver")
        if order.status != "EXECUTED_REVIEW_REQUIRED" or job.status != "EXECUTED_REVIEW_REQUIRED":
            raise PaidReportReviewRejected(409, "order is not awaiting customer report review")
        existing = db.scalar(select(CheckoutReportReview).where(
            CheckoutReportReview.order_id == order_id,
            CheckoutReportReview.tenant_id == tenant_id,
        ).with_for_update())
        if existing is not None:
            raise PaidReportReviewRejected(409, "report has already been reviewed")
        try:
            job_result = json.loads(job.result_json or "")
        except (ValueError, TypeError):
            raise PaidReportReviewRejected(409, "stored execution result is unavailable") from None
        if not isinstance(job_result, dict) or job_result.get("status") != "EXECUTED_REVIEW_REQUIRED":
            raise PaidReportReviewRejected(409, "stored execution result is not reviewable")
        for key in ("nina_status", "igor_status", "provenance_status", "replay_status"):
            if job_result.get(key) != "VERIFIED":
                raise PaidReportReviewRejected(409, f"report failed independent execution check: {key}")
        report = job_result.get("report")
        decision_report = report.get("decision_report") if isinstance(report, dict) else None
        stored_digest = job_result.get("decision_report_sha256")
        nested_digest = decision_report.get("report_sha256") if isinstance(decision_report, dict) else None
        computed_digest = _verified_report_digest(report)
        if (
            not isinstance(report, dict)
            or not isinstance(stored_digest, str)
            or stored_digest != report_sha256
            or nested_digest != report_sha256
            or computed_digest != report_sha256
        ):
            raise PaidReportReviewRejected(409, "report digest does not match the independently recomputed report")

        rows, records = _tenant_records(db, tenant_id)
        chain_ok, chain_reason = verify_chain(records)
        if not chain_ok:
            raise PaidReportReviewRejected(409, f"tenant evidence chain is invalid: {chain_reason}")
        if not records or records[-1]["record_hash"] != tip_hash:
            raise PaidReportReviewRejected(409, "evidence tip is stale or unknown")
        completion = []
        for record in records:
            if record["record_type"] != "revenue.execution_completed":
                continue
            try:
                payload = json.loads(record["payload_json"])
            except (ValueError, TypeError):
                raise PaidReportReviewRejected(409, "execution completion evidence is invalid") from None
            if isinstance(payload, dict) and payload.get("order_id") == order_id and payload.get("execution_job_id") == job.id:
                completion.append((record, payload))
        if len(completion) != 1:
            raise PaidReportReviewRejected(409, "unique trusted execution-completion evidence is required")
        completion_record, completion_payload = completion[0]
        if (
            not trusted_record(completion_record)
            or completion_payload.get("decision_report_sha256") != report_sha256
            or completion_payload.get("status") != "EXECUTED_REVIEW_REQUIRED"
        ):
            raise PaidReportReviewRejected(409, "execution evidence does not bind the submitted report digest")

        reviewed_at = int(time.time())
        review = CheckoutReportReview(
            id=str(uuid.uuid4()), order_id=order_id, tenant_id=tenant_id,
            reviewer_id=reviewer_id, status="APPROVED",
            report_sha256=report_sha256, reviewed_tip_hash=tip_hash,
            reason=reason.strip(), reviewed_at=reviewed_at,
        )
        db.add(review)
        approval_record = _append_locked(db, tenant_id, "human.customer_report_approval", {
            "order_id": order_id,
            "tenant_id": tenant_id,
            "execution_job_id": job.id,
            "requester_id": control.requester_id,
            "execution_approver_id": control.approver_id,
            "reviewer_id": reviewer_id,
            "report_sha256": report_sha256,
            "reviewed_tip_hash": tip_hash,
            "execution_completed_evidence_id": completion_record["id"],
            "execution_completed_evidence_hash": completion_record["record_hash"],
            "reason": reason.strip(),
            "decision": "REPORT_APPROVED",
            "reviewed_at": reviewed_at,
        })
        review.approval_evidence_id = approval_record["id"]
        order.status = "REPORT_APPROVED"
        try:
            payment = json.loads(order.payment_result_json or "{}")
        except (ValueError, TypeError):
            payment = {}
        if isinstance(payment, dict):
            payment.update({
                "status": "REPORT_APPROVED",
                "report_review_status": "APPROVED",
                "report_sha256": report_sha256,
                "customer_delivery": "NOT_DELIVERED",
            })
            order.payment_result_json = json.dumps(payment, sort_keys=True)
        db.commit()

    return {
        "status": "REPORT_APPROVED",
        "order_id": order_id,
        "reviewer_id": reviewer_id,
        "report_sha256": report_sha256,
        "review_evidence_id": approval_record["id"],
        "customer_delivery": "NOT_DELIVERED",
    }


def deliver_paid_order_report(*, tenant_id: str, requester_id: str, order_id: str) -> dict:
    with SessionLocal() as db:
        order = db.scalar(select(CheckoutOrder).where(
            CheckoutOrder.id == order_id, CheckoutOrder.tenant_id == tenant_id,
        ))
        if order is None:
            raise PaidReportReviewRejected(404, "paid order not found")
        control = db.scalar(select(CheckoutOrderControl).where(
            CheckoutOrderControl.order_id == order_id,
            CheckoutOrderControl.tenant_id == tenant_id,
        ))
        if control is None or requester_id != control.requester_id:
            raise PaidReportReviewRejected(403, "only the original order requester may retrieve this report")
        review = db.scalar(select(CheckoutReportReview).where(
            CheckoutReportReview.order_id == order_id,
            CheckoutReportReview.tenant_id == tenant_id,
        ))
        if review is None or review.status != "APPROVED":
            raise PaidReportReviewRejected(409, "customer report has not been independently approved")

        begin_write_transaction(db, tenant_id=tenant_id)
        order = db.scalar(select(CheckoutOrder).where(
            CheckoutOrder.id == order_id, CheckoutOrder.tenant_id == tenant_id,
        ).with_for_update())
        review = db.scalar(select(CheckoutReportReview).where(
            CheckoutReportReview.order_id == order_id,
            CheckoutReportReview.tenant_id == tenant_id,
        ).with_for_update())
        job = db.scalar(select(CheckoutExecutionJob).where(
            CheckoutExecutionJob.order_id == order_id,
            CheckoutExecutionJob.tenant_id == tenant_id,
        ).with_for_update())
        if review is None or review.status != "APPROVED" or job is None:
            raise PaidReportReviewRejected(409, "approved report or execution record is unavailable")
        if order is None or order.tenant_id != tenant_id or control.requester_id != requester_id:
            raise PaidReportReviewRejected(403, "report is not bound to the original requester")
        try:
            job_result = json.loads(job.result_json or "")
        except (ValueError, TypeError):
            raise PaidReportReviewRejected(409, "stored report is unavailable") from None
        report = job_result.get("report") if isinstance(job_result, dict) else None
        if (
            not isinstance(report, dict)
            or job_result.get("decision_report_sha256") != review.report_sha256
            or _verified_report_digest(report) != review.report_sha256
        ):
            raise PaidReportReviewRejected(409, "approved report no longer matches the independently recomputed execution result")

        rows, records = _tenant_records(db, tenant_id)
        chain_ok, chain_reason = verify_chain(records)
        if not chain_ok:
            raise PaidReportReviewRejected(409, f"tenant evidence chain is invalid: {chain_reason}")
        if not _trusted_review_evidence(records, review, order_id):
            raise PaidReportReviewRejected(409, "trusted report approval evidence is missing or mismatched")

        if review.delivery_evidence_id:
            delivery_rows = [row for row in records if row["id"] == review.delivery_evidence_id]
            if len(delivery_rows) != 1 or delivery_rows[0]["record_type"] != "revenue.report_delivered" or not trusted_record(delivery_rows[0]):
                raise PaidReportReviewRejected(409, "trusted report delivery evidence is missing or mismatched")
            evidence_id = review.delivery_evidence_id
        else:
            delivered_at = int(time.time())
            delivery = _append_locked(db, tenant_id, "revenue.report_delivered", {
                "order_id": order_id,
                "tenant_id": tenant_id,
                "execution_job_id": job.id,
                "requester_id": requester_id,
                "reviewer_id": review.reviewer_id,
                "report_sha256": review.report_sha256,
                "review_evidence_id": review.approval_evidence_id,
                "delivery_channel": "authenticated_api",
                "delivered_at": delivered_at,
            })
            review.delivery_evidence_id = delivery["id"]
            review.delivered_at = delivered_at
            order.status = "REPORT_DELIVERED"
            try:
                payment = json.loads(order.payment_result_json or "{}")
            except (ValueError, TypeError):
                payment = {}
            if isinstance(payment, dict):
                payment.update({"status": "REPORT_DELIVERED", "customer_delivery": "DELIVERED"})
                order.payment_result_json = json.dumps(payment, sort_keys=True)
            evidence_id = delivery["id"]
            db.commit()
        return {
            "status": "REPORT_DELIVERED",
            "order_id": order_id,
            "report_sha256": review.report_sha256,
            "delivery_evidence_id": evidence_id,
            "report": report,
        }
