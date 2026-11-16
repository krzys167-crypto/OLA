"""Order-bound Human Gate for paid, sandbox-only OLA execution requests."""
import hashlib
import json
import re
import time
import uuid

from sqlalchemy import select

from .database import SessionLocal, begin_write_transaction
from .hashchain import (
    GENESIS_HASH,
    compute_record_hash_v2,
    sealed_payload_json,
    verify_chain,
    trusted_record,
)
from .models import ApiKey, CheckoutOrder, CheckoutOrderControl, CheckoutExecutionJob, EvidenceRecord
from .runtime_provenance import runtime_source_commit


class PaidOrderApprovalRejected(ValueError):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


def _records_for_tenant(db, tenant_id: str):
    rows = db.scalars(
        select(EvidenceRecord)
        .where(EvidenceRecord.tenant_id == tenant_id)
        .order_by(EvidenceRecord.seq.asc())
    ).all()
    records = [{
        "id": row.id,
        "tenant_id": row.tenant_id,
        "seq": row.seq,
        "prev_hash": row.prev_hash,
        "record_hash": row.record_hash,
        "record_type": row.record_type,
        "payload_json": row.payload_json,
    } for row in rows]
    return rows, records


def _validate_paid_order(db, *, tenant_id, order_id, approver_id, tip_hash):
    order = db.scalar(
        select(CheckoutOrder)
        .where(CheckoutOrder.id == order_id)
        .with_for_update()
    )
    if order is None or order.tenant_id != tenant_id:
        raise PaidOrderApprovalRejected(404, "paid order not found")

    approver = db.get(ApiKey, approver_id)
    if approver is None or approver.tenant_id != tenant_id or approver.role != "execution_approver":
        raise PaidOrderApprovalRejected(403, "a tenant-scoped execution_approver API identity is required")

    control = db.scalar(select(CheckoutOrderControl).where(
        CheckoutOrderControl.order_id == order_id,
        CheckoutOrderControl.tenant_id == tenant_id,
    ).with_for_update())
    if control is None or not control.requester_id:
        raise PaidOrderApprovalRejected(409, "order requester identity is not proven; manual reconciliation required")
    if control.requester_id == approver_id:
        raise PaidOrderApprovalRejected(403, "checkout requester cannot approve their own order")
    if order.status != "PAID_PENDING_REVIEW" or control.status != "PAID_PENDING_REVIEW":
        raise PaidOrderApprovalRejected(409, "order is not awaiting Human Gate approval")

    try:
        payment = json.loads(order.payment_result_json or "")
    except (ValueError, TypeError):
        raise PaidOrderApprovalRejected(409, "durable payment proof is missing or invalid") from None
    if (
        not isinstance(payment, dict)
        or payment.get("status") != "PAID_PENDING_REVIEW"
        or payment.get("payment") != "CONFIRMED"
        or payment.get("execution_authorized") is not False
        or payment.get("checkout_session_id") != order.stripe_session_id
        or payment.get("order_id") != order_id
        or not isinstance(payment.get("event_id"), str)
        or not payment.get("event_id")
        or order.payment_event_id != payment.get("event_id")
    ):
        raise PaidOrderApprovalRejected(409, "durable payment proof does not match this order")

    evidence_id = payment.get("payment_evidence_id")
    if not isinstance(evidence_id, str) or not evidence_id:
        raise PaidOrderApprovalRejected(409, "payment evidence identifier is missing")
    rows, records = _records_for_tenant(db, tenant_id)
    chain_ok, chain_reason = verify_chain(records)
    if not chain_ok:
        raise PaidOrderApprovalRejected(409, f"tenant evidence chain is invalid: {chain_reason}")
    if not records or records[-1]["record_hash"] != tip_hash:
        raise PaidOrderApprovalRejected(409, "evidence tip is stale or unknown")

    checkout_matches = []
    for record in records:
        if record["record_type"] != "stripe.checkout_created":
            continue
        try:
            checkout_payload = json.loads(record["payload_json"])
        except (ValueError, TypeError):
            raise PaidOrderApprovalRejected(409, "checkout provenance record is invalid") from None
        if isinstance(checkout_payload, dict) and checkout_payload.get("ola_order_id") == order_id:
            checkout_matches.append((record, checkout_payload))
    if len(checkout_matches) != 1:
        raise PaidOrderApprovalRejected(409, "unique trusted checkout provenance is required")
    checkout_proof, checkout_payload = checkout_matches[0]
    if (
        not trusted_record(checkout_proof)
        or checkout_payload.get("tenant_id") != tenant_id
        or checkout_payload.get("requester_id") != control.requester_id
        or checkout_payload.get("checkout_session_id") != order.stripe_session_id
        or checkout_payload.get("request_hash") != order.request_hash
    ):
        raise PaidOrderApprovalRejected(409, "trusted checkout provenance does not match this order")

    matches = [record for record in records if record["id"] == evidence_id]
    if len(matches) != 1:
        raise PaidOrderApprovalRejected(409, "unique payment evidence record is required")
    proof = matches[0]
    if checkout_proof["seq"] >= proof["seq"]:
        raise PaidOrderApprovalRejected(409, "checkout provenance must precede payment confirmation")
    if proof["record_type"] != "stripe.payment_confirmed" or not trusted_record(proof):
        raise PaidOrderApprovalRejected(409, "payment evidence is not trusted server evidence")
    try:
        proof_payload = json.loads(proof["payload_json"])
    except (ValueError, TypeError):
        raise PaidOrderApprovalRejected(409, "payment evidence payload is invalid") from None
    private_task = order.task if isinstance(order.task, str) else None
    private_task_hash = (
        hashlib.sha256(private_task.encode("utf-8")).hexdigest()
        if private_task and private_task.strip() else None
    )
    if (
        not isinstance(proof_payload, dict)
        or proof_payload.get("ola_order_id") != order_id
        or proof_payload.get("checkout_session_id") != order.stripe_session_id
        or proof_payload.get("stripe_event_id") != payment.get("event_id")
        or private_task_hash != order.request_hash
        or control.payment_evidence_id != evidence_id
    ):
        raise PaidOrderApprovalRejected(409, "payment evidence is bound to a different order or session")

    existing_approval = []
    for record in records:
        if record["record_type"] != "human.revenue_execution_approval":
            continue
        payload = json.loads(record["payload_json"])
        if payload.get("order_id") == order_id:
            existing_approval.append(record)
    if existing_approval or control.status == "APPROVED_FOR_EXECUTION":
        raise PaidOrderApprovalRejected(409, "order has already been approved")

    return order, control, payment, checkout_proof, proof, private_task, rows, records


def approve_paid_order(*, tenant_id: str, approver_id: str, order_id: str,
                       tip_hash: str, reason: str) -> dict:
    if not all(isinstance(value, str) and value.strip() for value in (
        tenant_id, approver_id, order_id, tip_hash, reason
    )):
        raise PaidOrderApprovalRejected(400, "order, evidence tip and nonempty reason are required")
    if re.fullmatch(r"[0-9a-f]{64}", tip_hash) is None:
        raise PaidOrderApprovalRejected(400, "tip_hash must be a lowercase SHA-256 digest")
    if len(reason.strip()) > 1000:
        raise PaidOrderApprovalRejected(400, "approval reason exceeds 1000 characters")

    source_commit = runtime_source_commit()
    if not isinstance(source_commit, str) or re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
        raise PaidOrderApprovalRejected(409, "runtime source commit is unknown; approval is blocked")

    # Read-only preflight, followed by a locked revalidation before writing.
    with SessionLocal() as db:
        _validate_paid_order(
            db, tenant_id=tenant_id, order_id=order_id,
            approver_id=approver_id, tip_hash=tip_hash,
        )

    with SessionLocal() as db:
        begin_write_transaction(db, tenant_id=tenant_id)
        order, control, payment, checkout_proof, proof, proof_task, rows, records = _validate_paid_order(
            db, tenant_id=tenant_id, order_id=order_id,
            approver_id=approver_id, tip_hash=tip_hash,
        )
        latest = rows[-1] if rows else None
        previous_hash = latest.record_hash if latest is not None else GENESIS_HASH
        next_seq = latest.seq + 1 if latest is not None else 0
        approved_at = int(time.time())
        approval_payload = {
            "event": "human.revenue_execution_approval",
            "order_id": order_id,
            "tenant_id": tenant_id,
            "requester_id": control.requester_id,
            "approver_id": approver_id,
            "approver_role": "execution_approver",
            "reason": reason.strip(),
            "checkout_session_id": order.stripe_session_id,
            "stripe_event_id": payment["event_id"],
            "checkout_evidence_id": checkout_proof["id"],
            "checkout_evidence_hash": checkout_proof["record_hash"],
            "payment_evidence_id": proof["id"],
            "payment_evidence_hash": proof["record_hash"],
            "request_hash": order.request_hash,
            "approved_tip_hash": tip_hash,
            "source_commit": source_commit,
            "approved_at": approved_at,
            "decision": "APPROVED_FOR_EXECUTION",
            "execution_authorized": True,
            "deployment_authorized": False,
            "production_authorized": False,
        }
        raw = sealed_payload_json("human.revenue_execution_approval", approval_payload)
        record_hash = compute_record_hash_v2(
            tenant_id, next_seq, previous_hash,
            "human.revenue_execution_approval", "ola_runtime", raw,
        )
        record_id = str(uuid.uuid4())
        db.add(EvidenceRecord(
            id=record_id,
            tenant_id=tenant_id,
            seq=next_seq,
            record_type="human.revenue_execution_approval",
            payload_json=raw,
            prev_hash=previous_hash,
            record_hash=record_hash,
        ))
        control.status = "APPROVED_FOR_EXECUTION"
        control.approver_id = approver_id
        control.approval_reason = reason.strip()
        control.approved_tip_hash = tip_hash
        control.approval_record_hash = record_hash
        control.approved_at = approved_at
        execution_job_id = str(uuid.uuid4())
        db.add(CheckoutExecutionJob(
            id=execution_job_id,
            tenant_id=tenant_id,
            order_id=order_id,
            approval_record_hash=record_hash,
            task=proof_task,
            status="QUEUED",
            attempt_count=0,
        ))
        db.commit()

    return {
        "status": "APPROVED_FOR_EXECUTION",
        "order_id": order_id,
        "approver_id": approver_id,
        "approved_tip_hash": tip_hash,
        "approval_record_hash": record_hash,
        "approval_record_id": record_id,
        "execution_job_id": execution_job_id,
        "checkout_evidence_id": checkout_proof["id"],
        "execution": "QUEUED",
        "execution_job_status": "QUEUED",
        "next_gate": "EXECUTION_DISPATCH",
        "deployment_authorized": False,
        "production_authorized": False,
    }
