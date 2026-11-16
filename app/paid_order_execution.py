"""At-most-once paid-order execution with a durable SQLite outbox."""
import hashlib
import hmac
import json
import os
import time
import uuid

from sqlalchemy import select

from .database import SessionLocal, begin_write_transaction, lock_tenant_evidence_chain
from .hashchain import GENESIS_HASH, compute_record_hash_v2, sealed_payload_json, trusted_record, verify_chain
from .models import ApiKey, CheckoutExecutionJob, CheckoutOrder, CheckoutOrderControl, EvidenceRecord
from .runtime_provenance import runtime_source_commit


class PaidOrderExecutionRejected(ValueError):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


def verify_worker_token(token: str | None) -> None:
    configured = os.getenv("OLA_EXECUTION_WORKER_TOKEN", "")
    if len(configured) < 32:
        raise PaidOrderExecutionRejected(503, "execution worker authentication is not configured")
    if not isinstance(token, str) or not token:
        raise PaidOrderExecutionRejected(401, "worker authentication required")
    if not hmac.compare_digest(token, configured):
        raise PaidOrderExecutionRejected(403, "worker authentication failed")


def _append_locked(db, tenant_id: str, record_type: str, payload: dict) -> dict:
    """Append trusted evidence under the caller's tenant-chain transaction lock."""
    rows = db.scalars(
        select(EvidenceRecord).where(EvidenceRecord.tenant_id == tenant_id)
        .order_by(EvidenceRecord.seq.desc()).limit(1)
    ).all()
    latest = rows[0] if rows else None
    seq = latest.seq + 1 if latest else 0
    previous_hash = latest.record_hash if latest else GENESIS_HASH
    raw = sealed_payload_json(record_type, payload)
    digest = compute_record_hash_v2(
        tenant_id, seq, previous_hash, record_type, "ola_runtime", raw,
    )
    row = EvidenceRecord(
        id=str(uuid.uuid4()), tenant_id=tenant_id, seq=seq,
        record_type=record_type, payload_json=raw,
        prev_hash=previous_hash, record_hash=digest,
    )
    db.add(row)
    db.flush()
    return {"id": row.id, "record_hash": digest, "seq": seq}


def _execution_context(db, job: CheckoutExecutionJob):
    order = db.scalar(
        select(CheckoutOrder)
        .where(CheckoutOrder.id == job.order_id)
        .with_for_update()
    )
    control = db.scalar(select(CheckoutOrderControl).where(
        CheckoutOrderControl.order_id == job.order_id,
        CheckoutOrderControl.tenant_id == job.tenant_id,
    ).with_for_update())
    if (order is None or order.tenant_id != job.tenant_id or control is None
            or control.status != "APPROVED_FOR_EXECUTION"
            or not control.approval_record_hash
            or control.approval_record_hash != job.approval_record_hash
            or order.status != "PAID_PENDING_REVIEW"):
        raise PaidOrderExecutionRejected(409, "approved payment order is no longer eligible for execution")

    evidence_rows = db.scalars(
        select(EvidenceRecord).where(EvidenceRecord.tenant_id == job.tenant_id)
        .order_by(EvidenceRecord.seq.asc())
    ).all()
    evidence = [{
        "id": row.id, "tenant_id": row.tenant_id, "seq": row.seq,
        "record_type": row.record_type, "prev_hash": row.prev_hash,
        "record_hash": row.record_hash, "payload_json": row.payload_json,
    } for row in evidence_rows]
    valid, reason = verify_chain(evidence)
    if not valid:
        raise PaidOrderExecutionRejected(409, f"tenant evidence chain is invalid: {reason}")
    approvals = [row for row in evidence if row["record_hash"] == job.approval_record_hash]
    if len(approvals) != 1 or approvals[0]["record_type"] != "human.revenue_execution_approval" or not trusted_record(approvals[0]):
        raise PaidOrderExecutionRejected(409, "trusted Human Gate approval evidence is missing")
    try:
        approval_payload = json.loads(approvals[0]["payload_json"])
        payment_result = json.loads(order.payment_result_json or "")
    except (ValueError, TypeError):
        raise PaidOrderExecutionRejected(409, "Human Gate or payment evidence is invalid") from None
    approver = db.get(ApiKey, control.approver_id) if control.approver_id else None
    current_source = runtime_source_commit()
    if (not isinstance(approval_payload, dict)
            or approver is None or approver.tenant_id != job.tenant_id
            or approver.role != "execution_approver"
            or approval_payload.get("approver_role") != "execution_approver"
            or not isinstance(current_source, str) or len(current_source) != 40
            or approval_payload.get("source_commit") != current_source
            or approval_payload.get("order_id") != job.order_id
            or approval_payload.get("tenant_id") != job.tenant_id
            or approval_payload.get("requester_id") != control.requester_id
            or approval_payload.get("approver_id") != control.approver_id
            or approval_payload.get("approver_id") == approval_payload.get("requester_id")
            or approval_payload.get("request_hash") != order.request_hash
            or approval_payload.get("decision") != "APPROVED_FOR_EXECUTION"
            or approval_payload.get("execution_authorized") is not True
            or approval_payload.get("production_authorized") is not False
            or approval_payload.get("deployment_authorized") is not False
            or not isinstance(payment_result, dict)
            or payment_result.get("status") != "PAID_PENDING_REVIEW"
            or payment_result.get("payment") != "CONFIRMED"
            or payment_result.get("order_id") != order.id
            or payment_result.get("checkout_session_id") != order.stripe_session_id
            or payment_result.get("payment_evidence_id") != control.payment_evidence_id
            or payment_result.get("event_id") != approval_payload.get("stripe_event_id")):
        raise PaidOrderExecutionRejected(409, "Human Gate approval is not bound to this paid order")

    checkout_id = approval_payload.get("checkout_evidence_id")
    payment_id = approval_payload.get("payment_evidence_id")
    checkout_rows = [row for row in evidence if row["id"] == checkout_id]
    payment_rows = [row for row in evidence if row["id"] == payment_id]
    if (len(checkout_rows) != 1 or len(payment_rows) != 1
            or checkout_rows[0]["record_type"] != "stripe.checkout_created"
            or payment_rows[0]["record_type"] != "stripe.payment_confirmed"
            or not trusted_record(checkout_rows[0]) or not trusted_record(payment_rows[0])
            or checkout_rows[0]["record_hash"] != approval_payload.get("checkout_evidence_hash")
            or payment_rows[0]["record_hash"] != approval_payload.get("payment_evidence_hash")):
        raise PaidOrderExecutionRejected(409, "trusted checkout and payment evidence is missing or mismatched")
    try:
        checkout_payload = json.loads(checkout_rows[0]["payload_json"])
        payment_payload = json.loads(payment_rows[0]["payload_json"])
    except (ValueError, TypeError):
        raise PaidOrderExecutionRejected(409, "trusted checkout or payment evidence is invalid") from None
    if (checkout_payload.get("ola_order_id") != order.id
            or checkout_payload.get("tenant_id") != job.tenant_id
            or checkout_payload.get("requester_id") != control.requester_id
            or checkout_payload.get("checkout_session_id") != order.stripe_session_id
            or checkout_payload.get("request_hash") != order.request_hash
            or payment_payload.get("ola_order_id") != order.id
            or payment_payload.get("checkout_session_id") != order.stripe_session_id
            or payment_payload.get("stripe_event_id") != approval_payload.get("stripe_event_id")
            or payment_payload.get("execution_authorized") is not False
            or payment_payload.get("request_hash") != order.request_hash):
        raise PaidOrderExecutionRejected(409, "checkout or payment evidence does not match the approved order")
    if hashlib.sha256(job.task.encode("utf-8")).hexdigest() != order.request_hash:
        raise PaidOrderExecutionRejected(409, "execution task does not match the paid order scope")
    return order, control, evidence


def execute_paid_order_job(job_id: str, *, runner=None, now: int | None = None,
                            stale_after_seconds: int = 900) -> dict:
    """Claim and run one approved order once. Stale RUNNING jobs are never auto-replayed."""
    from .nina_execution import run_nina_task

    run_now = int(time.time()) if now is None else int(now)
    execute = runner or run_nina_task
    claim_token = str(uuid.uuid4())
    with SessionLocal() as db:
        if db.bind.dialect.name == "sqlite":
            begin_write_transaction(db)
        elif db.bind.dialect.name == "postgresql":
            # Lock the job row first to serialize competing workers, then the
            # tenant evidence chain before validation and evidence append.
            db.connection()
        else:
            raise PaidOrderExecutionRejected(503, "no atomic execution-outbox policy for this database")
        job = db.scalar(
            select(CheckoutExecutionJob)
            .where(CheckoutExecutionJob.id == job_id)
            .with_for_update()
        )
        if job is None:
            raise PaidOrderExecutionRejected(404, "execution job not found")
        lock_tenant_evidence_chain(db, job.tenant_id)
        if job.status in {"EXECUTED_REVIEW_REQUIRED", "EXECUTED_BLOCKED"} and job.result_json:
            return json.loads(job.result_json)
        if job.status == "RUNNING":
            if job.started_at is not None and job.started_at <= run_now - stale_after_seconds:
                job.status = "INTERRUPTED"
                job.error_code = "worker_interrupted_manual_reconciliation_required"
                job.finished_at = run_now
                _append_locked(db, job.tenant_id, "revenue.execution_interrupted", {
                    "order_id": job.order_id, "execution_job_id": job.id,
                    "attempt_count": job.attempt_count,
                    "reason": "worker lease exceeded; automatic replay prohibited",
                })
                db.commit()
                raise PaidOrderExecutionRejected(409, "execution was interrupted; manual reconciliation is required")
            raise PaidOrderExecutionRejected(409, "execution job is already running")
        if job.status != "QUEUED" or job.attempt_count != 0:
            raise PaidOrderExecutionRejected(409, "execution job is terminal or already attempted")
        try:
            order, control, _ = _execution_context(db, job)
        except PaidOrderExecutionRejected as exc:
            if exc.code == 409:
                job.status = "BLOCKED"
                job.error_code = "preflight_rejected"
                job.finished_at = run_now
                order = db.scalar(
            select(CheckoutOrder)
            .where(CheckoutOrder.id == job.order_id)
            .with_for_update()
        )
                if order is not None:
                    order.status = "BLOCKED"
                    try:
                        payment_state = json.loads(order.payment_result_json or "{}")
                    except (ValueError, TypeError):
                        payment_state = {}
                    if isinstance(payment_state, dict):
                        payment_state["status"] = "BLOCKED"
                        payment_state["execution"] = "BLOCKED"
                        order.payment_result_json = json.dumps(payment_state, sort_keys=True)
                _append_locked(db, job.tenant_id, "revenue.execution_blocked", {
                    "order_id": job.order_id,
                    "execution_job_id": job.id,
                    "approval_record_hash": job.approval_record_hash,
                    "reason_code": "preflight_rejected",
                })
                db.commit()
            raise
        job.status = "RUNNING"
        job.attempt_count = 1
        job.started_at = run_now
        job.error_code = None
        job.claim_token = claim_token
        start_evidence = _append_locked(db, job.tenant_id, "revenue.execution_started", {
            "order_id": job.order_id, "execution_job_id": job.id,
            "approval_record_hash": job.approval_record_hash,
            "request_hash": order.request_hash,
            "requester_id": control.requester_id,
            "approver_id": control.approver_id,
            "attempt": 1,
            "source_commit": runtime_source_commit(),
        })
        db.commit()
        tenant_id = job.tenant_id
        requester_id = control.requester_id
        task = job.task
        order_id = job.order_id

    execution_context = {"order_id": order_id, "execution_job_id": job_id}
    try:
        result = execute(
            tenant_id, requester_id, task, ["safe_expression"],
            execution_context=execution_context,
        )
        if not isinstance(result, dict):
            raise RuntimeError("NINA executor returned a non-object result")
        # Do not report a verified deliverable unless every independent check passed.
        checks_ok = (
            result.get("nina", {}).get("status") == "VERIFIED"
            and result.get("igor", {}).get("status") == "VERIFIED"
            and result.get("provenance", {}).get("status") == "VERIFIED"
            and result.get("replay_verification", {}).get("status") == "VERIFIED"
        )
        final_status = "EXECUTED_REVIEW_REQUIRED" if checks_ok else "EXECUTED_BLOCKED"
        report = result.get("decision_report") if isinstance(result.get("decision_report"), dict) else {}
        provenance = result.get("provenance") if isinstance(result.get("provenance"), dict) else {}
        invocation_type = provenance.get("invocation_type")
        llm_invocations = provenance.get("llm_invocations", 0)
        response_ids = provenance.get("response_ids", [])
        real_llm_invoked = (
            invocation_type == "real_llm"
            and isinstance(llm_invocations, int) and llm_invocations > 0
            and isinstance(response_ids, list) and len(response_ids) == llm_invocations
            and all(isinstance(value, str) and value for value in response_ids)
        )
        public_result = {
            "status": final_status,
            "order_id": order_id,
            "execution_job_id": job_id,
            "execution": "COMPLETED",
            "run_id": result.get("run_id"),
            "nina_status": result.get("nina", {}).get("status"),
            "igor_status": result.get("igor", {}).get("status"),
            "provenance_status": provenance.get("status"),
            "invocation_type": invocation_type,
            "real_llm_invoked": real_llm_invoked,
            "llm_invocations": llm_invocations,
            "replay_status": result.get("replay_verification", {}).get("status"),
            "decision_report_sha256": report.get("report_sha256"),
            "report": result,
            "customer_delivery": "NOT_DELIVERED",
            "next_gate": "CUSTOMER_REPORT_REVIEW" if checks_ok else "MANUAL_REMEDIATION",
        }
        error_code = None
    except Exception as exc:
        final_status = "FAILED"
        error_code = type(exc).__name__[:100]
        public_result = {
            "status": final_status, "order_id": order_id,
            "execution_job_id": job_id, "execution": "FAILED",
            "reason": "NINA execution failed; automatic replay is prohibited",
            "customer_delivery": "NOT_DELIVERED",
        }
        result = None

    with SessionLocal() as db:
        if db.bind.dialect.name == "sqlite":
            begin_write_transaction(db)
        elif db.bind.dialect.name == "postgresql":
            db.connection()
        else:
            raise PaidOrderExecutionRejected(503, "no atomic execution result policy for this database")
        job = db.scalar(
            select(CheckoutExecutionJob)
            .where(CheckoutExecutionJob.id == job_id)
            .with_for_update()
        )
        if job is None:
            raise PaidOrderExecutionRejected(409, "execution claim was lost; manual reconciliation is required")
        lock_tenant_evidence_chain(db, job.tenant_id)
        if job.status != "RUNNING" or job.claim_token != claim_token:
            raise PaidOrderExecutionRejected(409, "execution claim was lost; manual reconciliation is required")
        job.status = final_status
        job.finished_at = int(time.time())
        job.run_id = public_result.get("run_id")
        job.result_json = json.dumps(public_result, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        job.error_code = error_code
        evidence_type = "revenue.execution_completed" if result is not None else "revenue.execution_failed"
        _append_locked(db, job.tenant_id, evidence_type, {
            "order_id": order_id, "execution_job_id": job_id,
            "approval_record_hash": job.approval_record_hash,
            "started_evidence_id": start_evidence["id"],
            "run_id": public_result.get("run_id"),
            "status": final_status,
            "decision_report_sha256": public_result.get("decision_report_sha256"),
            "error_code": error_code,
        })
        order = db.get(CheckoutOrder, job.order_id)
        if order is not None:
            order.status = final_status
            try:
                payment = json.loads(order.payment_result_json or "{}")
            except (ValueError, TypeError):
                payment = {}
            if isinstance(payment, dict):
                payment.update({
                    "status": final_status, "execution_job_id": job_id,
                    "execution": "COMPLETED" if result is not None else "FAILED",
                    "ola_run_id": public_result.get("run_id"),
                })
                order.payment_result_json = json.dumps(payment, sort_keys=True)
        db.commit()
    return public_result
