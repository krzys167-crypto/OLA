import hashlib
import json
import os
import re
import uuid
import time
from pathlib import Path
from urllib.parse import urlsplit
from fastapi import FastAPI, Header, HTTPException, Request
from starlette.responses import FileResponse, JSONResponse
from sqlalchemy import select, func
from sqlalchemy.exc import IntegrityError
from .runtime_provenance import runtime_source_commit
from .database import Base, engine, SessionLocal, append_evidence_atomic, prepare_runtime_schema, verify_postgres_schema
from .models import Tenant, ApiKey, EvidenceRecord, CheckoutOrder, CheckoutOrderControl, CheckoutExecutionJob
from .api_key_hashing import api_key_fingerprint
from .hashchain import canonical_json
from .igor_evidence_verifier import verify_chain
from .agent_runtime import run_agent_task
from .agent_registry import build_agent_registry
from .execution_safety_gate import ExecutionDecision, ExecutionSafetyGate
from .business_runtime import run_invoice_task
from .nina import NinaOrchestrator, NinaTask, REGISTERED_TOOLS
from .nina_workflow import run_nina_workflow
from .nina_workflow_gate import approve_workflow, approve_nina_candidate, WorkflowApprovalRejected
from .workflow_engine import WorkflowPlanError
from .chat_runtime import chat
from .revenue import create_checkout, retrieve_checkout, payment_verified
from .stripe_webhook import process_checkout_event
from .order_approval import approve_paid_order, PaidOrderApprovalRejected
from .paid_order_execution import execute_paid_order_job, verify_worker_token, PaidOrderExecutionRejected
from .report_review import approve_paid_order_report, deliver_paid_order_report, PaidReportReviewRejected

app = FastAPI(title="OLA Execution Gate")
REGISTERED_AGENT_IDS = frozenset(agent.agent_id for agent in build_agent_registry(391))
AGENT_RUN_GATE = ExecutionSafetyGate(allowed_actions={"run_agent_task"})
prepare_runtime_schema()


def identity_from_key(raw_key):
    if not raw_key:
        raise HTTPException(status_code=401, detail="missing API key")
    try:
        key_hash = api_key_fingerprint(raw_key)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="invalid API key") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail="API key verification unavailable") from exc
    with SessionLocal() as db:
        key = db.scalar(select(ApiKey).where(ApiKey.key_hash == key_hash))
        if key is None:
            raise HTTPException(status_code=401, detail="invalid API key")
        return key.tenant_id, key.id


def tenant_from_key(raw_key):
    tenant_id, _ = identity_from_key(raw_key)
    return tenant_id


def bearer_identity(authorization):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization[7:].strip()
    if not token:
        raise HTTPException(status_code=401, detail="missing bearer token")
    return identity_from_key(token)


def append_record(tenant_id, record_type, payload, *, deduplicate=False):
    return append_evidence_atomic(tenant_id, record_type, payload, deduplicate=deduplicate)


def read_tenant_evidence(tenant_id):
    """Read the complete tenant chain, not only current-run rows."""
    with SessionLocal() as db:
        rows = db.scalars(
            select(EvidenceRecord)
            .where(EvidenceRecord.tenant_id == tenant_id)
            .order_by(EvidenceRecord.seq.asc())
        ).all()
    return [{
        "id": row.id, "tenant_id": row.tenant_id, "seq": row.seq,
        "record_type": row.record_type, "prev_hash": row.prev_hash,
        "record_hash": row.record_hash, "payload_json": row.payload_json,
    } for row in rows]


def run_controlled_audit(tenant_id, task, scenario):
    if scenario != "fault_then_recovery":
        raise HTTPException(status_code=400, detail="unsupported scenario")

    audit_id = str(uuid.uuid4())
    events = [
        ("task.received", {"audit_id": audit_id, "task": task}),
        ("execution.started", {"audit_id": audit_id, "mode": "controlled"}),
        ("fault.detected", {"audit_id": audit_id, "fault": "controlled_fault"}),
        ("recovery.applied", {"audit_id": audit_id, "action": "controlled_recovery"}),
        ("verification.passed", {"audit_id": audit_id, "assertion": "recovered_and_verified"}),
    ]
    evidence_ids = []
    for record_type, payload in events:
        evidence_ids.append(append_record(tenant_id, record_type, payload)["id"])

    with SessionLocal() as db:
        # Verify the complete tenant chain, not a selected suffix whose first
        # sequence may be nonzero after earlier activity.
        rows = db.scalars(
            select(EvidenceRecord)
            .where(EvidenceRecord.tenant_id == tenant_id)
            .order_by(EvidenceRecord.seq.asc())
        ).all()

    chain = [
        {
            "tenant_id": row.tenant_id,
            "seq": row.seq,
            "prev_hash": row.prev_hash,
            "record_hash": row.record_hash,
            "record_type": row.record_type,
            "payload_json": row.payload_json,
        }
        for row in rows
    ]
    chain_ok, reason = verify_chain(chain)
    if not chain_ok:
        return {
            "audit_id": audit_id,
            "status": "FAILED",
            "outcome": "evidence_chain_invalid",
            "evidence_count": len(evidence_ids),
            "evidence_ids": evidence_ids,
            "reason": reason,
        }

    return {
        "audit_id": audit_id,
        "status": "VERIFIED",
        "outcome": "recovered_and_verified",
        "evidence_count": len(evidence_ids),
        "evidence_ids": evidence_ids,
        "reason": reason,
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/readyz")
def core_readiness():
    """Read-only local CORE readiness, never whole-system production acceptance.

    /health is liveness only. /readyz requires source provenance, an active
    authentication pepper, a responsive supported database and append-only
    evidence triggers. No secrets or database paths enter the response.
    """
    failed = []
    source = runtime_source_commit() or ""
    if re.fullmatch(r"[a-fA-F0-9]{40}", source) is None:
        failed.append("source_commit")

    if os.getenv("OLA_REQUIRE_BUILD_INFO", "0") == "1":
        build_path = Path(os.getenv("OLA_BUILD_INFO_PATH", "/app/ola-build-info.json"))
        try:
            file_mode = build_path.stat().st_mode
            parent_mode = build_path.parent.stat().st_mode
            if (file_mode & 0o222) or (parent_mode & 0o222):
                failed.append("build_info_mutable")
        except OSError:
            failed.append("build_info_missing")

    pepper = os.getenv("OLA_API_KEY_PEPPER", "")
    if len(pepper.encode("utf-8")) < 32:
        failed.append("api_key_pepper")

    try:
        with engine.connect() as conn:
            conn.exec_driver_sql("SELECT 1").scalar_one()
        if engine.dialect.name == "sqlite":
            with engine.connect() as conn:
                # A named trigger can be a no-op, so verify stored definitions.
                definitions = dict(conn.exec_driver_sql(
                    "SELECT name, sql FROM sqlite_master "
                    "WHERE type='trigger' AND tbl_name='evidence_records'"
                ).all())
            expected = {
                "evidence_no_update": (
                    "create trigger evidence_no_update before update on evidence_records "
                    "begin select raise(abort, 'evidence_records is append-only'); end"
                ),
                "evidence_no_delete": (
                    "create trigger evidence_no_delete before delete on evidence_records "
                    "begin select raise(abort, 'evidence_records is append-only'); end"
                ),
            }
            if any(
                re.sub(r"\s+", " ", definitions.get(name) or "").strip().lower().rstrip(";")
                != definition
                for name, definition in expected.items()
            ):
                failed.append("evidence_append_only")
        elif engine.dialect.name == "postgresql":
            verify_postgres_schema(engine)
        else:
            failed.append("database_dialect")
    except Exception:
        # Never surface exception details: they may disclose internal paths.
        failed.append("evidence_store")

    return JSONResponse(
        status_code=503 if failed else 200,
        content={
            "core_status": "BLOCKED" if failed else "READY",
            "system_acceptance": "NOT_VERIFIED",
            "source_commit": source if "source_commit" not in failed else None,
            "failed_checks": failed,
            "scope": "local_core_only",
        },
    )


@app.get("/")
def home():
    web_path = Path(__file__).resolve().parent.parent / "web" / "index.html"
    return FileResponse(web_path, media_type="text/html")


@app.post("/chat")
def chat_endpoint(body: dict, x_api_key: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    messages = body.get("messages", [])
    if not isinstance(messages, list) or not messages:
        raise HTTPException(status_code=400, detail="messages list is required")
    clean = []
    for item in messages:
        if not isinstance(item, dict) or item.get("role") not in {"user", "assistant"} or not isinstance(item.get("content"), str):
            raise HTTPException(status_code=400, detail="invalid message")
        clean.append({"role": item["role"], "content": item["content"]})
    return chat(tenant_id, clean)


@app.post("/checkout")
def create_checkout_session(
    body: dict,
    x_api_key: str | None = Header(default=None),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
):
    tenant_id, requester_id = identity_from_key(x_api_key)
    task = body.get("task")
    if not isinstance(task, str) or not task.strip():
        raise HTTPException(status_code=400, detail="task is required")
    task = task.strip()
    if not isinstance(idempotency_key, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", idempotency_key):
        raise HTTPException(status_code=400, detail="a valid Idempotency-Key header is required")

    public_base_url = os.getenv("OLA_PUBLIC_BASE_URL", "").rstrip("/")
    try:
        parsed_base_url = urlsplit(public_base_url)
        parsed_port = parsed_base_url.port
    except ValueError:
        raise HTTPException(status_code=503, detail="a valid HTTPS OLA_PUBLIC_BASE_URL is required") from None
    local_http = parsed_base_url.scheme == "http" and parsed_base_url.hostname in {"localhost", "127.0.0.1", "::1"}
    if (
        not public_base_url
        or parsed_base_url.scheme not in {"https", "http"}
        or not parsed_base_url.netloc
        or parsed_base_url.username
        or parsed_base_url.password
        or parsed_base_url.path not in {"", "/"}
        or parsed_base_url.query
        or parsed_base_url.fragment
        or (parsed_port is not None and not 1 <= parsed_port <= 65535)
        or (parsed_base_url.scheme != "https" and not local_http)
    ):
        raise HTTPException(status_code=503, detail="a valid HTTPS OLA_PUBLIC_BASE_URL is required")
    success_url = public_base_url + "/payment-success"
    cancel_url = public_base_url + "/"

    key_hash = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()
    request_hash = hashlib.sha256(task.encode("utf-8")).hexdigest()
    order_id = None
    reused_order = None
    existing_payment_state = None
    with SessionLocal() as db:
        order = db.scalar(select(CheckoutOrder).where(
            CheckoutOrder.tenant_id == tenant_id,
            CheckoutOrder.idempotency_key_hash == key_hash,
        ))
        if order is None:
            order = CheckoutOrder(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                idempotency_key_hash=key_hash,
                request_hash=request_hash,
                task=task,
                status="CREATING",
            )
            db.add(order)
            try:
                db.flush()
                db.add(CheckoutOrderControl(
                    id=str(uuid.uuid4()),
                    order_id=order.id,
                    tenant_id=tenant_id,
                    requester_id=requester_id,
                    status="CREATING",
                ))
                db.commit()
            except IntegrityError:
                db.rollback()
                order = db.scalar(select(CheckoutOrder).where(
                    CheckoutOrder.tenant_id == tenant_id,
                    CheckoutOrder.idempotency_key_hash == key_hash,
                ))
                if order is None:
                    raise HTTPException(status_code=503, detail="checkout order could not be reserved") from None
        control = db.scalar(select(CheckoutOrderControl).where(
            CheckoutOrderControl.order_id == order.id,
            CheckoutOrderControl.tenant_id == tenant_id,
        ))
        if control is None or not control.requester_id:
            raise HTTPException(
                status_code=409,
                detail="legacy checkout order has no verified requester identity; manual reconciliation required",
            )
        if control.requester_id != requester_id:
            raise HTTPException(status_code=403, detail="checkout order belongs to another API-key identity")
        if order.request_hash != request_hash:
            raise HTTPException(status_code=409, detail="Idempotency-Key was already used for a different task")
        if not order.task:
            # Existing reservations may be backfilled only by the original
            # requester and only when the caller's request matches the stored hash.
            order.task = task
            db.commit()
        if hashlib.sha256(order.task.encode("utf-8")).hexdigest() != order.request_hash:
            raise HTTPException(status_code=409, detail="private checkout task does not match its request hash")
        # Stripe may prune idempotency keys after its retention window. Never
        # blindly retry a stale CREATING reservation and risk a second session.
        if order.status == "CREATING" and int(time.time()) - order.created_at >= 23 * 60 * 60:
            raise HTTPException(
                status_code=409,
                detail="checkout requires manual Stripe reconciliation; safe retry window expired",
            )
        if order.status == "CHECKOUT_CREATED" and order.stripe_session_id and order.checkout_url:
            reused_order = {
                "order_id": order.id,
                "session_id": order.stripe_session_id,
                "checkout_url": order.checkout_url,
                "task": task,
            }
        elif order.status in {
            "PAID_PENDING_REVIEW", "COMPLETED", "EXECUTED_REVIEW_REQUIRED",
            "EXECUTED_BLOCKED", "FAILED", "INTERRUPTED", "BLOCKED",
            "REPORT_APPROVED", "REPORT_DELIVERED",
        }:
            if not order.payment_result_json:
                raise HTTPException(status_code=503, detail="durable payment result is unavailable")
            control = db.scalar(select(CheckoutOrderControl).where(
                CheckoutOrderControl.order_id == order.id,
                CheckoutOrderControl.tenant_id == tenant_id,
            ))
            approved = bool(
                order.status == "PAID_PENDING_REVIEW"
                and control
                and control.status == "APPROVED_FOR_EXECUTION"
            )
            execution_job = db.scalar(select(CheckoutExecutionJob).where(
                CheckoutExecutionJob.order_id == order.id,
                CheckoutExecutionJob.tenant_id == tenant_id,
            ))
            existing_payment_state = {
                "status": "APPROVED_FOR_EXECUTION" if approved else order.status,
                "order_id": order.id,
                "session_id": order.stripe_session_id,
                "payment": "CONFIRMED",
                "execution": (
                    "QUEUED" if approved else
                    "NOT_STARTED" if order.status == "PAID_PENDING_REVIEW" else
                    execution_job.status if execution_job else "UNKNOWN"
                ),
                "next_gate": (
                    "EXECUTION_DISPATCH" if approved else
                    "HUMAN_REVIEW" if order.status == "PAID_PENDING_REVIEW" else
                    "CUSTOMER_REPORT_REVIEW" if order.status == "EXECUTED_REVIEW_REQUIRED" else
                    "CUSTOMER_DELIVERY" if order.status == "REPORT_APPROVED" else
                    "NONE" if order.status == "REPORT_DELIVERED" else
                    "MANUAL_RECONCILIATION" if order.status in {"EXECUTED_BLOCKED", "FAILED", "INTERRUPTED", "BLOCKED"} else "NONE"
                ),
            }
            if approved:
                existing_payment_state["approval_record_hash"] = control.approval_record_hash
            if execution_job is not None:
                existing_payment_state["execution_job_id"] = execution_job.id
                existing_payment_state["execution_job_status"] = execution_job.status
                if execution_job.result_json:
                    try:
                        stored_execution = json.loads(execution_job.result_json)
                    except (ValueError, TypeError):
                        raise HTTPException(status_code=503, detail="durable execution status is invalid") from None
                    existing_payment_state["report_review_status"] = (
                        "PENDING_REVIEW" if stored_execution.get("status") == "EXECUTED_REVIEW_REQUIRED" else "NOT_REVIEWABLE"
                    )
                    existing_payment_state["report_sha256"] = stored_execution.get("decision_report_sha256")
                    existing_payment_state["customer_delivery"] = "NOT_DELIVERED"
            if order.payment_result_json:
                try:
                    existing_payment_state["payment_result"] = json.loads(order.payment_result_json)
                except (ValueError, TypeError):
                    raise HTTPException(status_code=503, detail="durable payment result is invalid") from None
        elif order.status == "CREATING":
            order_id = order.id
            db.commit()
        else:
            raise HTTPException(status_code=409, detail="checkout order is already being processed or is not reusable")

    if existing_payment_state is not None:
        return existing_payment_state

    if reused_order is not None:
        append_record(tenant_id, "stripe.checkout_created", {
            "ola_order_id": reused_order["order_id"],
            "tenant_id": tenant_id,
            "requester_id": requester_id,
            "checkout_session_id": reused_order["session_id"],
            "request_hash": request_hash,
        }, deduplicate=True)
        append_record(
            tenant_id, "revenue.checkout_created", reused_order,
            deduplicate=True,
        )
        return {
            "status": "READY_FOR_PAYMENT",
            "order_id": reused_order["order_id"],
            "session_id": reused_order["session_id"],
            "checkout_url": reused_order["checkout_url"],
        }

    provider_idempotency_key = f"ola-checkout-{order_id}"
    try:
        session = create_checkout(
            task, success_url, cancel_url, tenant_id,
            idempotency_key=provider_idempotency_key,
            order_id=order_id,
        )
        session_id = session.get("id") if isinstance(session, dict) else None
        checkout_url = session.get("url") if isinstance(session, dict) else None
        if not isinstance(session_id, str) or not session_id.startswith("cs_test_") or not isinstance(checkout_url, str) or not checkout_url.startswith("https://"):
            raise RuntimeError("Stripe returned an invalid Checkout Session")
    except Exception as exc:
        # Leave the durable order in CREATING. A retry with the same key
        # reuses the same Stripe idempotency key and safely recovers the result.
        raise HTTPException(status_code=502, detail="checkout unavailable; retry with the same Idempotency-Key") from exc

    with SessionLocal() as db:
        order = db.get(CheckoutOrder, order_id)
        if order is None:
            raise HTTPException(status_code=503, detail="checkout order state unavailable")
        if order.stripe_session_id not in (None, session_id):
            raise HTTPException(status_code=409, detail="checkout order is bound to a different Stripe session")
        order.stripe_session_id = session_id
        order.checkout_url = checkout_url
        order.status = "CHECKOUT_CREATED"
        control = db.scalar(select(CheckoutOrderControl).where(
            CheckoutOrderControl.order_id == order_id,
            CheckoutOrderControl.tenant_id == tenant_id,
        ))
        if control is not None and control.status == "CREATING":
            control.status = "CHECKOUT_CREATED"
        db.commit()

    append_record(tenant_id, "stripe.checkout_created", {
        "ola_order_id": order_id,
        "tenant_id": tenant_id,
        "requester_id": requester_id,
        "checkout_session_id": session_id,
        "request_hash": request_hash,
    }, deduplicate=True)
    append_record(
        tenant_id, "revenue.checkout_created",
        {"order_id": order_id, "session_id": session_id, "request_hash": request_hash},
        deduplicate=True,
    )
    return {
        "status": "READY_FOR_PAYMENT",
        "order_id": order_id,
        "session_id": session_id,
        "checkout_url": checkout_url,
    }

@app.get("/payment-success")
def payment_success(session_id: str):
    try:
        session = retrieve_checkout(session_id)
    except Exception as exc:
        raise HTTPException(status_code=502, detail="payment lookup unavailable") from exc
    if not isinstance(session, dict) or session.get("id") != session_id:
        raise HTTPException(status_code=502, detail="Stripe returned an invalid Checkout Session")
    metadata = session.get("metadata")
    if not isinstance(metadata, dict):
        raise HTTPException(status_code=403, detail="payment session has no valid OLA metadata")
    tenant_id = metadata.get("tenant_id")
    order_id = metadata.get("order_id")
    request_hash = metadata.get("request_hash")
    if not isinstance(tenant_id, str) or not tenant_id or not isinstance(order_id, str) or not order_id:
        raise HTTPException(status_code=403, detail="payment session has no OLA order provenance")
    if not isinstance(request_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", request_hash):
        # Compatibility for old sandbox sessions whose metadata still contains task text.
        legacy_task = metadata.get("task")
        request_hash = hashlib.sha256(legacy_task.strip().encode("utf-8")).hexdigest() if isinstance(legacy_task, str) and legacy_task.strip() else None
    if not request_hash:
        raise HTTPException(status_code=403, detail="payment session has no request hash")

    with SessionLocal() as db:
        order = db.get(CheckoutOrder, order_id)
        if (
            order is None
            or order.tenant_id != tenant_id
            or order.stripe_session_id != session_id
        ):
            raise HTTPException(status_code=403, detail="payment session is not bound to this OLA order")
        if order.request_hash != request_hash:
            raise HTTPException(status_code=403, detail="payment session request hash does not match the OLA order")
        if not isinstance(order.task, str) or not order.task:
            legacy_task = metadata.get("task")
            if isinstance(legacy_task, str) and legacy_task.strip() and hashlib.sha256(legacy_task.strip().encode("utf-8")).hexdigest() == order.request_hash:
                order.task = legacy_task.strip()
                db.commit()
        if not isinstance(order.task, str) or hashlib.sha256(order.task.encode("utf-8")).hexdigest() != order.request_hash:
            raise HTTPException(status_code=403, detail="private OLA order task is unavailable")
        control = db.scalar(select(CheckoutOrderControl).where(
            CheckoutOrderControl.order_id == order_id,
            CheckoutOrderControl.tenant_id == tenant_id,
        ))
        control_status = control.status if control is not None else "UNKNOWN"

        if not payment_verified(session):
            blocked = True
            order_status = order.status
            recorded = None
        else:
            blocked = False
            order_status = order.status
            recorded = None
            if order.status in {
                "PAID_PENDING_REVIEW", "COMPLETED", "EXECUTED_REVIEW_REQUIRED",
                "EXECUTED_BLOCKED", "FAILED", "INTERRUPTED", "BLOCKED",
                "REPORT_APPROVED", "REPORT_DELIVERED",
            }:
                if not order.payment_result_json:
                    raise HTTPException(status_code=503, detail="durable payment result is unavailable")
                try:
                    recorded = json.loads(order.payment_result_json)
                except (ValueError, TypeError):
                    raise HTTPException(status_code=503, detail="durable payment result is invalid") from None
                if (
                    not isinstance(recorded, dict)
                    or recorded.get("checkout_session_id") != session_id
                ):
                    raise HTTPException(status_code=503, detail="durable payment result binding is invalid")

    if blocked:
        append_record(tenant_id, "revenue.payment_blocked", {
            "order_id": order_id,
            "session_id": session_id,
            "payment_status": session.get("payment_status"),
            "status": session.get("status"),
        }, deduplicate=True)
        # Public success redirect is deliberately a status-only response.
        return {"status": "PAYMENT_NOT_CONFIRMED", "execution": "NOT_STARTED"}

    if order_status == "PAID_PENDING_REVIEW":
        approved = control_status == "APPROVED_FOR_EXECUTION"
        return {
            "status": "APPROVED_FOR_EXECUTION" if approved else "PAID_PENDING_REVIEW",
            "payment": "CONFIRMED",
            "execution": "QUEUED" if approved else "NOT_STARTED",
            "customer_delivery": "NOT_DELIVERED",
            "next_gate": "EXECUTION_DISPATCH" if approved else "HUMAN_REVIEW",
        }

    if order_status in {"REPORT_APPROVED", "REPORT_DELIVERED"}:
        return {
            "status": order_status,
            "payment": "CONFIRMED",
            "execution": "COMPLETED",
            "customer_delivery": "DELIVERED" if order_status == "REPORT_DELIVERED" else "NOT_DELIVERED",
            "next_gate": "NONE" if order_status == "REPORT_DELIVERED" else "CUSTOMER_DELIVERY",
        }

    if order_status == "COMPLETED":
        # Legacy completed orders must not disclose their stored task, report,
        # run identifier, evidence identifiers or payment metadata here.
        return {
            "status": "COMPLETED",
            "payment": "CONFIRMED",
            "execution": "COMPLETED",
            "customer_delivery": "NOT_DELIVERED",
            "next_gate": "CUSTOMER_REPORT_REVIEW",
        }

    if order_status in {
        "EXECUTED_REVIEW_REQUIRED", "EXECUTED_BLOCKED", "FAILED", "INTERRUPTED", "BLOCKED",
    }:
        return {
            "status": order_status,
            "payment": "CONFIRMED",
            "execution": (
                "COMPLETED" if order_status in {"EXECUTED_REVIEW_REQUIRED", "EXECUTED_BLOCKED"}
                else "FAILED" if order_status == "FAILED"
                else "INTERRUPTED" if order_status == "INTERRUPTED"
                else "BLOCKED"
            ),
            "customer_delivery": "NOT_DELIVERED",
            "next_gate": "CUSTOMER_REPORT_REVIEW" if order_status == "EXECUTED_REVIEW_REQUIRED" else "MANUAL_RECONCILIATION",
        }

    if order_status in {"CHECKOUT_CREATED", "PAYMENT_PROCESSING"}:
        return {
            "status": "PAYMENT_VERIFICATION_PENDING",
            "execution": "NOT_STARTED",
            "customer_delivery": "NOT_DELIVERED",
            "next_gate": "STRIPE_WEBHOOK",
        }

    raise HTTPException(status_code=409, detail="OLA order is not in a payable state")


@app.post("/evidence")
def create_evidence(body: dict, x_api_key: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    record_type = body.get("record_type", "generic")
    if not isinstance(record_type, str) or not record_type.strip():
        raise HTTPException(status_code=400, detail="record_type must be a nonempty string")
    # Public tenant keys may submit customer evidence, but cannot impersonate
    # trusted NINA execution, DAG timing, or Human Gate producers. The local
    # hash chain proves record integrity, not who caused a record to be written.
    from .hashchain import is_privileged_type, EVIDENCE_META_KEY
    from .evidence_v4 import V4_META_KEY
    if is_privileged_type(record_type):
        raise HTTPException(status_code=403, detail="reserved internal evidence type")
    payload = body.get("payload", {})
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="evidence payload must be a JSON object")
    if EVIDENCE_META_KEY in payload or V4_META_KEY in payload:
        raise HTTPException(status_code=400, detail="reserved evidence metadata")
    return append_evidence_atomic(tenant_id, record_type, payload, producer_id="tenant_api")


@app.post("/audit")
def create_audit(body: dict, x_api_key: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    task = body.get("task")
    if not task:
        raise HTTPException(status_code=400, detail="task is required")
    return run_controlled_audit(
        tenant_id,
        task,
        body.get("scenario", "fault_then_recovery"),
    )


@app.post("/agent-run")
def create_agent_run(body: dict, x_api_key: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    task = body.get("task")
    if not task:
        raise HTTPException(status_code=400, detail="task is required")

    # Preserve the original task-only API with a registered default identity.
    agent_id = body.get("agent_id", "agent-001")
    risk = body.get("risk", "LOW")
    allowed = False
    try:
        if not isinstance(agent_id, str) or agent_id not in REGISTERED_AGENT_IDS:
            reason = "unregistered_agent"
        elif not isinstance(risk, str) or risk.upper() not in {"LOW", "HIGH"}:
            reason = "unknown_risk"
        else:
            risk = risk.upper()
            # The HTTP caller cannot certify its own human approval. The gate
            # checks a no-op first; runtime is unreachable without ALLOW.
            decision = AGENT_RUN_GATE.execute(
                agent_id=agent_id, action="run_agent_task", effect=lambda: None,
                risk=risk, human_approved=False,
            )
            allowed = (risk == "LOW" and isinstance(decision, ExecutionDecision)
                       and decision.status == "ALLOW")
            reason = ("allowlisted_action" if allowed else
                      "human_owner_approval_required" if risk == "HIGH" else
                      "gate_denied_or_missing_decision")
    except Exception:
        reason = "gate_exception"
        allowed = False

    try:
        append_record(tenant_id, "execution.safety_gate", {
            "decision": "ALLOW" if allowed else "DENY",
            "agent_id": agent_id, "risk": risk, "reason": reason,
            "action": "run_agent_task",
            "task_sha256": hashlib.sha256(canonical_json(task).encode()).hexdigest(),
        })
    except Exception as exc:
        raise HTTPException(status_code=403, detail="gate evidence unavailable") from exc
    if not allowed:
        raise HTTPException(status_code=403, detail=reason)
    return run_agent_task(tenant_id, task)



@app.post("/nina-workflow")
def create_nina_workflow(body: dict, x_api_key: str | None = Header(default=None)):
    """Opt-in bounded DAG execution. No automatic production approval."""
    tenant_id, requester_id = identity_from_key(x_api_key)
    if os.getenv("OLA_PARALLEL_WORKFLOWS_ENABLED", "0") != "1":
        raise HTTPException(status_code=503, detail="parallel NINA workflows are disabled")
    task_text = body.get("task")
    if not isinstance(task_text, str) or not task_text.strip():
        raise HTTPException(status_code=400, detail="task is required")
    requested_tools = body.get("requested_tools", ["llm_agent"])
    if (not isinstance(requested_tools, list) or not requested_tools
            or not all(isinstance(tool, str) and tool.strip() for tool in requested_tools)):
        raise HTTPException(status_code=400, detail="requested_tools must be nonempty strings")
    # Bound provider prompt size and prevent duplicate capability amplification.
    # This must happen before NINA or the LLM planner is invoked.
    if len(requested_tools) > len(REGISTERED_TOOLS) or len(set(requested_tools)) != len(requested_tools):
        raise HTTPException(status_code=400, detail="requested_tools must be unique and bounded")
    nina_task = NinaTask.create(tenant_id, task_text, requested_tools)
    policy = NinaOrchestrator().plan(nina_task)
    if policy.status != "ALLOW":
        return {"status": "BLOCK", "reason": policy.reason, "verified": False}
    try:
        return run_nina_workflow(
            tenant_id=tenant_id,
            requester_id=requester_id,
            goal=task_text,
            allowed_tools=policy.allowed_tools,
            append=append_record,
            fetch_records=read_tenant_evidence,
        )
    except WorkflowPlanError as exc:
        return {"status": "BLOCK", "reason": "workflow plan rejected", "verified": False}
    except Exception as exc:
        raise HTTPException(status_code=503, detail="workflow runtime unavailable") from exc



@app.get("/nina-workflow/{run_id}/report")
def refresh_nina_workflow_report(run_id: str,
                                 authorization: str | None = Header(default=None)):
    """Read-only, tenant-scoped refresh for a stale tip-bound IGOR report."""
    from .igor_workflow import verify_dag_records

    tenant_id, _ = bearer_identity(authorization)
    expected_commit = runtime_source_commit()
    if not expected_commit:
        raise HTTPException(status_code=409, detail="runtime source commit unknown")
    evidence = read_tenant_evidence(tenant_id)
    if any(row["record_type"] == "human.workflow_approval"
           and json.loads(row["payload_json"]).get("run_id") == run_id for row in evidence):
        raise HTTPException(status_code=409, detail="workflow already reviewed")
    report = verify_dag_records(evidence, tenant_id=tenant_id, run_id=run_id,
                                expected_commit=expected_commit)
    if report["status"] != "VERIFIED":
        raise HTTPException(status_code=409, detail="independent workflow verification unavailable")
    return {
        "run_id": run_id, "status": report["status"],
        "tip_hash": report["chain_tip"], "report_digest": report["report_digest"],
        "trust_scope": report["trust_scope"],
        "human_gate": "NOT_APPROVED", "production_authorized": False,
    }


@app.post("/nina-workflow/{run_id}/approve")
def approve_nina_workflow(run_id: str, body: dict,
                          authorization: str | None = Header(default=None)):
    """Explicit second-identity review, bound to full IGOR report and evidence tip.

    This does NOT grant deployment authority or approve a GitHub pull request.
    """
    tenant_id, approver_id = bearer_identity(authorization)
    try:
        return approve_workflow(
            tenant_id=tenant_id, approver_id=approver_id, run_id=run_id,
            tip_hash=body.get("tip_hash"),
            report_digest=body.get("report_digest"),
            reason=body.get("reason"),
        )
    except WorkflowApprovalRejected as exc:
        raise HTTPException(status_code=exc.code, detail=str(exc)) from exc


@app.post("/nina-run")
def create_nina_run(body: dict, x_api_key: str | None = Header(default=None)):
    tenant_id, requester_id = identity_from_key(x_api_key)
    task_text = body.get("task")
    if not task_text:
        raise HTTPException(status_code=400, detail="task is required")
    requested_tools = body.get("requested_tools", ["safe_expression"])
    if not isinstance(requested_tools, list):
        raise HTTPException(status_code=400, detail="requested_tools must be a list")
    from .nina_execution import run_nina_task
    try:
        return run_nina_task(tenant_id, requester_id, task_text, requested_tools)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/nina-run/{run_id}/approve")
def approve_nina_run(
    run_id: str,
    body: dict,
    authorization: str | None = Header(default=None),
):
    tenant_id, approver_id = bearer_identity(authorization)
    try:
        return approve_nina_candidate(
            tenant_id=tenant_id, approver_id=approver_id, run_id=run_id,
            tip_hash=body.get("tip_hash"),
            report_sha256=body.get("report_sha256"),
            reason=body.get("reason"),
        )
    except WorkflowApprovalRejected as exc:
        raise HTTPException(status_code=exc.code, detail=str(exc)) from exc


@app.post("/checkout-orders/{order_id}/approve")
def approve_checkout_order(
    order_id: str,
    body: dict,
    authorization: str | None = Header(default=None),
):
    tenant_id, approver_id = bearer_identity(authorization)
    try:
        return approve_paid_order(
            tenant_id=tenant_id,
            approver_id=approver_id,
            order_id=order_id,
            tip_hash=body.get("tip_hash"),
            reason=body.get("reason"),
        )
    except PaidOrderApprovalRejected as exc:
        raise HTTPException(status_code=exc.code, detail=str(exc)) from exc


@app.post("/checkout-orders/{order_id}/review-report")
def review_checkout_order_report(
    order_id: str,
    body: dict,
    authorization: str | None = Header(default=None),
):
    tenant_id, reviewer_id = bearer_identity(authorization)
    try:
        return approve_paid_order_report(
            tenant_id=tenant_id, reviewer_id=reviewer_id, order_id=order_id,
            tip_hash=body.get("tip_hash"), report_sha256=body.get("report_sha256"),
            reason=body.get("reason"),
        )
    except PaidReportReviewRejected as exc:
        raise HTTPException(status_code=exc.code, detail=str(exc)) from exc


@app.get("/checkout-orders/{order_id}/report")
def retrieve_checkout_order_report(
    order_id: str,
    authorization: str | None = Header(default=None),
):
    tenant_id, requester_id = bearer_identity(authorization)
    try:
        return deliver_paid_order_report(
            tenant_id=tenant_id, requester_id=requester_id, order_id=order_id,
        )
    except PaidReportReviewRejected as exc:
        raise HTTPException(status_code=exc.code, detail=str(exc)) from exc


@app.post("/internal/checkout-execution/{job_id}/run")
def run_paid_order_execution_job(
    job_id: str,
    x_ola_worker_token: str | None = Header(default=None),
):
    try:
        verify_worker_token(x_ola_worker_token)
        return execute_paid_order_job(job_id)
    except PaidOrderExecutionRejected as exc:
        raise HTTPException(status_code=exc.code, detail=str(exc)) from exc


@app.post("/stripe/webhook")
async def stripe_webhook(request: Request, stripe_signature: str | None = Header(default=None)):
    if not stripe_signature:
        raise HTTPException(status_code=400, detail="missing Stripe signature")
    body = await request.body()
    return process_checkout_event(body, stripe_signature)


@app.post("/business-invoice-run")
def create_business_invoice_run(body: dict, x_api_key: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    invoice = body.get("invoice")
    if not isinstance(invoice, dict):
        raise HTTPException(status_code=400, detail="invoice object is required")
    task = "INVOICE_JSON:" + canonical_json(invoice)
    try:
        return run_invoice_task(tenant_id, task)
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="invalid invoice input") from exc


@app.get("/evidence/tip")
def get_evidence_tip(x_api_key: str | None = Header(default=None)):
    """Return only the authenticated tenant's current chain tip for Human Gate."""
    tenant_id = tenant_from_key(x_api_key)
    with SessionLocal() as db:
        latest = db.scalar(
            select(EvidenceRecord)
            .where(EvidenceRecord.tenant_id == tenant_id)
            .order_by(EvidenceRecord.seq.desc())
            .limit(1)
        )
        count = db.scalar(
            select(func.count(EvidenceRecord.id)).where(
                EvidenceRecord.tenant_id == tenant_id
            )
        ) or 0
        return {
            "tip_hash": latest.record_hash if latest else "0" * 64,
            "record_count": int(count),
        }


@app.get("/evidence")
def list_evidence(
    limit: int = 20,
    before_seq: int | None = None,
    x_api_key: str | None = Header(default=None),
):
    """List only the authenticated tenant's evidence records, newest first."""
    tenant_id = tenant_from_key(x_api_key)
    if limit < 1 or limit > 100:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 100")
    if before_seq is not None and before_seq < 0:
        raise HTTPException(status_code=400, detail="before_seq must be >= 0")

    with SessionLocal() as db:
        query = select(EvidenceRecord).where(EvidenceRecord.tenant_id == tenant_id)
        if before_seq is not None:
            query = query.where(EvidenceRecord.seq < before_seq)
        records = db.scalars(
            query.order_by(EvidenceRecord.seq.desc()).limit(limit)
        ).all()

    return {
        "records": [
            {
                "id": record.id,
                "tenant_id": record.tenant_id,
                "seq": record.seq,
                "record_type": record.record_type,
                "payload": json.loads(record.payload_json),
                "prev_hash": record.prev_hash,
                "record_hash": record.record_hash,
            }
            for record in records
        ],
        "count": len(records),
        "limit": limit,
        "before_seq": before_seq,
    }


@app.get("/evidence/{record_id}")
def get_evidence(record_id: str, x_api_key: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    with SessionLocal() as db:
        record = db.scalar(
            select(EvidenceRecord).where(
                EvidenceRecord.id == record_id,
                EvidenceRecord.tenant_id == tenant_id,
            )
        )
        if record is None:
            raise HTTPException(status_code=404, detail="evidence not found")
        return {
            "id": record.id,
            "tenant_id": record.tenant_id,
            "seq": record.seq,
            "record_type": record.record_type,
            "payload": json.loads(record.payload_json),
            "prev_hash": record.prev_hash,
            "record_hash": record.record_hash,
        }
