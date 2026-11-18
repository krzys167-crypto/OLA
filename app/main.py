import unicodedata
import hashlib
import logging
import re
import json
import os
import traceback
import uuid
from pathlib import Path
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from starlette.responses import FileResponse, JSONResponse
from sqlalchemy.exc import OperationalError, TimeoutError as PoolTimeoutError
from sqlalchemy import select
from .database import Base, engine, SessionLocal, install_append_only_triggers
from .models import Tenant, ApiKey, EvidenceRecord, StripeEvent
from .hashchain import GENESIS_HASH, canonical_json, compute_record_hash, verify_chain
from .agent_runtime import run_agent_task, task_is_computable
from .business_runtime import run_invoice_task, MAX_INVOICE_BYTES
from .nina import NinaOrchestrator, NinaTask
from .igor import IgorVerifier
from .replay import build_replay, verify_replay
from .human_gate import HumanGate, ReviewDecision
from .nina_igor import NinaIgorChain, STATUS_FIELDS
from .decision_report import build_decision_report
from .decision_fabric import DecisionFabric
from .chat_runtime import chat
from .revenue import create_checkout, retrieve_checkout
from .stripe_webhook import process_checkout_event, checkout_task, session_is_for_offer, session_paid_for_offer
from . import ambient, anchor_external, cfr, firewall, identity, pipeline_bridge
from .payment_binding import checkout_result_matches
from .revenue_proof import revenue_proof
from .http_guard import HttpGuard, security_headers
from .migrations import run_migrations
from starlette.concurrency import run_in_threadpool

app = FastAPI(title="OLA Execution Gate")
app.add_middleware(HttpGuard)
Base.metadata.create_all(bind=engine)
install_append_only_triggers()
run_migrations()                                          # stripe_events lease + per-session columns (idempotent)


log = logging.getLogger("ola.app")
SQLITE_BUSY, SQLITE_LOCKED = 5, 6                       # primary result codes: a transient lock, not a bug


def _is_lock_error(exc) -> bool:
    """Lock or busy, decided from the DBAPI error alone: its sqlite error code, or the lock text in ITS message.
    str(exc) of the SQLAlchemy error also holds the SQL and the bound parameters, i.e. caller-controlled text: a payload
    containing the word "busy" used to turn a disk or read-only error into a retryable 503."""
    orig = getattr(exc, "orig", None)
    code = getattr(orig, "sqlite_errorcode", None)
    if isinstance(code, int) and (code & 0xFF) in (SQLITE_BUSY, SQLITE_LOCKED):
        return True
    message = str(orig).lower() if orig is not None else ""
    return "database is locked" in message or "database table is locked" in message


@app.exception_handler(OperationalError)
async def _database_error(request, exc):
    """A locked database is a transient 503 (retry), never a 500 that prints the SQL and parameters. Every other
    OperationalError stays a 500 for the client (nothing of the SQL reaches it) but is logged: this handler is the
    reason the server no longer sees it as an unhandled exception."""
    if _is_lock_error(exc):
        return JSONResponse({"detail": "database busy, retry"}, status_code=503, headers={"Retry-After": "2"})
    orig = getattr(exc, "orig", None)
    log.error("database error on %s %r: %s: %s (%s)\n%s", request.method, request.url.path, type(orig).__name__, orig,
              getattr(orig, "sqlite_errorname", "?"), "".join(traceback.format_tb(exc.__traceback__)))
    return JSONResponse({"detail": "database error"}, status_code=500)


@app.exception_handler(PoolTimeoutError)
async def _database_pool_exhausted(request, exc):
    """All pooled connections are busy waiting for the same lock: the same transient condition, so the same 503."""
    log.warning("database connection pool exhausted on %s %r", request.method, request.url.path)
    return JSONResponse({"detail": "database busy, retry"}, status_code=503, headers={"Retry-After": "2"})


@app.exception_handler(Exception)
async def _internal_error(request, exc):
    """An unhandled error is answered by ServerErrorMiddleware, which sits OUTSIDE HttpGuard: the security headers have
    to be set here. The exception is still re-raised to the server afterwards (it is logged there); nothing of it
    reaches the client."""
    return JSONResponse({"detail": "internal server error"}, status_code=500, headers=security_headers())


def identity_from_key(raw_key):
    if not raw_key:
        raise HTTPException(status_code=401, detail="missing API key")
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
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


def append_record(tenant_id, record_type, payload):
    """Same hashing as before, now through pipeline_bridge.append_evidence: a concurrent writer that took the same
    (tenant_id, seq) is retried (UNIQUE constraint -> clean IntegrityError, never a fork, never a 500)."""
    return pipeline_bridge.append_evidence(tenant_id, record_type, payload, attempts=96)


MAX_EVIDENCE_BYTES = 262144
MAX_PAYLOAD_DEPTH = 32


def _nesting_depth(value, cap: int) -> int:
    """Depth of the deepest dict/list (the value itself is level 1), computed with an explicit stack - a deeply nested
    document must not be able to exhaust the interpreter stack here - and abandoned as soon as it passes `cap`."""
    deepest = 0
    stack = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict):
            children = node.values()
        elif isinstance(node, list):
            children = node
        else:
            continue
        deepest = max(deepest, depth)
        if deepest > cap:
            return deepest
        stack.extend((child, depth + 1) for child in children)
    return deepest


def _checked_payload(payload):
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="payload must be a JSON object")
    if _nesting_depth(payload, MAX_PAYLOAD_DEPTH) > MAX_PAYLOAD_DEPTH:
        raise HTTPException(status_code=400, detail=f"payload nesting is limited to {MAX_PAYLOAD_DEPTH} levels")
    try:
        encoded = canonical_json(payload).encode("utf-8")
    except (ValueError, UnicodeEncodeError, RecursionError):
        raise HTTPException(status_code=400, detail="payload must be strict JSON (no NaN/Infinity, valid Unicode, "
                                                    "bounded nesting)") from None
    if len(encoded) > MAX_EVIDENCE_BYTES:
        raise HTTPException(status_code=400, detail=f"payload must be at most {MAX_EVIDENCE_BYTES} bytes")
    return payload


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
        rows = db.scalars(
            select(EvidenceRecord)
            .where(
                EvidenceRecord.tenant_id == tenant_id,
                EvidenceRecord.id.in_(evidence_ids),
            )
            .order_by(EvidenceRecord.seq.asc())
        ).all()

    # the WHOLE tenant chain is verified: a subset of its rows does not start at seq 0 once the tenant has any
    # other record and would be reported as broken
    chain = pipeline_bridge.load_chain(tenant_id)
    chain_ok, reason = verify_chain(chain)
    if not chain_ok:
        return {
            "audit_id": audit_id,
            "status": "FAILED",
            "outcome": "evidence_chain_invalid",
            "evidence_count": len(rows),
            "evidence_ids": evidence_ids,
            "reason": reason,
        }

    return {
        "audit_id": audit_id,
        "status": "VERIFIED",
        "outcome": "recovered_and_verified",
        "evidence_count": len(rows),
        "evidence_ids": evidence_ids,
        "reason": reason,
    }


def _ambient_mode():
    """off | shadow | enforce. A bad setting is a 503 before any model is called, never a silent 'off'."""
    try:
        amb = ambient.mode()
        if amb == "enforce":
            ambient.preflight()
        return amb
    except ambient.AmbientConfigError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


def _ambient_apply(amb, background, tenant_id, surface, task, output, response, produced_by):
    """The ambient IGOR can only downgrade: shadow never touches the response, enforce may replace it by BLOCK."""
    if amb == "shadow":
        background.add_task(ambient.shadow, tenant_id, surface, task, output, produced_by)
        return response
    try:
        decision = ambient.enforce(tenant_id, surface, task, output, produced_by)
    except pipeline_bridge.PipelineBusy as exc:
        raise HTTPException(status_code=429, detail=str(exc), headers={"Retry-After": "5"}) from exc
    except ambient.AmbientConfigError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return response if decision["allow"] else ambient.blocked_response(decision)


def _agent_producer(result: dict):
    """The model that actually produced an /agent-run output (last real_llm step), so the self-judge guard can fire."""
    execution = result.get("execution")
    if not isinstance(execution, list):
        return None
    for step in reversed(execution):
        if isinstance(step, dict) and step.get("invocation_type") == "real_llm" and isinstance(step.get("model"), str):
            return step["model"]
    return None


def _unjudged(result: dict) -> dict:
    return dict(result, status="UNKNOWN", verification="NOT_JUDGED")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def home():
    web_path = Path(__file__).resolve().parent.parent / "web" / "index.html"
    return FileResponse(web_path, media_type="text/html")


@app.post("/chat")
def chat_endpoint(body: dict, background: BackgroundTasks, x_api_key: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    messages = body.get("messages", [])
    if not isinstance(messages, list) or not messages:
        raise HTTPException(status_code=400, detail="messages list is required")
    clean = []
    for item in messages:
        if (not isinstance(item, dict) or not isinstance(item.get("role"), str)
                or item["role"] not in {"user", "assistant"} or not isinstance(item.get("content"), str)):
            raise HTTPException(status_code=400, detail="invalid message")
        try:
            item["content"].encode("utf-8")
        except UnicodeEncodeError:
            raise HTTPException(status_code=400, detail="message is not valid UTF-8 text") from None
        clean.append({"role": item["role"], "content": item["content"]})
    amb = _ambient_mode()
    result = chat(tenant_id, clean)
    if result.get("status") == "VERIFIED" and not isinstance(result.get("message"), str):
        # "VERIFIED" without a text answer is a broken model layer: never passed on as verified (or as anything else)
        return {"status": "BLOCK", "reason": "the model layer returned no text answer"}
    if result.get("status") != "VERIFIED":
        return result                                   # BLOCK from the model layer passes through
    # "VERIFIED" from the model layer means the model answered. It does NOT mean the answer is correct: only an
    # enforce-mode ACCEPT by a qualified independent judge earns that word. Off and shadow report UNKNOWN.
    if amb == "off":
        return _unjudged(result)
    task = next((m["content"] for m in reversed(clean) if m["role"] == "user"), "")
    out = _ambient_apply(amb, background, tenant_id, "chat", task, result["message"], result, result.get("model"))
    if amb == "shadow":
        return _unjudged(out)
    return dict(out, verification="INDEPENDENT_JUDGE_ACCEPTED") if out is result else out


@app.post("/checkout")
def create_checkout_session(body: dict, x_api_key: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    # everything is validated BEFORE the Stripe session exists: a session is not undone by a later error
    task = _task_from_body(body)
    success_url = _url_from_body(body, "success_url", "http://localhost:8000/payment-success")
    cancel_url = _url_from_body(body, "cancel_url", "http://localhost:8000/")
    try:
        session = create_checkout(task.strip(), success_url, cancel_url, tenant_id)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"checkout creation failed: {exc.__class__.__name__}") from exc
    expected = "PERFORMED" if task_is_computable(task) else "NOT_PERFORMED"
    append_record(tenant_id, "revenue.checkout_created", {"session_id": session.get("id"), "task": task.strip(), "amount": session.get("amount_total"),
                                                           "computation_expected": expected})
    response = {"status": "READY_FOR_PAYMENT", "session_id": session.get("id"), "checkout_url": session.get("url"),
                "computation_expected": expected}
    if expected == "NOT_PERFORMED":
        # not a refusal (that is a product decision): the customer is told before paying what the audit can do with this task
        response["notice"] = ("the audit computes a plain arithmetic expression (for example \"Calculate 17 * 23\"); this task "
                              "contains none, so the paid run will end as UNKNOWN with computation NOT_PERFORMED")
    return response


def _session_row_recorded(tenant_id: str, record_type: str, session_id: str, **fields) -> bool:
    """True when this tenant's chain already holds a `record_type` row about THIS session whose payload carries every
    one of `fields`. /payment-success needs no secret (the session id is enough), so a poll must not be able to grow
    the chain: one row per distinct state of a session. (Two polls racing on the very first one can both write.)"""
    with SessionLocal() as db:
        rows = db.scalars(select(EvidenceRecord).where(
            EvidenceRecord.tenant_id == tenant_id, EvidenceRecord.record_type == record_type,
            EvidenceRecord.payload_json.contains(session_id, autoescape=True)))
        for row in rows:
            try:
                payload = json.loads(row.payload_json)
            except (TypeError, ValueError):
                continue
            if (isinstance(payload, dict) and payload.get("session_id") == session_id
                    and all(payload.get(key) == value for key, value in fields.items())):
                return True
    return False


def _block_recorded(tenant_id: str, session_id: str, payment_status, status) -> bool:
    """True when the chain already says that THIS session was blocked in THIS state; a state Stripe reports later is
    a new fact and gets its own row."""
    return _session_row_recorded(tenant_id, "revenue.payment_blocked", session_id,
                                 payment_status=payment_status, status=status)


def _record_result_served(tenant_id: str, session_id: str, run_id, result: dict) -> None:
    """The one place that says the paid result was handed out: `revenue.result_served` (session, run, SHA-256 of the
    result exactly as the webhook stored it). It is written once per session and run, and only here, for a session
    that is paid for this offer and whose execution is bound to the payment. It says that the SERVER served the result
    to whoever presented the session id; that the customer received or read it cannot be observed."""
    digest = hashlib.sha256(canonical_json(result).encode("utf-8")).hexdigest()
    if _session_row_recorded(tenant_id, "revenue.result_served", session_id, run_id=run_id, result_sha256=digest):
        return
    append_record(tenant_id, "revenue.result_served", {"session_id": session_id, "run_id": run_id, "result_sha256": digest})


@app.get("/payment-success")
def payment_success(session_id: str):
    try:
        session = retrieve_checkout(session_id)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"payment lookup failed: {exc.__class__.__name__}") from exc
    if not isinstance(session, dict):
        raise HTTPException(status_code=502, detail="payment lookup failed: unexpected answer")
    metadata = session.get("metadata")
    tenant_id = metadata.get("tenant_id") if isinstance(metadata, dict) else None
    if not isinstance(tenant_id, str) or not tenant_id:
        raise HTTPException(status_code=403, detail="payment session has no tenant provenance")
    if not session_paid_for_offer(session):
        status, payment_status = session.get("status"), session.get("payment_status")
        if status == "expired" and payment_status != "paid":
            return {"status": "BLOCK", "reason": "checkout session expired without payment", "session_id": session_id}
        if session_is_for_offer(session) and payment_status == "unpaid" and status in ("open", "complete"):
            # The customer is still paying, or an asynchronous method (SEPA debit, bank transfer) has not settled yet:
            # not an anomaly, so nothing is written (a GET that appended evidence on every poll let anyone holding a
            # session id grow the tenant's chain). The webhook starts the run when Stripe confirms the money.
            return {"status": "AWAITING_PAYMENT", "reason": "payment is not confirmed yet", "session_id": session_id}
        if not _block_recorded(tenant_id, session_id, payment_status, status):
            append_record(tenant_id, "revenue.payment_blocked", {"session_id": session_id, "payment_status": payment_status, "status": status})
        return {"status": "BLOCK", "reason": "payment not verified", "session_id": session_id}
    task = checkout_task(session)        # the task exactly as the webhook read (and stored) it: stripped, or the custom field
    if not task:
        return {"status": "BLOCK", "reason": "paid session has no task", "session_id": session_id}

    with SessionLocal() as db:
        completed = None
        bound_result = None
        evidence_rows = db.scalars(
            select(EvidenceRecord).where(
                EvidenceRecord.tenant_id == tenant_id,
                EvidenceRecord.record_type == "stripe.ola_execution_completed",
            ).order_by(EvidenceRecord.seq.desc())
        )
        for evidence_row in evidence_rows:
            try:
                evidence = json.loads(evidence_row.payload_json)
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(evidence, dict) or evidence.get("checkout_session_id") != session_id:
                continue
            candidate = db.scalar(
                select(StripeEvent).where(
                    StripeEvent.event_id == evidence.get("stripe_event_id"),
                    StripeEvent.status == "COMPLETED",
                    StripeEvent.task == task,
                    StripeEvent.run_id == evidence.get("ola_run_id"),
                )
            )
            if candidate is None:
                continue
            try:
                result = json.loads(candidate.result_json)
            except (TypeError, json.JSONDecodeError):
                continue
            evidence["tenant_id"] = evidence_row.tenant_id
            if checkout_result_matches(tenant_id, session_id, task, evidence, candidate, result):
                completed = candidate
                bound_result = result
                break

    if completed is None:
        return {
            "status": "PAYMENT_CONFIRMED_EXECUTION_PENDING",
            "session_id": session_id,
            "task": task,
            "execution": "STRIPE_WEBHOOK",
        }

    _record_result_served(tenant_id, session_id, completed.run_id, bound_result)
    return {
        "status": "COMPLETED",
        "session_id": session_id,
        "task": task,
        "execution": "STRIPE_WEBHOOK",
        "run_id": completed.run_id,
        "result": bound_result,
    }


@app.get("/revenue/proof")
def revenue_proof_report(x_api_key: str | None = Header(default=None)):
    """Is a live payment proven end to end for THIS tenant? Computed from its evidence chain only (app/revenue_proof.py)."""
    return revenue_proof(tenant_from_key(x_api_key))


@app.post("/evidence")
def create_evidence(body: dict, x_api_key: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    record_type = body.get("record_type", "generic")
    # Dotted types (agent.*, igor.*, pipeline.*, anchor.*, firewall.*, ...) are written by the server only:
    # IGOR, the firewall and the anchors trust them, so a caller must not be able to forge one here.
    if not isinstance(record_type, str) or not re.fullmatch(r"[a-z0-9_-]{1,64}", record_type):
        raise HTTPException(status_code=400, detail="record_type must match [a-z0-9_-]{1,64} "
                                                    "(dotted types are reserved for the server)")
    return append_record(
        tenant_id,
        record_type,
        _checked_payload(body.get("payload", {})),
    )


@app.post("/audit")
def create_audit(body: dict, x_api_key: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    task = _task_from_body(body)
    return run_controlled_audit(
        tenant_id,
        task,
        body.get("scenario", "fault_then_recovery"),
    )


@app.post("/agent-run")
def create_agent_run(body: dict, background: BackgroundTasks, x_api_key: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    task = _task_from_body(body)
    amb = _ambient_mode()
    result = run_agent_task(tenant_id, task)
    if amb != "off" and result.get("status") == "VERIFIED":
        task_text = task
        return _ambient_apply(amb, background, tenant_id, "agent-run", task_text, ambient.agent_output_text(result),
                              result, _agent_producer(result))
    return result


@app.post("/nina-run")
def create_nina_run(body: dict, x_api_key: str | None = Header(default=None)):
    tenant_id, requester_id = identity_from_key(x_api_key)
    task_text = _task_from_body(body)
    requested_tools = _requested_tools(body, ["safe_expression"])

    nina_task = NinaTask.create(tenant_id, task_text, requested_tools)
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
    replay_nonce = runtime["runtime"].get("replay_nonce")
    runtime_commit = os.getenv("OLA_SOURCE_COMMIT") or os.getenv("OLA_RUNTIME_COMMIT")
    provider = execution[0].get("provider") if execution else None
    model = execution[0].get("model") if execution else None
    invocation_type = execution[0].get("invocation_type") if execution else None
    response_ids = [item.get("response_id") for item in execution if item.get("response_id")]
    response_digests = [item.get("response_digest") for item in execution if item.get("response_digest")]
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
            "response_digests": response_digests,
            "source_commit": runtime_commit or "UNKNOWN",
            "requester_id": requester_id,
            "replay_nonce": replay_nonce,
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
        expected_nonce=replay_nonce,
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
            runtime_commit
            and provider
            and model
            and invocation_type
            and (
                invocation_type != "real_llm"
                or len(response_ids) + len(response_digests) >= len(execution)
            )
        ) else "BLOCK",
        "commit": runtime_commit or "UNKNOWN",
        "provider": provider,
        "model": model,
        "invocation_type": invocation_type,
        "llm_invocations": len(execution),
        "response_ids": response_ids,
        "response_digests": response_digests,
        "source_commit": runtime_commit or "UNKNOWN",
        "replay_nonce": replay_nonce,
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

@app.post("/nina-run/{run_id}/approve")
def approve_nina_run(
    run_id: str,
    body: dict,
    authorization: str | None = Header(default=None),
):
    approver_tenant_id, approver_id = bearer_identity(authorization)
    tip_hash = body.get("tip_hash")
    if not isinstance(tip_hash, str) or not tip_hash:
        raise HTTPException(status_code=400, detail="tip_hash is required")
    reason = _visible_text(body.get("reason", ""), "reason", MAX_HUMAN_REASON, required=False)

    with SessionLocal() as db:
        rows = db.scalars(
            select(EvidenceRecord)
            .where(EvidenceRecord.tenant_id == approver_tenant_id)
            .order_by(EvidenceRecord.seq.asc())
        ).all()

    if not rows:
        raise HTTPException(status_code=404, detail="run evidence not found")
    if rows[-1].record_hash != tip_hash:
        raise HTTPException(status_code=409, detail="tip_hash is stale or does not match current chain tip")

    candidate = None
    for row in rows:
        if row.record_type != "decision.candidate":
            continue
        try:
            payload = json.loads(row.payload_json)
        except json.JSONDecodeError:
            continue
        if payload.get("run_id") == run_id:
            candidate = payload
            break

    if candidate is None:
        raise HTTPException(status_code=404, detail="decision candidate not found")
    requester_id = candidate.get("requester_id")
    if not requester_id:
        raise HTTPException(status_code=409, detail="requester identity missing from decision candidate")
    if approver_id == requester_id:
        raise HTTPException(status_code=403, detail="approver must differ from requester")

    candidate_fields = candidate.get("status_fields")
    if not isinstance(candidate_fields, dict):
        raise HTTPException(status_code=409, detail="decision candidate status fields are invalid")
    if set(candidate_fields) != set(STATUS_FIELDS) | {"EXECUTION_ALLOWED"}:
        raise HTTPException(status_code=409, detail="decision candidate status fields are invalid")
    approved_fields = {field: candidate_fields[field] for field in STATUS_FIELDS}
    if NinaIgorChain.derive_status(approved_fields) != candidate_fields["EXECUTION_ALLOWED"]:
        raise HTTPException(status_code=409, detail="decision candidate aggregate is inconsistent")
    approved_fields["HUMAN_GATE"] = "VERIFIED"
    if NinaIgorChain.derive_status(approved_fields) != "VERIFIED":
        raise HTTPException(status_code=409, detail="candidate is not eligible for human approval")

    record = append_record(
        approver_tenant_id,
        "human.approval",
        {
            "run_id": run_id,
            "tip_hash": tip_hash,
            "requester_id": requester_id,
            "approver_id": approver_id,
            "reason": reason,
            "status": "VERIFIED",
        },
    )
    return {
        "status": "VERIFIED",
        "run_id": run_id,
        "tip_hash": record["record_hash"],
        "approved_tip_hash": tip_hash,
        "record_id": record["id"],
        "record_type": "human.approval",
        "approver_id": approver_id,
    }


MAX_TEXT_CHARS = 8000
MAX_TASK_CHARS = MAX_TEXT_CHARS
MAX_URL_CHARS = 5000                                    # Stripe's own limit for success_url / cancel_url


def _checked_text(value, field: str, limit: int = MAX_TEXT_CHARS) -> str:
    """The one validator for free text that reaches the chain, a model or a third party: a string, bounded, without NUL
    and encodable as UTF-8 (a lone surrogate passes json.loads but later fails in the hash, the database or the JSON
    response - as a 500, sometimes after a side effect)."""
    if not isinstance(value, str):
        raise HTTPException(status_code=400, detail=f"{field} must be a string")
    if len(value) > limit:
        raise HTTPException(status_code=400, detail=f"{field} is too long (max {limit} characters)")
    if "\x00" in value:
        raise HTTPException(status_code=400, detail=f"{field} must not contain NUL characters")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise HTTPException(status_code=400, detail=f"{field} is not valid UTF-8 text") from None
    return value


def _task_from_body(body: dict) -> str:
    """task must be a bounded, UTF-8-encodable string (a surrogate or a list would otherwise reach the chain)."""
    task = body.get("task")
    if not isinstance(task, str) or not task.strip():
        raise HTTPException(status_code=400, detail="task is required")
    return _checked_text(task, "task")


def _url_from_body(body: dict, field: str, default: str) -> str:
    value = body.get(field)
    if not value:
        return default
    return _checked_text(value, field, MAX_URL_CHARS)


def _requested_tools(body: dict, default: list) -> list:
    tools = body.get("requested_tools", default)
    if not isinstance(tools, list):
        raise HTTPException(status_code=400, detail="requested_tools must be a list")
    for index, tool in enumerate(tools):
        _checked_text(tool, f"requested_tools[{index}]")
    return tools


MAX_HUMAN_ACTOR = 200
MAX_HUMAN_REASON = 1000
# Characters that render as nothing but are not whitespace/control/format characters: Hangul fillers and the blank
# Braille cell. (Combining marks are excluded by category, see _visible_text.)
_BLANK_LOOKING = frozenset("\u3164\uffa0\u115f\u1160\u2800")


def _visible_text(value, field: str, limit: int, required: bool) -> str:
    """A human-attested text must be a real string with visible characters. Whitespace (Z*), control/format/private
    characters (C*), combining marks (M*) and the blank-looking set above do not count: a name needs at least one
    other character."""
    if value is None and not required:
        return ""
    if not isinstance(value, str):
        raise HTTPException(status_code=400, detail=f"{field} must be a string")
    if len(value) > limit:
        raise HTTPException(status_code=400, detail=f"{field} is too long (max {limit})")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise HTTPException(status_code=400, detail=f"{field} is not valid UTF-8 text") from None
    visible = "".join(ch for ch in value if unicodedata.category(ch)[0] not in ("Z", "C", "M")
                      and ch not in _BLANK_LOOKING)
    if required and not visible:
        raise HTTPException(status_code=400, detail=f"{field} must contain visible characters")
    return value


def _review_from_body(body: dict) -> ReviewDecision:
    """Only the JSON boolean true approves. Strings such as "false" are NOT coerced (bool("false") is True).

    The gate is caller-attested: it records who the caller says approved, under the caller's tenant key.
    It is not an independent second factor (see docs/pipeline-bridge.md, fourth review).
    """
    approved = body.get("human_approved", False)
    if not isinstance(approved, bool):
        raise HTTPException(status_code=400, detail="human_approved must be a JSON boolean")
    actor = _visible_text(body.get("human_actor", ""), "human_actor", MAX_HUMAN_ACTOR, required=approved)
    reason = _visible_text(body.get("human_reason", ""), "human_reason", MAX_HUMAN_REASON, required=approved)
    return ReviewDecision(approved, actor, reason)


@app.post("/pipeline-run")
def create_pipeline_run(body: dict, x_api_key: str | None = Header(default=None)):
    """NINA -> OLLAMA -> EVIDENCE -> IGOR -> GATE -> REPLAY, anchored in the tenant evidence chain."""
    tenant_id = tenant_from_key(x_api_key)
    task_text = _task_from_body(body)
    requested_tools = _requested_tools(body, [])
    review = _review_from_body(body)
    try:
        return pipeline_bridge.run_pipeline(tenant_id, task_text, review, requested_tools=requested_tools)
    except pipeline_bridge.PipelineBusy as exc:
        raise HTTPException(status_code=429, detail=str(exc), headers={"Retry-After": "5"}) from exc
    except pipeline_bridge.PipelineNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/pipeline-session/{session_id}")
def get_pipeline_session(session_id: str, x_api_key: str | None = Header(default=None)):
    """Independent re-verification + replay of an anchored session (tenant-scoped; others get 404)."""
    tenant_id = tenant_from_key(x_api_key)
    try:
        trusted_key = pipeline_bridge.trusted_key_from_env()
        verification = pipeline_bridge.verify_anchor(tenant_id, session_id, trusted_key=trusted_key)
    except pipeline_bridge.PipelineNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError:
        raise HTTPException(status_code=404, detail="session not found") from None
    if verification["checks"] == {} and verification["status"] == "UNKNOWN":
        raise HTTPException(status_code=404, detail="session not found")
    replay = pipeline_bridge.replay_from_anchor(tenant_id, session_id)
    return {"session_id": session_id, "verification": verification, "replay": replay["events"],
            "replay_verification": pipeline_bridge.scope_replay(replay["verification"], verification)}


@app.post("/anchor/timestamp")
def create_anchor_timestamp(x_api_key: str | None = Header(default=None)):
    """RFC 3161 time-stamp of the tenant chain tip (external anchor). 503 unless fully configured."""
    tenant_id = tenant_from_key(x_api_key)
    try:
        return anchor_external.timestamp_tip(tenant_id)
    except anchor_external.AnchorNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except anchor_external.AnchorFailed as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/anchor/timestamp/{anchor_seq}")
def get_anchor_timestamp(anchor_seq: int, x_api_key: str | None = Header(default=None)):
    """Independent re-verification of one anchor.timestamp record (tenant-scoped)."""
    tenant_id = tenant_from_key(x_api_key)
    try:
        return anchor_external.verify_timestamp(tenant_id, anchor_seq)
    except anchor_external.AnchorNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ------------------------------------------------------------------ Agent Firewall + evidence verification
def _firewall_call(fn, *args):
    try:
        return fn(*args)
    except firewall.FirewallError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except firewall.FirewallNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except firewall.FirewallConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except firewall.FirewallUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (identity.IdentityError, cfr.CfrError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except cfr.CfrNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except cfr.CfrConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except cfr.CfrUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except identity.IdentityDenied as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except identity.IdentityConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except identity.IdentityUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/firewall/authorize")
def firewall_authorize(body: dict, x_api_key: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    return _firewall_call(firewall.authorize, tenant_id, body.get("agent_id"), body.get("action"), body.get("context"),
                          body.get("auth"))


@app.post("/firewall/approve")
def firewall_approve(body: dict, x_api_key: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    for field in ("request_id", "approver_id", "reason"):       # strings only: any other type is the firewall's 400
        if isinstance(body.get(field), str):
            _checked_text(body[field], field)
    return _firewall_call(firewall.approve, tenant_id, body.get("request_id"), body.get("approver_id"),
                          body.get("reason"), body.get("auth"))


@app.post("/firewall/consume")
def firewall_consume(body: dict, x_api_key: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    return _firewall_call(firewall.consume, tenant_id, body.get("request_id"), body.get("agent_id"),
                          body.get("action"), body.get("context"), body.get("auth"))


@app.post("/identity/enroll")
def identity_enroll(body: dict, x_api_key: str | None = Header(default=None),
                    x_enroll_token: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    return _firewall_call(identity.enroll, tenant_id, body.get("principal_id"), body.get("role"),
                          body.get("public_key"), x_enroll_token)


@app.post("/identity/revoke")
def identity_revoke(body: dict, x_api_key: str | None = Header(default=None),
                    x_enroll_token: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    return _firewall_call(identity.revoke, tenant_id, body.get("principal_id"), body.get("reason"), x_enroll_token)


@app.get("/identity/principals")
def identity_principals(x_api_key: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    return {"mode": _firewall_call(identity.auth_mode), "principals": _firewall_call(identity.principals, tenant_id)}


# ------------------------------------------------------------------ Code Forensics Range (CFR)
@app.post("/cfr/scenarios")
def cfr_register(body: dict, x_api_key: str | None = Header(default=None),
                 x_enroll_token: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    return _firewall_call(cfr.register_scenario, tenant_id, body.get("manifest"), x_enroll_token)


@app.post("/cfr/runs")
def cfr_issue(body: dict, x_api_key: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    return _firewall_call(cfr.issue_run, tenant_id, body.get("scenario_id"), body.get("participant_id"),
                          body.get("runner_id"))


@app.post("/cfr/results")
def cfr_submit(body: dict, x_api_key: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    submission = {k: v for k, v in body.items() if k != "auth"}
    return _firewall_call(cfr.submit_result, tenant_id, submission, body.get("auth"))


@app.post("/cfr/witness")
def cfr_witness(body: dict, x_api_key: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    observation = {k: v for k, v in body.items() if k != "auth"}
    return _firewall_call(cfr.submit_witness, tenant_id, observation, body.get("auth"))


@app.get("/cfr/results/{run_id}")
def cfr_result(run_id: str, x_api_key: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    return _firewall_call(cfr.result, tenant_id, run_id)


@app.get("/cfr/leaderboard/{scenario_id}")
def cfr_leaderboard(scenario_id: str, limit: int = 20, x_api_key: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    return _firewall_call(cfr.leaderboard, tenant_id, scenario_id, limit)


@app.get("/firewall/requests/{request_id}")
def firewall_request(request_id: str, x_api_key: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    return _firewall_call(firewall.state, tenant_id, request_id)


@app.post("/evidence/{record_id}/verify")
def verify_evidence(record_id: str, x_api_key: str | None = Header(default=None)):
    """PASS / FAIL / UNKNOWN for ONE record: recomputed hash, link to its predecessor, and the whole tenant
    chain. PASS means integrity inside the tenant chain only - not authorship, not truth, not external time."""
    tenant_id = tenant_from_key(x_api_key)
    chain = pipeline_bridge.load_chain(tenant_id)
    rec = next((r for r in chain if r["id"] == record_id), None)
    if rec is None:
        raise HTTPException(status_code=404, detail="evidence not found")
    own = {compute_record_hash(rec["tenant_id"], rec["seq"], rec["prev_hash"], rec["payload_json"], rec["record_type"]),
           compute_record_hash(rec["tenant_id"], rec["seq"], rec["prev_hash"], rec["payload_json"])}   # v2 or legacy v1
    own_ok = rec["record_hash"] in own
    ok, why = verify_chain(chain)
    state = "PASS" if (ok and own_ok) else "FAIL"
    return {"id": record_id, "seq": rec["seq"], "verification": state,
            "checks": {"record_hash": own_ok, "chain": ok},
            "reason": "" if state == "PASS" else (why if not ok else "record hash mismatch"),
            "proves": "integrity of this record inside the tenant chain; not authorship, truth or external time"}


@app.post("/decision-evaluate")
def decision_evaluate(body: dict, x_api_key: str | None = Header(default=None)):
    """Advisory decision vector from the hosted Jev model. Never a verification: the answer is recorded as
    `decision.fabric` evidence and returned with advisory_only=true. OFF unless OLA_JEV=on, because the state
    and questions are sent to api.typesafe.ai."""
    tenant_id = tenant_from_key(x_api_key)
    mode = os.getenv("OLA_JEV", "").strip().lower()
    if mode not in ("", "off", "on"):
        raise HTTPException(status_code=503, detail="OLA_JEV must be 'on' or 'off'")
    if mode != "on":
        raise HTTPException(status_code=503, detail="the Jev decision layer is not enabled (set OLA_JEV=on; "
                                                    "the request is sent to a hosted third-party model)")
    state = body.get("state")
    questions = body.get("questions")
    if state is None:
        raise HTTPException(status_code=400, detail="state is required")
    if not isinstance(questions, dict) or not questions:
        raise HTTPException(status_code=400, detail="questions object is required")
    try:                                              # strict JSON, valid Unicode, bounded: checked before any model call
        size = len(canonical_json(state).encode("utf-8")) + len(canonical_json(questions).encode("utf-8"))
    except (ValueError, UnicodeEncodeError, RecursionError, TypeError):
        raise HTTPException(status_code=400, detail="state and questions must be strict JSON with valid Unicode") from None
    if size > MAX_EVIDENCE_BYTES:
        raise HTTPException(status_code=400, detail=f"state and questions must be at most {MAX_EVIDENCE_BYTES} bytes")

    fabric = DecisionFabric()
    try:
        with pipeline_bridge._run_slot():
            result = fabric.evaluate(state=state, questions=questions)
    except pipeline_bridge.PipelineBusy as exc:
        raise HTTPException(status_code=429, detail=str(exc), headers={"Retry-After": "5"}) from exc
    except pipeline_bridge.PipelineNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    evidence = fabric.evidence(result)
    evidence["tenant_id"] = tenant_id
    record_type = "decision.fabric" if result.status == "READY" else "decision.fabric_blocked"
    append_record(tenant_id, record_type, evidence)
    return evidence


@app.post("/stripe/webhook")
async def stripe_webhook(request: Request, stripe_signature: str | None = Header(default=None)):
    if not stripe_signature:
        raise HTTPException(status_code=400, detail="missing Stripe signature")
    body = await request.body()
    # the handler is synchronous (DB + agent run): keep it off the event loop so one paid run cannot stall every request
    return await run_in_threadpool(process_checkout_event, body, stripe_signature)


@app.post("/business-invoice-run")
def create_business_invoice_run(body: dict, x_api_key: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    invoice = body.get("invoice")
    if not isinstance(invoice, dict):
        raise HTTPException(status_code=400, detail="invoice object is required")
    try:
        encoded = canonical_json(invoice)
        encoded_len = len(encoded.encode("utf-8"))
    except (ValueError, UnicodeEncodeError, RecursionError):
        raise HTTPException(status_code=400, detail="invoice must be strict JSON (no NaN/Infinity, valid Unicode)") from None
    if encoded_len > MAX_INVOICE_BYTES:
        raise HTTPException(status_code=400, detail=f"invoice must be at most {MAX_INVOICE_BYTES} bytes")
    task = "INVOICE_JSON:" + encoded
    try:
        return run_invoice_task(tenant_id, task)
    except (ValueError, TypeError, OverflowError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


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
        head = {"id": record.id, "tenant_id": record.tenant_id, "seq": record.seq, "record_type": record.record_type}
        tail = {"prev_hash": record.prev_hash, "record_hash": record.record_hash}
        payload_json = record.payload_json
    # A stored record must always be readable. The row is returned as a JSONResponse (no jsonable_encoder: it recurses
    # in Python and failed on deeply nested payloads); a payload that is not strict JSON any more (rows written before
    # NaN/Infinity were refused, or an unparsable one) comes back as its raw text instead of a 500.
    try:
        return JSONResponse({**head, "payload": json.loads(payload_json), **tail})
    except (ValueError, RecursionError):
        return JSONResponse({**head, "payload": None, "payload_error": "stored payload is not readable as strict JSON",
                             "payload_json": payload_json, **tail})
