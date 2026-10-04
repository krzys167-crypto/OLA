import hashlib
import json
import os
import uuid
from pathlib import Path
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from starlette.responses import FileResponse
from sqlalchemy import select
from .database import Base, engine, SessionLocal, install_append_only_triggers
from .models import Tenant, ApiKey, EvidenceRecord, StripeEvent
from .hashchain import GENESIS_HASH, canonical_json, compute_record_hash, verify_chain
from .agent_runtime import run_agent_task
from .business_runtime import run_invoice_task
from .nina import NinaOrchestrator, NinaTask
from .igor import IgorVerifier
from .replay import build_replay, verify_replay
from .human_gate import HumanGate, ReviewDecision
from .nina_igor import NinaIgorChain
from .decision_report import build_decision_report
from .chat_runtime import chat
from .revenue import create_checkout, retrieve_checkout, payment_verified
from .stripe_webhook import process_checkout_event
from . import ambient, pipeline_bridge

app = FastAPI(title="OLA Execution Gate")
Base.metadata.create_all(bind=engine)
install_append_only_triggers()


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
    payload_json = canonical_json(payload)
    with SessionLocal() as db:
        last = db.scalar(
            select(EvidenceRecord)
            .where(EvidenceRecord.tenant_id == tenant_id)
            .order_by(EvidenceRecord.seq.desc())
        )
        seq = 0 if last is None else last.seq + 1
        prev_hash = GENESIS_HASH if last is None else last.record_hash
        record = EvidenceRecord(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            seq=seq,
            record_type=record_type,
            payload_json=payload_json,
            prev_hash=prev_hash,
            record_hash=compute_record_hash(tenant_id, seq, prev_hash, payload_json),
        )
        db.add(record)
        db.commit()
        return {
            "id": record.id,
            "tenant_id": record.tenant_id,
            "seq": record.seq,
            "record_hash": record.record_hash,
        }


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

    chain = [
        {
            "tenant_id": row.tenant_id,
            "seq": row.seq,
            "prev_hash": row.prev_hash,
            "record_hash": row.record_hash,
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
        if not isinstance(item, dict) or item.get("role") not in {"user", "assistant"} or not isinstance(item.get("content"), str):
            raise HTTPException(status_code=400, detail="invalid message")
        clean.append({"role": item["role"], "content": item["content"]})
    amb = _ambient_mode()
    result = chat(tenant_id, clean)
    task = next((m["content"] for m in reversed(clean) if m["role"] == "user"), "")
    if amb != "off" and result.get("status") == "VERIFIED" and isinstance(result.get("message"), str):
        return _ambient_apply(amb, background, tenant_id, "chat", task, result["message"], result, result.get("model"))
    return result


@app.post("/checkout")
def create_checkout_session(body: dict, x_api_key: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    task = body.get("task")
    if not isinstance(task, str) or not task.strip():
        raise HTTPException(status_code=400, detail="task is required")
    success_url = body.get("success_url") or "http://localhost:8000/payment-success"
    cancel_url = body.get("cancel_url") or "http://localhost:8000/"
    try:
        session = create_checkout(task.strip(), success_url, cancel_url, tenant_id)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"checkout creation failed: {exc.__class__.__name__}") from exc
    append_record(tenant_id, "revenue.checkout_created", {"session_id": session.get("id"), "task": task.strip(), "amount": session.get("amount_total")})
    return {"status": "READY_FOR_PAYMENT", "session_id": session.get("id"), "checkout_url": session.get("url")}


@app.get("/payment-success")
def payment_success(session_id: str):
    try:
        session = retrieve_checkout(session_id)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"payment lookup failed: {exc.__class__.__name__}") from exc
    tenant_id = session.get("metadata", {}).get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=403, detail="payment session has no tenant provenance")
    if not payment_verified(session):
        append_record(tenant_id, "revenue.payment_blocked", {"session_id": session_id, "payment_status": session.get("payment_status"), "status": session.get("status")})
        return {"status": "BLOCK", "reason": "payment not verified", "session_id": session_id}
    task = session.get("metadata", {}).get("task")
    if not task:
        return {"status": "BLOCK", "reason": "paid session has no task", "session_id": session_id}

    with SessionLocal() as db:
        completed = db.scalar(
            select(StripeEvent).where(
                StripeEvent.status == "COMPLETED",
                StripeEvent.task == task,
            )
        )

    if completed is None:
        return {
            "status": "PAYMENT_CONFIRMED_EXECUTION_PENDING",
            "session_id": session_id,
            "task": task,
            "execution": "STRIPE_WEBHOOK",
        }

    return {
        "status": "COMPLETED",
        "session_id": session_id,
        "task": task,
        "execution": "STRIPE_WEBHOOK",
        "run_id": completed.run_id,
        "result": json.loads(completed.result_json) if completed.result_json else None,
    }


@app.post("/evidence")
def create_evidence(body: dict, x_api_key: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    return append_record(
        tenant_id,
        body.get("record_type", "generic"),
        body.get("payload", {}),
    )


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
def create_agent_run(body: dict, background: BackgroundTasks, x_api_key: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    task = body.get("task")
    if not task:
        raise HTTPException(status_code=400, detail="task is required")
    amb = _ambient_mode()
    result = run_agent_task(tenant_id, task)
    if amb != "off" and result.get("status") == "VERIFIED":
        task_text = task if isinstance(task, str) else canonical_json(task)
        return _ambient_apply(amb, background, tenant_id, "agent-run", task_text, ambient.agent_output_text(result),
                              result, None)
    return result


@app.post("/nina-run")
def create_nina_run(body: dict, x_api_key: str | None = Header(default=None)):
    tenant_id, requester_id = identity_from_key(x_api_key)
    task_text = body.get("task")
    if not task_text:
        raise HTTPException(status_code=400, detail="task is required")
    requested_tools = body.get("requested_tools", ["safe_expression"])
    if not isinstance(requested_tools, list):
        raise HTTPException(status_code=400, detail="requested_tools must be a list")

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
    runtime_commit = os.getenv("OLA_RUNTIME_COMMIT")
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
            runtime_commit
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
    approved_fields = dict(candidate_fields)
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
            "reason": str(body.get("reason", "")),
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


@app.post("/pipeline-run")
def create_pipeline_run(body: dict, x_api_key: str | None = Header(default=None)):
    """NINA -> OLLAMA -> EVIDENCE -> IGOR -> GATE -> REPLAY, anchored in the tenant evidence chain."""
    tenant_id = tenant_from_key(x_api_key)
    task_text = body.get("task")
    if not isinstance(task_text, str) or not task_text.strip():
        raise HTTPException(status_code=400, detail="task is required")
    requested_tools = body.get("requested_tools", [])
    if not isinstance(requested_tools, list):
        raise HTTPException(status_code=400, detail="requested_tools must be a list")
    review = ReviewDecision(
        bool(body.get("human_approved", False)),
        str(body.get("human_actor", "")),
        str(body.get("human_reason", "")),
    )
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
            "replay_verification": replay["verification"]}


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
        return {
            "id": record.id,
            "tenant_id": record.tenant_id,
            "seq": record.seq,
            "record_type": record.record_type,
            "payload": json.loads(record.payload_json),
            "prev_hash": record.prev_hash,
            "record_hash": record.record_hash,
        }