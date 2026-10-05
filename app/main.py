import hashlib
import re
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
from .nina_igor import NinaIgorChain, STATUS_FIELDS
from .decision_report import build_decision_report
from .decision_fabric import DecisionFabric
from .chat_runtime import chat
from .revenue import create_checkout, retrieve_checkout, payment_verified
from .stripe_webhook import process_checkout_event
from . import ambient, anchor_external, cfr, firewall, identity, pipeline_bridge
from .payment_binding import checkout_result_matches

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

    return {
        "status": "COMPLETED",
        "session_id": session_id,
        "task": task,
        "execution": "STRIPE_WEBHOOK",
        "run_id": completed.run_id,
        "result": bound_result,
    }


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
    return _firewall_call(cfr.issue_run, tenant_id, body.get("scenario_id"), body.get("participant_id"))


@app.post("/cfr/results")
def cfr_submit(body: dict, x_api_key: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    submission = {k: v for k, v in body.items() if k != "auth"}
    return _firewall_call(cfr.submit_result, tenant_id, submission, body.get("auth"))


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
    own_hash = compute_record_hash(rec["tenant_id"], rec["seq"], rec["prev_hash"], rec["payload_json"])
    ok, why = verify_chain(chain)
    state = "PASS" if (ok and own_hash == rec["record_hash"]) else "FAIL"
    return {"id": record_id, "seq": rec["seq"], "verification": state,
            "checks": {"record_hash": own_hash == rec["record_hash"], "chain": ok},
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
