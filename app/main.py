import json
import os
import urllib.error
import uuid
from pathlib import Path
from fastapi import FastAPI, Header, HTTPException, Request
from starlette.responses import FileResponse
from sqlalchemy import select
from .database import Base, engine, SessionLocal, install_append_only_triggers, append_evidence_atomic
from .models import Tenant, ApiKey, EvidenceRecord, StripeEvent
from .api_key_hashing import api_key_fingerprint
from .hashchain import GENESIS_HASH, canonical_json, compute_record_hash, verify_chain
from .agent_runtime import run_agent_task
from .agent_registry import build_agent_registry
from .execution_safety_gate import ExecutionDecision, ExecutionSafetyGate
from .business_runtime import run_invoice_task
from .nina import NinaOrchestrator, NinaTask, REGISTERED_TOOLS
from .nina_workflow import run_nina_workflow
from .nina_workflow_gate import approve_workflow, WorkflowApprovalRejected
from .workflow_engine import WorkflowPlanError
from .igor import IgorVerifier
from .replay import build_replay, verify_replay
from .human_gate import HumanGate, ReviewDecision
from .nina_igor import NinaIgorChain
from .decision_report import build_decision_report
from .chat_runtime import chat
from .revenue import create_checkout, retrieve_checkout, payment_verified
from .stripe_webhook import process_checkout_event

app = FastAPI(title="OLA Execution Gate")
REGISTERED_AGENT_IDS = frozenset(agent.agent_id for agent in build_agent_registry(391))
AGENT_RUN_GATE = ExecutionSafetyGate(allowed_actions={"run_agent_task"})
Base.metadata.create_all(bind=engine)
install_append_only_triggers()


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


def append_record(tenant_id, record_type, payload):
    return append_evidence_atomic(tenant_id, record_type, payload)


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


@app.get("/health")
def health():
    return {"status": "ok"}


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
        raise HTTPException(status_code=503, detail="checkout unavailable") from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail="checkout unavailable") from exc
    append_record(tenant_id, "revenue.checkout_created", {"session_id": session.get("id"), "task": task.strip(), "amount": session.get("amount_total")})
    return {"status": "READY_FOR_PAYMENT", "session_id": session.get("id"), "checkout_url": session.get("url")}


@app.get("/payment-success")
def payment_success(session_id: str, x_api_key: str | None = Header(default=None)):
    # A Checkout Session ID is not a credential: it travels in the redirect
    # URL, browser history, logs and Referer headers. Authenticate first, so
    # anonymous callers never reach Stripe or any tenant's evidence chain.
    tenant_id = tenant_from_key(x_api_key)
    try:
        session = retrieve_checkout(session_id)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise HTTPException(status_code=404, detail="order not found") from exc
        raise HTTPException(status_code=502, detail="payment lookup unavailable") from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail="payment lookup unavailable") from exc
    metadata = session.get("metadata") if isinstance(session, dict) else None
    if (not isinstance(metadata, dict)
            or session.get("id") != session_id
            or metadata.get("tenant_id") != tenant_id):
        # Same answer for a foreign, unbound or unknown session: no oracle.
        raise HTTPException(status_code=404, detail="order not found")
    if not payment_verified(session):
        append_record(tenant_id, "revenue.payment_blocked", {"session_id": session_id, "payment_status": session.get("payment_status"), "status": session.get("status")})
        return {"status": "BLOCK", "reason": "payment not verified", "session_id": session_id}
    task = session.get("metadata", {}).get("task")
    if not task:
        return {"status": "BLOCK", "reason": "paid session has no task", "session_id": session_id}

    # Different customers can buy the same audit task. Task text is not an
    # order identity: only a webhook result for THIS Checkout Session may be
    # returned to the caller. Legacy rows without checkout_session_id fail closed.
    with SessionLocal() as db:
        candidates = db.scalars(
            select(StripeEvent).where(
                StripeEvent.status == "COMPLETED",
                StripeEvent.task == task,
            )
        ).all()
        matches = []
        for candidate in candidates:
            if not candidate.result_json:
                continue
            try:
                recorded = json.loads(candidate.result_json)
            except (ValueError, TypeError):
                continue
            if (isinstance(recorded, dict)
                    and recorded.get("checkout_session_id") == session_id
                    and recorded.get("status") == "COMPLETED"):
                matches.append((candidate.run_id, recorded))

    if len(matches) > 1:
        raise HTTPException(status_code=409, detail="conflicting Checkout Session executions")
    if not matches:
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
        "run_id": matches[0][0],
        "result": matches[0][1],
    }


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
    if is_privileged_type(record_type):
        raise HTTPException(status_code=403, detail="reserved internal evidence type")
    payload = body.get("payload", {})
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="evidence payload must be a JSON object")
    if EVIDENCE_META_KEY in payload:
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
    expected_commit = os.getenv("OLA_RUNTIME_COMMIT")
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
