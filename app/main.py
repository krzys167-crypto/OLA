import hashlib
import json
import os
import re
import uuid
import time
from pathlib import Path
from fastapi import FastAPI, Header, HTTPException, Request
from starlette.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from .database import Base, engine, SessionLocal, install_append_only_triggers, ensure_evidence_hash_schema
from .api_key_crypto import hash_api_key, KeyConfigurationError
from .models import Tenant, ApiKey, EvidenceRecord, StripeEvent
from .hashchain import GENESIS_HASH, canonical_json, compute_record_hash, verify_chain
from .agent_runtime import run_agent_task
from .business_runtime import run_invoice_task
from .nina import NinaOrchestrator, NinaTask
from .igor import IgorVerifier
from .replay import build_replay, verify_replay
from .control_plane import get_overview, get_run_detail
from .human_gate import HumanGate, ReviewDecision
from .nina_igor import NinaIgorChain
from .decision_report import build_decision_report
from .decision_report_v2 import build_decision_report_v2
from .execution_binding import prepare_binding, capture_source, validate_review_subject, digest, review_state
from .chat_runtime import chat
from .revenue import create_checkout, retrieve_checkout, payment_verified
from .stripe_webhook import process_checkout_event

app = FastAPI(title="OLA Execution Gate")
Base.metadata.create_all(bind=engine)
ensure_evidence_hash_schema()
install_append_only_triggers()


def identity_from_key(raw_key):
    if not raw_key:
        raise HTTPException(status_code=401, detail="missing API key")
    try:
        key_hash = hash_api_key(raw_key)
    except ValueError:
        raise HTTPException(status_code=401, detail="invalid API key") from None
    except KeyConfigurationError:
        # A missing pepper is a deployment defect, never a bad user credential.
        raise HTTPException(status_code=503, detail="OLA API authentication is not configured") from None
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
        # Reserve the SQLite writer before reading the hash-chain tip.
        # Without this reservation concurrent agent/audit writes can choose
        # the same sequence number and fail with an unhandled unique-key race.
        db.connection().exec_driver_sql("BEGIN IMMEDIATE")
        last = db.scalar(
            select(EvidenceRecord)
            .where(EvidenceRecord.tenant_id == tenant_id)
            .order_by(EvidenceRecord.seq.desc())
        )
        seq = 0 if last is None else last.seq + 1
        prev_hash = GENESIS_HASH if last is None else last.record_hash
        record_id = str(uuid.uuid4())
        record = EvidenceRecord(
            id=record_id,
            tenant_id=tenant_id,
            seq=seq,
            record_type=record_type,
            payload_json=payload_json,
            prev_hash=prev_hash,
            hash_version=2,
            record_hash=compute_record_hash(
                tenant_id, seq, prev_hash, payload_json,
                record_id=record_id, record_type=record_type, hash_version=2,
            ),
        )
        db.add(record)
        db.commit()
        return {
            "id": record.id,
            "tenant_id": record.tenant_id,
            "seq": record.seq,
            "hash_version": record.hash_version,
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

    # Verify the *complete* tenant chain, not only the five new audit records:
    # genesis/prev_hash validation must start at sequence zero even on repeated audits.
    with SessionLocal() as db:
        rows = db.scalars(
            select(EvidenceRecord)
            .where(EvidenceRecord.tenant_id == tenant_id)
            .order_by(EvidenceRecord.seq.asc())
        ).all()
    audit_rows = [row for row in rows if row.id in set(evidence_ids)]

    chain = [
        {
            "id": row.id,
            "tenant_id": row.tenant_id,
            "seq": row.seq,
            "prev_hash": row.prev_hash,
            "record_hash": row.record_hash,
            "record_type": row.record_type,
            "hash_version": row.hash_version,
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
            "evidence_count": len(audit_rows),
            "evidence_ids": evidence_ids,
            "reason": reason,
            "verification_scope": "CONTROLLED_SIMULATION",
        }

    return {
        "audit_id": audit_id,
        "status": "VERIFIED",
        "outcome": "recovered_and_verified",
        "evidence_count": len(audit_rows),
        "evidence_ids": evidence_ids,
        "reason": reason,
        "verification_scope": "CONTROLLED_SIMULATION",
    }


@app.get("/auth/session")
def get_current_operator(x_api_key: str | None = Header(default=None)):
    """Read-only credential check. Never issues credentials or exposes raw keys."""
    tenant_id, key_id = identity_from_key(x_api_key)
    return {"authenticated": True, "tenant_id": tenant_id, "credential_id": key_id, "scope": "OLA_CORE"}


@app.get("/control/overview")
def command_center_overview(x_api_key: str | None = Header(default=None)):
    """Read-only, tenant-scoped operational truth. Does not authorize host commands."""
    tenant_id = tenant_from_key(x_api_key)
    return get_overview(tenant_id)


@app.get("/control/runs/{run_id}")
def command_center_run(run_id: str, x_api_key: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    result = get_run_detail(tenant_id, run_id)
    if result is None:
        raise HTTPException(status_code=404, detail="run not found")
    return result


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

    # Task text is NOT a payment/session identifier: identical customer tasks
    # can exist across tenants. Return execution proof only for this checkout.
    completed_run_id = None
    completed_result = None
    with SessionLocal() as db:
        candidates = db.scalars(
            select(StripeEvent).where(
                StripeEvent.status == "COMPLETED",
                StripeEvent.task == task,
            )
        ).all()
        for candidate in candidates:
            if not candidate.result_json or not candidate.run_id:
                continue
            try:
                stored = json.loads(candidate.result_json)
            except (TypeError, json.JSONDecodeError):
                continue
            if (
                isinstance(stored, dict)
                and stored.get("checkout_session_id") == session_id
                and stored.get("ola_run_id") == candidate.run_id
            ):
                completed_run_id = candidate.run_id
                completed_result = stored
                break

    if completed_run_id is None:
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
        "run_id": completed_run_id,
        "result": completed_result,
    }


@app.post("/evidence")
def create_evidence(body: dict, x_api_key: str | None = Header(default=None)):
    tenant_id = tenant_from_key(x_api_key)
    record_type = body.get("record_type", "generic")
    if not isinstance(record_type, str) or not (
        record_type == "generic"
        or re.fullmatch(r"user\.[A-Za-z][A-Za-z0-9_.-]{0,90}", record_type)
    ):
        raise HTTPException(status_code=400, detail="record_type must be generic or user.*")
    payload = body.get("payload", {})
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="evidence payload must be an object")
    # Caller-generated metadata cannot impersonate NINA/IGOR runtime provenance.
    reserved = {
        "run_id", "commit", "task", "result", "tool_output",
        "provider", "model", "invocation_type", "response_ids",
        "status_fields", "requester_id", "approver_id",
        "candidate_status", "human_approved", "record_hash", "prev_hash",
    }
    if reserved.intersection(payload):
        raise HTTPException(status_code=400, detail="reserved system evidence field")
    if len(canonical_json(payload).encode("utf-8")) > 65536:
        raise HTTPException(status_code=413, detail="evidence payload too large")
    return append_record(tenant_id, record_type, payload)


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
    return run_agent_task(tenant_id, task, allowed_tools=body.get("requested_tools", []))


@app.post("/nina-run")
def create_nina_run(body: dict, x_api_key: str | None = Header(default=None)):
    tenant_id, requester_id = identity_from_key(x_api_key)
    task_text = body.get("task")
    if not task_text:
        raise HTTPException(status_code=400, detail="task is required")
    requested_tools = body.get("requested_tools", [])
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

    try:
        execution_binding = prepare_binding(tenant_id, requester_id, task_text, requested_tools)
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    # Capture the policy decision before invoking the executor.
    append_record(tenant_id, "execution.authorization", {
        "task_id": nina_task.task_id, "execution_binding": execution_binding,
    })
    runtime = nina.execute(nina_task)
    source_after = capture_source()
    if source_after != execution_binding["source"]:
        append_record(tenant_id, "execution.binding_failed", {"task_id": nina_task.task_id})
        raise HTTPException(status_code=409, detail="source changed during execution; result blocked")
    run_id = runtime["runtime"]["run_id"]
    execution = runtime["runtime"].get("execution", [])
    runtime_commit = execution_binding["source"]["sha"]
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
            "hash_version": row.hash_version,
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
        execution_binding=execution_binding,
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
    report_v2 = build_decision_report_v2(
        legacy_report=report, source_sha=runtime_commit,
        evidence_root=record_dicts[-1]["record_hash"] if record_dicts else None,
        policy_digest=execution_binding["policy_digest"], human_approval_digest=None,
    )
    review_issued_at = int(time.time())
    candidate_record = append_record(
        tenant_id,
        "decision.candidate",
        {
            "run_id": run_id,
            "requester_id": requester_id,
            "status_fields": status_fields,
            "candidate_status": derived_status,
            "decision_report_v2": report_v2,
            "execution_binding": execution_binding,
            "review_issued_at": review_issued_at,
            "review_expires_at": review_issued_at + 900,
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
        "decision_report_v2": report_v2,
        "review_scope": "review-result",
        "review_expires_at": review_issued_at + 900,
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

    # SQLite transaction obtains a write reservation BEFORE inspecting any
    # evidence. Otherwise parallel reviewers may both pass eligibility and
    # race in the non-atomic append_record() helper.
    with SessionLocal() as db:
        try:
            db.connection().exec_driver_sql("BEGIN IMMEDIATE")
        except OperationalError as exc:
            raise HTTPException(status_code=409, detail="approval transaction busy") from exc

        rows = db.scalars(
            select(EvidenceRecord)
            .where(EvidenceRecord.tenant_id == approver_tenant_id)
            .order_by(EvidenceRecord.seq.asc())
        ).all()

        if not rows:
            raise HTTPException(status_code=404, detail="run evidence not found")

        chain = [
            {
                "id": row.id,
                "tenant_id": row.tenant_id,
                "seq": row.seq,
                "prev_hash": row.prev_hash,
                "record_hash": row.record_hash,
                "record_type": row.record_type,
                "hash_version": row.hash_version,
                "payload_json": row.payload_json,
            }
            for row in rows
        ]
        chain_ok, _ = verify_chain(chain)
        if not chain_ok:
            raise HTTPException(status_code=409, detail="evidence chain verification failed")
        if rows[-1].record_hash != tip_hash:
            raise HTTPException(status_code=409, detail="tip_hash is stale or does not match current chain tip")

        for row in rows:
            if row.record_type != "human.approval":
                continue
            try:
                payload = json.loads(row.payload_json)
            except (TypeError, json.JSONDecodeError):
                continue
            if isinstance(payload, dict) and payload.get("run_id") == run_id:
                raise HTTPException(status_code=409, detail="run already approved")

        candidate = None
        for row in reversed(rows):
            if row.record_type != "decision.candidate":
                continue
            try:
                payload = json.loads(row.payload_json)
            except (TypeError, json.JSONDecodeError):
                continue
            if isinstance(payload, dict) and payload.get("run_id") == run_id:
                candidate = payload
                candidate_previous_hash = row.prev_hash
                break

        if candidate is None:
            raise HTTPException(status_code=404, detail="decision candidate not found")
        requester_id = candidate.get("requester_id")
        if not requester_id:
            raise HTTPException(status_code=409, detail="requester identity missing from decision candidate")
        if approver_id == requester_id:
            raise HTTPException(status_code=403, detail="approver must differ from requester")

        candidate_fields = candidate.get("status_fields")
        # EXECUTION_ALLOWED is a derived report field, not an input status.
        # Reject missing, extra, or forged fields before making any approval.
        required_fields = {"RUNTIME", "EVIDENCE", "REPLAY_INTEGRITY", "POLICY", "HUMAN_GATE"}
        if not isinstance(candidate_fields, dict) or set(candidate_fields) != required_fields | {"EXECUTION_ALLOWED"}:
            raise HTTPException(status_code=409, detail="decision candidate status fields are invalid")
        gate_fields = {name: candidate_fields[name] for name in required_fields}
        derived = NinaIgorChain.derive_status(gate_fields)
        if (candidate_fields["EXECUTION_ALLOWED"] != derived
                or candidate.get("candidate_status") != derived
                or gate_fields["HUMAN_GATE"] != "REVIEW"):
            raise HTTPException(status_code=409, detail="decision candidate status is inconsistent")
        approved_fields = {**gate_fields, "HUMAN_GATE": "VERIFIED"}
        if derived != "REVIEW" or NinaIgorChain.derive_status(approved_fields) != "VERIFIED":
            raise HTTPException(status_code=409, detail="candidate is not eligible for human approval")

        bound_report = candidate.get("decision_report_v2", {})
        if bound_report.get("bindings", {}).get("evidence_root") != candidate_previous_hash:
            raise HTTPException(status_code=409, detail="report evidence root differs from candidate predecessor")
        if body.get("scope") != "review-result":
            raise HTTPException(status_code=400, detail="scope must be review-result")
        try:
            binding = validate_review_subject(candidate, approver_tenant_id, requester_id,
                                              body.get("report_sha256"))
        except (ValueError, OSError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        approval_payload = {
            "tenant_id": approver_tenant_id,
            "run_id": run_id,
            "tip_hash": tip_hash,
            "requester_id": requester_id,
            "approver_id": approver_id,
            "reason": str(body.get("reason", "")),
            "status": "APPROVED",
            "assurance": "UNKNOWN",
            "scope": "review-result",
            "report_sha256": body["report_sha256"],
            "source_sha": binding["source"]["sha"],
            "policy_digest": binding["policy_digest"],
            "parameters_digest": binding["parameters_digest"],
            "issued_at": int(time.time()),
            "expires_at": candidate["review_expires_at"],
        }
        approval_digest = digest(approval_payload)
        payload_json = canonical_json(approval_payload)
        record_id = str(uuid.uuid4())
        new_seq = rows[-1].seq + 1
        record_hash = compute_record_hash(
            approver_tenant_id, new_seq, tip_hash, payload_json,
            record_id=record_id, record_type="human.approval", hash_version=2,
        )
        db.add(EvidenceRecord(
            id=record_id,
            tenant_id=approver_tenant_id,
            seq=new_seq,
            record_type="human.approval",
            hash_version=2,
            payload_json=payload_json,
            prev_hash=tip_hash,
            record_hash=record_hash,
        ))
        db.commit()

    return {
        "status": "APPROVED",
        "assurance": "UNKNOWN",
        "scope": "review-result",
        "report_sha256": body["report_sha256"],
        "human_approval_digest": approval_digest,
        "expires_at": approval_payload["expires_at"],
        "production_eligible": False,
        "run_id": run_id,
        "tip_hash": record_hash,
        "approved_tip_hash": tip_hash,
        "record_id": record_id,
        "record_type": "human.approval",
        "approver_id": approver_id,
    }


@app.get("/nina-run/{run_id}/approval")
def get_nina_review(run_id: str, authorization: str | None = Header(default=None)):
    tenant_id, _ = bearer_identity(authorization)
    with SessionLocal() as db:
        rows = db.scalars(select(EvidenceRecord).where(
            EvidenceRecord.tenant_id == tenant_id).order_by(EvidenceRecord.seq.asc())).all()
        chain = [{name: getattr(row, name) for name in (
            "id", "tenant_id", "seq", "prev_hash", "record_hash", "record_type",
            "hash_version", "payload_json")} for row in rows]
    state, approval_digest = review_state(chain, run_id)
    return {"status": state, "human_approval_digest": approval_digest,
            "scope": "review-result", "assurance": "UNKNOWN", "production_eligible": False}


@app.post("/nina-run/{run_id}/approval/revoke")
def revoke_nina_review(run_id: str, body: dict,
                       authorization: str | None = Header(default=None)):
    tenant_id, actor_id = bearer_identity(authorization)
    with SessionLocal() as db:
        try:
            db.connection().exec_driver_sql("BEGIN IMMEDIATE")
        except OperationalError as exc:
            raise HTTPException(status_code=409, detail="revocation transaction busy") from exc
        rows = db.scalars(select(EvidenceRecord).where(
            EvidenceRecord.tenant_id == tenant_id).order_by(EvidenceRecord.seq.asc())).all()
        chain = [{name: getattr(row, name) for name in (
            "id", "tenant_id", "seq", "prev_hash", "record_hash", "record_type",
            "hash_version", "payload_json")} for row in rows]
        if not verify_chain(chain)[0]:
            raise HTTPException(status_code=409, detail="invalid evidence chain")
        approvals = [json.loads(row.payload_json) for row in rows
                     if row.record_type == "human.approval"
                     and json.loads(row.payload_json).get("run_id") == run_id]
        if not approvals:
            raise HTTPException(status_code=404, detail="approval not found")
        approval = approvals[-1]
        if approval.get("approver_id") != actor_id:
            raise HTTPException(status_code=403, detail="only original approver may revoke")
        approval_digest = digest(approval)
        if body.get("human_approval_digest") != approval_digest:
            raise HTTPException(status_code=409, detail="approval digest mismatch")
        payload = {"run_id": run_id, "human_approval_digest": approval_digest,
                   "actor_id": actor_id, "revoked_at": int(time.time())}
        encoded = canonical_json(payload)
        record_id, seq, previous = str(uuid.uuid4()), rows[-1].seq + 1, rows[-1].record_hash
        record_hash = compute_record_hash(tenant_id, seq, previous, encoded,
            record_id=record_id, record_type="human.approval.revoked", hash_version=2)
        db.add(EvidenceRecord(id=record_id, tenant_id=tenant_id, seq=seq,
            prev_hash=previous, record_hash=record_hash, record_type="human.approval.revoked",
            hash_version=2, payload_json=encoded))
        db.commit()
    return {"status": "REVOKED", "human_approval_digest": approval_digest,
            "assurance": "UNKNOWN", "production_eligible": False}


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
            "hash_version": record.hash_version,
            "payload": json.loads(record.payload_json),
            "prev_hash": record.prev_hash,
            "record_hash": record.record_hash,
        }