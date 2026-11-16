"""Order-bound Human Gate tests for the paid sandbox workflow."""
import hashlib
import json
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.api_key_hashing import api_key_fingerprint
from app.database import SessionLocal, append_evidence_atomic
from app.hashchain import trusted_record
from app.main import app
from app.models import ApiKey, CheckoutOrder, CheckoutOrderControl, Tenant, EvidenceRecord, CheckoutExecutionJob


def test_paid_order_approval_route_is_registered():
    routes = {route.path for route in app.routes}
    assert "/checkout-orders/{order_id}/approve" in routes


def _seed_paid_order(monkeypatch, *, include_checkout_proof=True):
    monkeypatch.setenv("OLA_RUNTIME_COMMIT", "a" * 40)
    tenant_id = str(uuid.uuid4())
    requester_id = str(uuid.uuid4())
    approver_id = str(uuid.uuid4())
    reviewer_id = str(uuid.uuid4())
    requester_key = f"requester-{uuid.uuid4()}"
    approver_key = f"approver-{uuid.uuid4()}"
    reviewer_key = f"reviewer-{uuid.uuid4()}"
    idempotency_key = f"paid-order-{uuid.uuid4().hex}"
    order_id = str(uuid.uuid4())
    session_id = f"cs_test_{uuid.uuid4().hex}"
    event_id = f"evt_test_{uuid.uuid4().hex}"
    task = "Run the paid OLA runtime audit for a synthetic workflow."
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="paid-order-approval"))
        db.add_all([
            ApiKey(id=requester_id, tenant_id=tenant_id,
                   key_hash=api_key_fingerprint(requester_key)),
            ApiKey(id=approver_id, tenant_id=tenant_id,
                   key_hash=api_key_fingerprint(approver_key), role="execution_approver"),
            ApiKey(id=reviewer_id, tenant_id=tenant_id,
                   key_hash=api_key_fingerprint(reviewer_key), role="report_reviewer"),
        ])
        db.add(CheckoutOrder(
            id=order_id,
            tenant_id=tenant_id,
            idempotency_key_hash=hashlib.sha256(idempotency_key.encode()).hexdigest(),
            request_hash=hashlib.sha256(task.encode()).hexdigest(),
            task=task,
            status="PAID_PENDING_REVIEW",
            stripe_session_id=session_id,
            checkout_url="https://checkout.stripe.test/session",
            payment_event_id=event_id,
        ))
        db.add(CheckoutOrderControl(
            id=str(uuid.uuid4()), order_id=order_id, tenant_id=tenant_id,
            requester_id=requester_id, status="PAID_PENDING_REVIEW",
        ))
        db.commit()

    checkout_proof = None
    if include_checkout_proof:
        checkout_proof = append_evidence_atomic(tenant_id, "stripe.checkout_created", {
            "ola_order_id": order_id,
            "tenant_id": tenant_id,
            "requester_id": requester_id,
            "checkout_session_id": session_id,
            "request_hash": hashlib.sha256(task.encode()).hexdigest(),
        }, deduplicate=True)
    proof = append_evidence_atomic(tenant_id, "stripe.payment_confirmed", {
        "ola_order_id": order_id,
        "stripe_event_id": event_id,
        "checkout_session_id": session_id,
        "offer": "ola-execution-audit",
        "product": "OLA Execution Audit",
        "amount_total": 9900,
        "currency": "eur",
        "request_hash": hashlib.sha256(task.encode()).hexdigest(),
        "execution_authorized": False,
        "review_required": True,
    })
    payment_result = {
        "status": "PAID_PENDING_REVIEW",
        "event_id": event_id,
        "order_id": order_id,
        "checkout_session_id": session_id,
        "payment": "CONFIRMED",
        "ola_status": "NOT_STARTED",
        "ola_run_id": None,
        "payment_evidence_id": proof["id"],
        "execution_authorized": False,
        "next_gate": "HUMAN_REVIEW",
    }
    with SessionLocal() as db:
        order = db.get(CheckoutOrder, order_id)
        order.payment_result_json = json.dumps(payment_result)
        control = db.scalar(select(CheckoutOrderControl).where(
            CheckoutOrderControl.order_id == order_id
        ))
        control.payment_evidence_id = proof["id"]
        db.commit()
        tip_hash = db.scalar(
            select(EvidenceRecord.record_hash)
            .where(EvidenceRecord.tenant_id == tenant_id)
            .order_by(EvidenceRecord.seq.desc())
        )
    return {
        "tenant_id": tenant_id,
        "requester_id": requester_id,
        "approver_id": approver_id,
        "reviewer_id": reviewer_id,
        "requester_key": requester_key,
        "approver_key": approver_key,
        "reviewer_key": reviewer_key,
        "idempotency_key": idempotency_key,
        "order_id": order_id,
        "session_id": session_id,
        "task": task,
        "payment_evidence_id": proof["id"],
        "checkout_evidence_id": checkout_proof["id"] if checkout_proof else None,
        "tip_hash": tip_hash,
    }


def checkout_proof_hash(tenant_id, evidence_id):
    with SessionLocal() as db:
        row = db.scalar(select(EvidenceRecord).where(
            EvidenceRecord.tenant_id == tenant_id,
            EvidenceRecord.id == evidence_id,
        ))
        return row.record_hash if row else None


def _approve(ctx, *, key=None, tip_hash=None, reason="Reviewed payment and order scope"):
    return TestClient(app).post(
        f"/checkout-orders/{ctx['order_id']}/approve",
        headers={"Authorization": f"Bearer {key or ctx['approver_key']}"},
        json={"tip_hash": tip_hash or ctx["tip_hash"], "reason": reason},
    )


def test_paid_order_approval_requires_second_identity_and_binds_payment_and_tip(monkeypatch):
    ctx = _seed_paid_order(monkeypatch)
    response = _approve(ctx)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "APPROVED_FOR_EXECUTION"
    assert body["execution"] == "QUEUED"
    assert body["next_gate"] == "EXECUTION_DISPATCH"
    assert body["production_authorized"] is False
    assert body["deployment_authorized"] is False

    with SessionLocal() as db:
        control = db.scalar(select(CheckoutOrderControl).where(
            CheckoutOrderControl.order_id == ctx["order_id"]
        ))
        approval = db.scalar(select(EvidenceRecord).where(
            EvidenceRecord.tenant_id == ctx["tenant_id"],
            EvidenceRecord.id == body["approval_record_id"],
        ))
        assert control.status == "APPROVED_FOR_EXECUTION"
        assert control.approver_id == ctx["approver_id"]
        assert control.approved_tip_hash == ctx["tip_hash"]
        record = {
            "id": approval.id,
            "tenant_id": approval.tenant_id,
            "seq": approval.seq,
            "prev_hash": approval.prev_hash,
            "record_hash": approval.record_hash,
            "record_type": approval.record_type,
            "payload_json": approval.payload_json,
        }
        assert trusted_record(record)
        payload = json.loads(approval.payload_json)
        assert payload["payment_evidence_id"] == ctx["payment_evidence_id"]
        assert payload["checkout_evidence_id"] == ctx["checkout_evidence_id"]
        assert payload["checkout_evidence_hash"] == checkout_proof_hash(ctx["tenant_id"], ctx["checkout_evidence_id"])
        assert payload["approved_tip_hash"] == ctx["tip_hash"]
        assert payload["requester_id"] == ctx["requester_id"]
        assert payload["approver_id"] == ctx["approver_id"]
        job = db.scalar(select(CheckoutExecutionJob).where(
            CheckoutExecutionJob.order_id == ctx["order_id"]
        ))
        assert job is not None
        assert job.tenant_id == ctx["tenant_id"]
        assert job.status == "QUEUED"
        assert job.attempt_count == 0
        assert job.approval_record_hash == body["approval_record_hash"]


def test_paid_order_requester_cannot_approve_own_order(monkeypatch):
    ctx = _seed_paid_order(monkeypatch)
    response = _approve(ctx, key=ctx["requester_key"])
    assert response.status_code == 403, response.text


def test_paid_order_approval_rejects_stale_evidence_tip(monkeypatch):
    ctx = _seed_paid_order(monkeypatch)
    response = _approve(ctx, tip_hash="0" * 64)
    assert response.status_code == 409, response.text


def test_paid_order_approval_rejects_payment_evidence_for_different_task(monkeypatch):
    ctx = _seed_paid_order(monkeypatch)
    with SessionLocal() as db:
        order = db.get(CheckoutOrder, ctx["order_id"])
        order.request_hash = hashlib.sha256(b"another task").hexdigest()
        db.commit()
    response = _approve(ctx)
    assert response.status_code == 409, response.text
    assert "checkout provenance" in response.text.lower()


def test_paid_order_approval_rejects_empty_reason(monkeypatch):
    ctx = _seed_paid_order(monkeypatch)
    response = _approve(ctx, reason="   ")
    assert response.status_code == 400, response.text


def test_paid_order_approval_is_one_time(monkeypatch):
    ctx = _seed_paid_order(monkeypatch)
    first = _approve(ctx)
    second = _approve(ctx)
    assert first.status_code == 200, first.text
    assert second.status_code == 409, second.text


def test_paid_order_approval_is_tenant_scoped(monkeypatch):
    ctx = _seed_paid_order(monkeypatch)
    other_tenant = str(uuid.uuid4())
    other_key = f"other-tenant-{uuid.uuid4()}"
    with SessionLocal() as db:
        db.add(Tenant(id=other_tenant, name="other-tenant"))
        db.add(ApiKey(
            id=str(uuid.uuid4()), tenant_id=other_tenant,
            key_hash=api_key_fingerprint(other_key),
        ))
        db.commit()
    response = _approve(ctx, key=other_key)
    assert response.status_code == 404, response.text


def test_paid_order_approval_rejects_legacy_order_without_requester_provenance(monkeypatch):
    ctx = _seed_paid_order(monkeypatch)
    with SessionLocal() as db:
        db.query(CheckoutOrderControl).filter(
            CheckoutOrderControl.order_id == ctx["order_id"]
        ).delete()
        db.commit()
    response = _approve(ctx)
    assert response.status_code == 409, response.text


def test_paid_order_approval_requires_trusted_checkout_requester_proof(monkeypatch):
    # The DB control row alone is not enough: requester identity and reserved
    # task must have an immutable, server-sealed checkout evidence record.
    ctx = _seed_paid_order(monkeypatch, include_checkout_proof=False)
    response = _approve(ctx)
    assert response.status_code == 409, response.text
    assert "checkout provenance" in response.text.lower()


def test_paid_order_approval_concurrent_replay_cannot_create_two_approvals(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    ctx = _seed_paid_order(monkeypatch)
    def submit(_):
        response = _approve(ctx)
        return response.status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(submit, range(2)))
    assert sorted(statuses) == [200, 409], statuses


def test_tenant_api_cannot_forge_stripe_payment_proof(monkeypatch):
    ctx = _seed_paid_order(monkeypatch)
    response = TestClient(app).post(
        "/evidence",
        headers={"X-API-Key": ctx["requester_key"]},
        json={
            "record_type": "stripe.payment_confirmed",
            "payload": {
                "ola_order_id": ctx["order_id"],
                "checkout_session_id": "cs_test_forged",
            },
        },
    )
    assert response.status_code == 403, response.text


def test_tenant_api_cannot_forge_revenue_execution_proof(monkeypatch):
    ctx = _seed_paid_order(monkeypatch)
    response = TestClient(app).post(
        "/evidence",
        headers={"X-API-Key": ctx["requester_key"]},
        json={
            "record_type": "revenue.execution_completed",
            "payload": {
                "ola_order_id": ctx["order_id"],
                "status": "EXECUTED_REVIEW_REQUIRED",
                "report_digest": "f" * 64,
            },
        },
    )
    assert response.status_code == 403, response.text


def test_paid_order_approval_blocks_without_verified_runtime_source(monkeypatch):
    ctx = _seed_paid_order(monkeypatch)
    monkeypatch.delenv("OLA_RUNTIME_COMMIT", raising=False)
    monkeypatch.setenv("OLA_REQUIRE_BUILD_INFO", "1")
    response = _approve(ctx)
    assert response.status_code == 409, response.text


def test_checkout_webhook_success_redirect_and_human_approval_form_one_bound_chain(monkeypatch):
    import hmac
    import time
    from app import main as main_module
    from app import stripe_webhook as webhook_module

    monkeypatch.setenv("OLA_RUNTIME_COMMIT", "b" * 40)
    monkeypatch.setenv("OLA_PUBLIC_BASE_URL", "http://localhost:8000")
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_order_flow_test")
    monkeypatch.setenv("OLA_STRIPE_PRICE_ID", "price_test_ola")

    tenant_id = str(uuid.uuid4())
    requester_id = str(uuid.uuid4())
    approver_id = str(uuid.uuid4())
    requester_key = f"full-flow-requester-{uuid.uuid4()}"
    approver_key = f"full-flow-approver-{uuid.uuid4()}"
    task = "Verify a synthetic customer workflow and produce an evidence report."
    session_id = f"cs_test_{uuid.uuid4().hex}"
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="full-paid-order-flow"))
        db.add_all([
            ApiKey(id=requester_id, tenant_id=tenant_id,
                   key_hash=api_key_fingerprint(requester_key)),
            ApiKey(id=approver_id, tenant_id=tenant_id,
                   key_hash=api_key_fingerprint(approver_key), role="execution_approver"),
        ])
        db.commit()

    monkeypatch.setattr(main_module, "create_checkout", lambda *args, **kwargs: {
        "id": session_id,
        "url": "https://checkout.stripe.test/full-flow",
    })
    client = TestClient(app)
    checkout = client.post(
        "/checkout",
        headers={
            "X-API-Key": requester_key,
            "Idempotency-Key": "full-paid-order-flow-123",
        },
        json={"task": task},
    )
    assert checkout.status_code == 200, checkout.text
    order_id = checkout.json()["order_id"]

    stripe_session = {
        "id": session_id,
        "livemode": False,
        "metadata": {
            "offer": "ola-execution-audit",
            "product": "OLA Execution Audit",
            "request_hash": hashlib.sha256(task.encode()).hexdigest(),
            "tenant_id": tenant_id,
            "order_id": order_id,
        },
        "payment_status": "paid",
        "status": "complete",
        "amount_total": 9900,
        "currency": "eur",
        "line_items": {
            "data": [{
                "price": {"id": "price_test_ola", "unit_amount": 9900, "currency": "eur"},
                "quantity": 1,
            }]
        },
    }
    monkeypatch.setattr(webhook_module, "retrieve_checkout", lambda sid: stripe_session)
    event = {
        "id": f"evt_full_flow_{uuid.uuid4().hex}",
        "type": "checkout.session.completed",
        "livemode": False,
        "data": {"object": {"id": session_id}},
    }
    raw = json.dumps(event, separators=(",", ":")).encode()
    timestamp = int(time.time())
    signed = f"{timestamp}.".encode() + raw
    signature = hmac.new(
        b"whsec_order_flow_test", signed, hashlib.sha256
    ).hexdigest()
    webhook = client.post(
        "/stripe/webhook",
        headers={"Stripe-Signature": f"t={timestamp},v1={signature}"},
        content=raw,
    )
    assert webhook.status_code == 200, webhook.text
    assert webhook.json()["status"] == "PAID_PENDING_REVIEW"

    monkeypatch.setattr(main_module, "retrieve_checkout", lambda sid: stripe_session)
    success = client.get("/payment-success", params={"session_id": session_id})
    assert success.status_code == 200, success.text
    success_body = success.json()
    assert success_body["status"] == "PAID_PENDING_REVIEW"
    assert success_body["payment"] == "CONFIRMED"
    assert success_body["execution"] == "NOT_STARTED"
    assert "payment_evidence_id" not in success_body
    assert "evidence_tip_hash" not in success_body
    assert "task" not in success_body
    tip_response = client.get(
        "/evidence/tip", headers={"X-API-Key": approver_key}
    )
    assert tip_response.status_code == 200, tip_response.text
    tip_hash = tip_response.json()["tip_hash"]
    assert len(tip_hash) == 64

    approval = client.post(
        f"/checkout-orders/{order_id}/approve",
        headers={"Authorization": f"Bearer {approver_key}"},
        json={
            "tip_hash": tip_hash,
            "reason": "Independent reviewer approved the paid sandbox order scope.",
        },
    )
    assert approval.status_code == 200, approval.text
    assert approval.json()["status"] == "APPROVED_FOR_EXECUTION"
    assert approval.json()["execution"] == "QUEUED"

    approved_success = client.get("/payment-success", params={"session_id": session_id})
    assert approved_success.status_code == 200, approved_success.text
    assert approved_success.json()["status"] == "APPROVED_FOR_EXECUTION"
    assert approved_success.json()["execution"] == "QUEUED"
    assert approved_success.json()["next_gate"] == "EXECUTION_DISPATCH"
    assert "approval_record_hash" not in approved_success.json()
    assert "execution_job_id" not in approved_success.json()
    assert "task" not in approved_success.json()

    worker_token = "full-flow-worker-secret-" + "x" * 40
    monkeypatch.setenv("OLA_EXECUTION_WORKER_TOKEN", worker_token)
    execution = client.post(
        f"/internal/checkout-execution/{approval.json()['execution_job_id']}/run",
        headers={"X-OLA-Worker-Token": worker_token},
    )
    assert execution.status_code == 200, execution.text
    assert execution.json()["status"] == "EXECUTED_REVIEW_REQUIRED"
    assert execution.json()["igor_status"] == "VERIFIED"
    assert execution.json()["invocation_type"] == "local_deterministic_model"
    assert execution.json()["real_llm_invoked"] is False
    assert execution.json()["customer_delivery"] == "NOT_DELIVERED"

    executed_success = client.get("/payment-success", params={"session_id": session_id})
    assert executed_success.status_code == 200, executed_success.text
    assert executed_success.json()["status"] == "EXECUTED_REVIEW_REQUIRED"
    assert executed_success.json()["customer_delivery"] == "NOT_DELIVERED"

    checkout_retry = client.post(
        "/checkout",
        headers={
            "X-API-Key": requester_key,
            "Idempotency-Key": "full-paid-order-flow-123",
        },
        json={"task": task},
    )
    assert checkout_retry.status_code == 200, checkout_retry.text
    assert checkout_retry.json()["status"] == "EXECUTED_REVIEW_REQUIRED"
    assert checkout_retry.json()["execution_job_status"] == "EXECUTED_REVIEW_REQUIRED"

    with SessionLocal() as db:
        control = db.scalar(select(CheckoutOrderControl).where(
            CheckoutOrderControl.order_id == order_id
        ))
        order = db.get(CheckoutOrder, order_id)
    assert order.status == "EXECUTED_REVIEW_REQUIRED"
    assert control.requester_id == requester_id
    assert control.approver_id == approver_id
    assert control.status == "APPROVED_FOR_EXECUTION"


def test_payment_success_rejects_session_task_not_bound_to_reserved_order(monkeypatch):
    from app import main as main_module

    ctx = _seed_paid_order(monkeypatch)
    session = {
        "id": ctx["session_id"],
        "metadata": {
            "tenant_id": ctx["tenant_id"],
            "order_id": ctx["order_id"],
            "task": "different task than the paid order reservation",
        },
        "payment_status": "paid",
        "status": "complete",
    }
    monkeypatch.setattr(main_module, "retrieve_checkout", lambda session_id: session)
    monkeypatch.setattr(main_module, "payment_verified", lambda value: True)
    response = TestClient(app).get(
        "/payment-success", params={"session_id": ctx["session_id"]}
    )
    assert response.status_code == 403, response.text
    assert "request hash" in response.text.lower()


def test_approval_creates_single_durable_execution_outbox_job(monkeypatch):
    from app.models import CheckoutExecutionJob
    ctx = _seed_paid_order(monkeypatch)
    response = _approve(ctx)
    assert response.status_code == 200, response.text
    with SessionLocal() as db:
        jobs = db.scalars(select(CheckoutExecutionJob).where(
            CheckoutExecutionJob.order_id == ctx["order_id"]
        )).all()
        assert len(jobs) == 1
        assert jobs[0].tenant_id == ctx["tenant_id"]
        assert jobs[0].task == ctx["task"]
        assert jobs[0].status == "QUEUED"
        assert jobs[0].attempt_count == 0
        assert jobs[0].approval_record_hash == response.json()["approval_record_hash"]


def test_evidence_tip_requires_tenant_api_key_and_returns_only_tip(monkeypatch):
    ctx = _seed_paid_order(monkeypatch)
    client = TestClient(app)

    denied = client.get("/evidence/tip")
    assert denied.status_code == 401

    response = client.get(
        "/evidence/tip", headers={"X-API-Key": ctx["approver_key"]}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert len(body["tip_hash"]) == 64
    assert body["record_count"] >= 2
    assert set(body) == {"tip_hash", "record_count"}


def test_paid_order_approval_rejects_ordinary_tenant_key_without_side_effects(monkeypatch):
    ctx = _seed_paid_order(monkeypatch)
    ordinary_key = f"ordinary-{uuid.uuid4()}"
    ordinary_id = str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(ApiKey(
            id=ordinary_id,
            tenant_id=ctx["tenant_id"],
            key_hash=api_key_fingerprint(ordinary_key),
            role="tenant",
        ))
        db.commit()

    response = _approve(ctx, key=ordinary_key)
    assert response.status_code == 403, response.text
    with SessionLocal() as db:
        control = db.scalar(select(CheckoutOrderControl).where(
            CheckoutOrderControl.order_id == ctx["order_id"]
        ))
        jobs = db.scalars(select(CheckoutExecutionJob).where(
            CheckoutExecutionJob.order_id == ctx["order_id"]
        )).all()
        approvals = db.scalars(select(EvidenceRecord).where(
            EvidenceRecord.tenant_id == ctx["tenant_id"],
            EvidenceRecord.record_type == "human.revenue_execution_approval",
        )).all()
    assert control.status == "PAID_PENDING_REVIEW"
    assert control.approver_id is None
    assert jobs == []
    assert approvals == []
