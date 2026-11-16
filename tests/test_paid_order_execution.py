import pytest
from app.main import app


def test_internal_paid_order_execution_worker_route_is_registered():
    routes = {route.path for route in app.routes}
    assert "/internal/checkout-execution/{job_id}/run" in routes


def test_worker_runs_paid_order_once_and_replays_completed_response(monkeypatch):
    import json
    from sqlalchemy import select
    from fastapi.testclient import TestClient
    from app.main import app
    from app.database import SessionLocal
    from app.models import CheckoutExecutionJob, EvidenceRecord
    from app.paid_order_execution import _append_locked
    from test_paid_order_approval import _seed_paid_order, _approve

    ctx = _seed_paid_order(monkeypatch)
    approved = _approve(ctx)
    assert approved.status_code == 200, approved.text
    with SessionLocal() as db:
        job = db.scalar(select(CheckoutExecutionJob).where(CheckoutExecutionJob.order_id == ctx["order_id"]))
        job_id = job.id
    token = "worker-secret-" + "w" * 40
    monkeypatch.setenv("OLA_EXECUTION_WORKER_TOKEN", token)
    calls = []
    def fake_runner(tenant_id, requester_id, task, requested_tools, *, execution_context=None):
        calls.append((tenant_id, requester_id, task, requested_tools, execution_context))
        return {
            "run_id": "run-verified-001",
            "nina": {"status": "VERIFIED"},
            "igor": {"status": "VERIFIED"},
            "provenance": {"status": "VERIFIED"},
            "replay_verification": {"status": "VERIFIED"},
            "decision_report": {"report_sha256": "d" * 64},
            "status": "REVIEW",
        }
    import app.nina_execution as nina_execution
    # Patch the production runner behind the internal worker's explicit service boundary.
    monkeypatch.setattr(nina_execution, "run_nina_task", fake_runner)
    response = TestClient(app).post(
        f"/internal/checkout-execution/{job_id}/run",
        headers={"X-OLA-Worker-Token": token},
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "EXECUTED_REVIEW_REQUIRED"
    assert response.json()["customer_delivery"] == "NOT_DELIVERED"
    assert len(calls) == 1
    second = TestClient(app).post(
        f"/internal/checkout-execution/{job_id}/run",
        headers={"X-OLA-Worker-Token": token},
    )
    assert second.status_code == 200, second.text
    assert second.json() == response.json()
    assert len(calls) == 1
    with SessionLocal() as db:
        job = db.get(CheckoutExecutionJob, job_id)
        assert job.status == "EXECUTED_REVIEW_REQUIRED"
        assert job.attempt_count == 1
        records = db.scalars(select(EvidenceRecord).where(
            EvidenceRecord.tenant_id == ctx["tenant_id"]
        )).all()
        events = [row.record_type for row in records]
        assert events.count("revenue.execution_started") == 1
        assert events.count("revenue.execution_completed") == 1
        from app.hashchain import trusted_record
        worker_events = [row for row in records if row.record_type in {
            "revenue.execution_started", "revenue.execution_completed"
        }]
        assert len(worker_events) == 2
        assert all(trusted_record({
            "record_type": row.record_type,
            "payload_json": row.payload_json,
        }) for row in worker_events)


def test_worker_rejects_missing_or_wrong_token(monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import app
    token = "worker-secret-" + "w" * 40
    monkeypatch.setenv("OLA_EXECUTION_WORKER_TOKEN", token)
    client = TestClient(app)
    missing = client.post("/internal/checkout-execution/not-a-job/run")
    wrong = client.post("/internal/checkout-execution/not-a-job/run", headers={"X-OLA-Worker-Token": "wrong"})
    assert missing.status_code == 401
    assert wrong.status_code == 403


def test_stale_running_job_is_marked_interrupted_and_never_replayed(monkeypatch):
    import time
    from sqlalchemy import select
    from fastapi.testclient import TestClient
    from app.main import app
    from app.database import SessionLocal
    from app.models import CheckoutExecutionJob, EvidenceRecord
    from test_paid_order_approval import _seed_paid_order, _approve
    ctx = _seed_paid_order(monkeypatch)
    assert _approve(ctx).status_code == 200
    with SessionLocal() as db:
        job = db.scalar(select(CheckoutExecutionJob).where(CheckoutExecutionJob.order_id == ctx["order_id"]))
        job.status = "RUNNING"
        job.attempt_count = 1
        job.started_at = int(time.time()) - 901
        db.commit()
        job_id = job.id
    token = "worker-secret-" + "w" * 40
    monkeypatch.setenv("OLA_EXECUTION_WORKER_TOKEN", token)
    response = TestClient(app).post(
        f"/internal/checkout-execution/{job_id}/run",
        headers={"X-OLA-Worker-Token": token},
    )
    assert response.status_code == 409
    assert "manual reconciliation" in response.text
    with SessionLocal() as db:
        job = db.get(CheckoutExecutionJob, job_id)
        assert job.status == "INTERRUPTED"
        records = db.scalars(select(EvidenceRecord).where(
            EvidenceRecord.tenant_id == ctx["tenant_id"]
        )).all()
        assert sum(row.record_type == "revenue.execution_interrupted" for row in records) == 1


def test_nina_failure_is_terminal_and_does_not_auto_retry(monkeypatch):
    from sqlalchemy import select
    from fastapi.testclient import TestClient
    from app.main import app
    from app.database import SessionLocal
    from app.models import CheckoutExecutionJob, EvidenceRecord
    from test_paid_order_approval import _seed_paid_order, _approve
    import app.nina_execution as nina_execution
    ctx = _seed_paid_order(monkeypatch)
    assert _approve(ctx).status_code == 200
    with SessionLocal() as db:
        job = db.scalar(select(CheckoutExecutionJob).where(CheckoutExecutionJob.order_id == ctx["order_id"]))
        job_id = job.id
    token = "worker-secret-" + "w" * 40
    monkeypatch.setenv("OLA_EXECUTION_WORKER_TOKEN", token)
    calls = []
    def failing_runner(*args, **kwargs):
        calls.append(1)
        raise RuntimeError("provider unavailable")
    monkeypatch.setattr(nina_execution, "run_nina_task", failing_runner)
    client = TestClient(app)
    first = client.post(f"/internal/checkout-execution/{job_id}/run", headers={"X-OLA-Worker-Token": token})
    second = client.post(f"/internal/checkout-execution/{job_id}/run", headers={"X-OLA-Worker-Token": token})
    assert first.status_code == 200, first.text
    assert first.json()["status"] == "FAILED"
    assert second.status_code == 409
    assert len(calls) == 1
    with SessionLocal() as db:
        job = db.get(CheckoutExecutionJob, job_id)
        assert job.status == "FAILED"
        assert job.attempt_count == 1
        records = db.scalars(select(EvidenceRecord).where(
            EvidenceRecord.tenant_id == ctx["tenant_id"]
        )).all()
        assert sum(row.record_type == "revenue.execution_failed" for row in records) == 1


def test_worker_fails_closed_when_secret_is_not_configured(monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import app
    monkeypatch.delenv("OLA_EXECUTION_WORKER_TOKEN", raising=False)
    response = TestClient(app).post("/internal/checkout-execution/not-a-job/run")
    assert response.status_code == 503


def test_paid_order_worker_executes_real_nina_and_igor_runtime(monkeypatch):
    import json
    from sqlalchemy import select
    from app.database import SessionLocal
    from app.models import CheckoutExecutionJob, CheckoutOrder, EvidenceRecord
    from app.paid_order_execution import execute_paid_order_job
    from test_paid_order_approval import _seed_paid_order, _approve

    monkeypatch.setenv("OLA_LLM_PROVIDER", "openai")
    monkeypatch.setenv("OLA_LLM_MODE", "deterministic")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    ctx = _seed_paid_order(monkeypatch)
    approved = _approve(ctx)
    assert approved.status_code == 200, approved.text
    with SessionLocal() as db:
        job = db.scalar(select(CheckoutExecutionJob).where(CheckoutExecutionJob.order_id == ctx["order_id"]))
        job_id = job.id
    result = execute_paid_order_job(job_id)
    assert result["status"] == "EXECUTED_REVIEW_REQUIRED", result
    assert result["nina_status"] == "VERIFIED", result
    assert result["igor_status"] == "VERIFIED", result
    assert result["provenance_status"] == "VERIFIED", result
    assert result["replay_status"] == "VERIFIED", result
    assert result["customer_delivery"] == "NOT_DELIVERED"
    assert result["invocation_type"] == "local_deterministic_model"
    assert result["real_llm_invoked"] is False
    with SessionLocal() as db:
        job = db.get(CheckoutExecutionJob, job_id)
        order = db.get(CheckoutOrder, ctx["order_id"])
        assert job.status == "EXECUTED_REVIEW_REQUIRED"
        assert job.attempt_count == 1
        assert job.run_id == result["run_id"]
        assert order.status == "EXECUTED_REVIEW_REQUIRED"
        evidence = db.scalars(select(EvidenceRecord).where(EvidenceRecord.tenant_id == ctx["tenant_id"])).all()
        context_records = [row for row in evidence if row.record_type in {"provenance.runtime", "decision.candidate"}]
        assert any(json.loads(row.payload_json).get("order_id") == ctx["order_id"] for row in context_records)
        assert any(json.loads(row.payload_json).get("execution_job_id") == job_id for row in context_records)


def test_worker_blocks_changed_task_scope_before_running_nina(monkeypatch):
    from sqlalchemy import select
    from app.database import SessionLocal
    from app.models import CheckoutExecutionJob, CheckoutOrder
    from app.paid_order_execution import execute_paid_order_job, PaidOrderExecutionRejected
    from test_paid_order_approval import _seed_paid_order, _approve
    ctx = _seed_paid_order(monkeypatch)
    assert _approve(ctx).status_code == 200
    with SessionLocal() as db:
        job = db.scalar(select(CheckoutExecutionJob).where(CheckoutExecutionJob.order_id == ctx["order_id"]))
        job_id = job.id
        job.task = "changed after approval"
        db.commit()
    with pytest.raises(PaidOrderExecutionRejected) as exc:
        execute_paid_order_job(job_id)
    assert exc.value.code == 409
    with SessionLocal() as db:
        job = db.get(CheckoutExecutionJob, job_id)
        order = db.get(CheckoutOrder, ctx["order_id"])
        assert job.status == "BLOCKED"
        assert job.attempt_count == 0
        assert order.status == "BLOCKED"


def test_worker_polling_selects_queued_and_stale_but_not_terminal_jobs(monkeypatch):
    import time
    from sqlalchemy import select
    from app.database import SessionLocal
    from app.models import CheckoutExecutionJob
    from scripts.run_paid_order_worker import pending_job_ids
    from test_paid_order_approval import _seed_paid_order, _approve
    ctx = _seed_paid_order(monkeypatch)
    assert _approve(ctx).status_code == 200
    with SessionLocal() as db:
        job = db.scalar(select(CheckoutExecutionJob).where(CheckoutExecutionJob.order_id == ctx["order_id"]))
        queued_id = job.id
        job.status = "RUNNING"
        job.attempt_count = 1
        job.started_at = 100
        db.commit()
    assert queued_id in pending_job_ids(now=1000, stale_after_seconds=900)
    assert queued_id not in pending_job_ids(now=1000, stale_after_seconds=901)


def test_worker_batch_exit_code_signals_execution_failure(monkeypatch):
    import scripts.run_paid_order_worker as worker
    monkeypatch.setattr(worker, "pending_job_ids", lambda **kwargs: ["job-failed"])
    monkeypatch.setattr(worker, "execute_paid_order_job", lambda *args, **kwargs: {"status": "FAILED"})
    assert worker.run_once(now=1000) == 1


def test_worker_batch_exit_code_is_zero_for_empty_queue(monkeypatch):
    import scripts.run_paid_order_worker as worker
    monkeypatch.setattr(worker, "pending_job_ids", lambda **kwargs: [])
    assert worker.run_once(now=1000) == 0


def test_worker_once_mode_propagates_failed_batch_exit_code(monkeypatch):
    import sys
    import scripts.run_paid_order_worker as worker
    monkeypatch.setattr(sys, "argv", ["run_paid_order_worker.py", "--once"])
    monkeypatch.setattr(worker, "prepare_runtime_schema", lambda: None)
    monkeypatch.setattr(worker, "run_once", lambda **kwargs: 1)
    assert worker.main() == 1


def test_concurrent_worker_invocations_claim_one_execution_only(monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor
    from app.database import SessionLocal
    from app.models import CheckoutExecutionJob
    from app.paid_order_execution import execute_paid_order_job, PaidOrderExecutionRejected
    from sqlalchemy import select
    from test_paid_order_approval import _seed_paid_order, _approve

    ctx = _seed_paid_order(monkeypatch)
    assert _approve(ctx).status_code == 200
    with SessionLocal() as db:
        job = db.scalar(select(CheckoutExecutionJob).where(CheckoutExecutionJob.order_id == ctx["order_id"]))
        job_id = job.id

    started = threading.Event()
    release = threading.Event()
    calls = []

    def blocked_runner(tenant_id, requester_id, task, requested_tools, *, execution_context=None):
        calls.append(job_id)
        started.set()
        assert release.wait(timeout=5), "test runner was not released"
        return {
            "run_id": "run-concurrent-001",
            "nina": {"status": "VERIFIED"},
            "igor": {"status": "VERIFIED"},
            "provenance": {"status": "VERIFIED"},
            "replay_verification": {"status": "VERIFIED"},
            "decision_report": {"report_sha256": "e" * 64},
            "status": "REVIEW",
        }

    with ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(execute_paid_order_job, job_id, runner=blocked_runner)
        assert started.wait(timeout=5), "first worker did not claim the job"
        with pytest.raises(PaidOrderExecutionRejected) as exc:
            execute_paid_order_job(job_id, runner=blocked_runner)
        assert exc.value.code == 409
        assert "already running" in str(exc.value)
        release.set()
        result = first.result(timeout=10)

    assert result["status"] == "EXECUTED_REVIEW_REQUIRED"
    assert len(calls) == 1


def test_worker_rechecks_execution_approver_role_before_running_nina(monkeypatch):
    from sqlalchemy import select
    from app.database import SessionLocal
    from app.models import ApiKey, CheckoutExecutionJob, CheckoutOrder
    from app.paid_order_execution import execute_paid_order_job, PaidOrderExecutionRejected
    from test_paid_order_approval import _seed_paid_order, _approve

    ctx = _seed_paid_order(monkeypatch)
    approved = _approve(ctx)
    assert approved.status_code == 200, approved.text
    with SessionLocal() as db:
        approver = db.get(ApiKey, ctx["approver_id"])
        approver.role = "tenant"
        job = db.scalar(select(CheckoutExecutionJob).where(
            CheckoutExecutionJob.order_id == ctx["order_id"]
        ))
        job_id = job.id
        db.commit()

    calls = []
    def forbidden_runner(*args, **kwargs):
        calls.append(True)
        return {"status": "SHOULD_NOT_RUN"}

    with pytest.raises(PaidOrderExecutionRejected) as exc:
        execute_paid_order_job(job_id, runner=forbidden_runner)
    assert exc.value.code == 409
    assert calls == []
    with SessionLocal() as db:
        job = db.get(CheckoutExecutionJob, job_id)
        order = db.get(CheckoutOrder, ctx["order_id"])
    assert job.status == "BLOCKED"
    assert order.status == "BLOCKED"
