import hashlib
import json
import uuid

from fastapi.testclient import TestClient

from app import main
from app.api_key_hashing import api_key_fingerprint
from app.database import SessionLocal
from app.igor_evidence_verifier import trusted_record
from app.main import app
from app.models import ApiKey, Tenant, EvidenceRecord, CheckoutOrder
from sqlalchemy import select


def _client_and_key(*, raise_server_exceptions=True):
    tenant_id = str(uuid.uuid4())
    raw_key = f"checkout-key-{tenant_id}"
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="checkout-idempotency-test"))
        db.commit()
        db.add(ApiKey(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            key_hash=api_key_fingerprint(raw_key),
        ))
        db.commit()
    return TestClient(app, raise_server_exceptions=raise_server_exceptions), raw_key


def _checkout(client, key, idempotency_key, task="verify workflow"):
    return client.post(
        "/checkout",
        headers={
            "X-API-Key": key,
            "Idempotency-Key": idempotency_key,
        },
        json={"task": task},
    )


def test_checkout_reuses_existing_session_for_same_idempotency_key(monkeypatch):
    client, key = _client_and_key()
    calls = []

    def create(task, success_url, cancel_url, tenant_id, idempotency_key, order_id):
        calls.append((task, tenant_id, idempotency_key))
        return {"id": "cs_test_reused123", "url": "https://checkout.stripe.test/session"}

    monkeypatch.setattr(main, "create_checkout", create)
    first = _checkout(client, key, "request-12345678")
    second = _checkout(client, key, "request-12345678")

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["session_id"] == second.json()["session_id"]
    assert first.json()["checkout_url"] == second.json()["checkout_url"]
    assert len(calls) == 1
    with SessionLocal() as db:
        order_id = first.json()["order_id"]
        trusted_checkout_records = db.scalars(select(EvidenceRecord).where(
            EvidenceRecord.record_type == "stripe.checkout_created",
        )).all()
    assert len([row for row in trusted_checkout_records if json.loads(row.payload_json).get("ola_order_id") == order_id]) == 1


def test_checkout_rejects_idempotency_key_reuse_for_different_task(monkeypatch):
    client, key = _client_and_key()
    calls = []

    def create(task, success_url, cancel_url, tenant_id, idempotency_key, order_id):
        calls.append(task)
        return {"id": "cs_test_taskbind123", "url": "https://checkout.stripe.test/session"}

    monkeypatch.setattr(main, "create_checkout", create)
    first = _checkout(client, key, "request-task-12345", "task A")
    second = _checkout(client, key, "request-task-12345", "task B")

    assert first.status_code == 200
    assert second.status_code == 409
    assert calls == ["task A"]


def test_checkout_retries_stripe_creation_with_same_provider_idempotency_key(monkeypatch):
    client, key = _client_and_key()
    provider_keys = []
    attempts = 0

    def create(task, success_url, cancel_url, tenant_id, idempotency_key, order_id):
        nonlocal attempts
        attempts += 1
        provider_keys.append(idempotency_key)
        if attempts == 1:
            raise RuntimeError("temporary Stripe outage")
        return {"id": "cs_test_retry123", "url": "https://checkout.stripe.test/retried"}

    monkeypatch.setattr(main, "create_checkout", create)
    first = _checkout(client, key, "request-retry-12345")
    second = _checkout(client, key, "request-retry-12345")

    assert first.status_code == 502
    assert second.status_code == 200
    assert len(provider_keys) == 2
    assert provider_keys[0] == provider_keys[1]


def test_checkout_requires_idempotency_key(monkeypatch):
    client, key = _client_and_key()
    called = []
    monkeypatch.setattr(main, "create_checkout", lambda *args, **kwargs: called.append(True))
    response = client.post("/checkout", headers={"X-API-Key": key}, json={"task": "verify"})

    assert response.status_code == 400
    assert called == []


def test_checkout_replay_repairs_missing_evidence_without_duplicate(monkeypatch):
    client, key = _client_and_key(raise_server_exceptions=False)
    original_append = main.append_record
    attempts = 0

    def fail_once(tenant_id, record_type, payload, *, deduplicate=False):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("simulated evidence-store interruption")
        return original_append(
            tenant_id, record_type, payload, deduplicate=deduplicate
        )

    monkeypatch.setattr(main, "create_checkout", lambda *args, **kwargs: {
        "id": "cs_test_evidencerepair123",
        "url": "https://checkout.stripe.test/evidence-repair",
    })
    monkeypatch.setattr(main, "append_record", fail_once)
    first = _checkout(client, key, "request-evidence-123")
    second = _checkout(client, key, "request-evidence-123")

    assert first.status_code == 500
    assert second.status_code == 200
    with SessionLocal() as db:
        rows = db.scalars(select(EvidenceRecord).where(
            EvidenceRecord.record_type == "revenue.checkout_created"
        )).all()
        orders = db.scalars(select(CheckoutOrder)).all()
    assert len([row for row in rows if "cs_test_evidencerepair123" in row.payload_json]) == 1
    assert len([order for order in orders if order.stripe_session_id == "cs_test_evidencerepair123"]) == 1


def test_checkout_ignores_caller_controlled_redirect_urls(monkeypatch):
    client, key = _client_and_key()
    captured = {}

    def create(task, success_url, cancel_url, tenant_id, idempotency_key, order_id):
        captured.update(success_url=success_url, cancel_url=cancel_url)
        return {"id": "cs_test_redirect123", "url": "https://checkout.stripe.test/redirect"}

    monkeypatch.setattr(main, "create_checkout", create)
    response = client.post(
        "/checkout",
        headers={"X-API-Key": key, "Idempotency-Key": "request-redirect-123"},
        json={
            "task": "verify redirect safety",
            "success_url": "https://attacker.example/collect",
            "cancel_url": "https://attacker.example/cancel",
        },
    )

    assert response.status_code == 200
    assert captured["success_url"] == "http://localhost:8000/payment-success"
    assert captured["cancel_url"] == "http://localhost:8000/"


def test_checkout_stale_reservation_fails_closed_after_provider_key_window(monkeypatch):
    import time

    client, key = _client_and_key()
    calls = []

    def create(*args, **kwargs):
        calls.append(kwargs.get("idempotency_key"))
        raise RuntimeError("simulated lost Stripe response")

    monkeypatch.setattr(main, "create_checkout", create)
    first = _checkout(client, key, "request-stale-12345")
    assert first.status_code == 502

    with SessionLocal() as db:
        order = db.scalar(select(CheckoutOrder).where(
            CheckoutOrder.idempotency_key_hash
            == hashlib.sha256(b"request-stale-12345").hexdigest()
        ))
        order.created_at = int(time.time()) - (24 * 60 * 60)
        db.commit()

    second = _checkout(client, key, "request-stale-12345")
    assert second.status_code == 409
    assert "manual Stripe reconciliation" in second.json()["detail"]
    assert len(calls) == 1


def test_checkout_requires_configured_public_origin_before_order_reservation(monkeypatch):
    client, key = _client_and_key()
    called = []
    monkeypatch.delenv("OLA_PUBLIC_BASE_URL", raising=False)
    monkeypatch.setattr(main, "create_checkout", lambda *args, **kwargs: called.append(True))
    response = _checkout(client, key, "request-no-origin-123")

    assert response.status_code == 503
    assert called == []
    with SessionLocal() as db:
        order = db.scalar(select(CheckoutOrder).where(
            CheckoutOrder.idempotency_key_hash
            == hashlib.sha256(b"request-no-origin-123").hexdigest()
        ))
    assert order is None


def test_checkout_rejects_non_tls_non_local_public_origin(monkeypatch):
    client, key = _client_and_key()
    called = []
    monkeypatch.setenv("OLA_PUBLIC_BASE_URL", "http://public.example")
    monkeypatch.setattr(main, "create_checkout", lambda *args, **kwargs: called.append(True))
    response = _checkout(client, key, "request-http-origin-123")

    assert response.status_code == 503
    assert called == []


def test_checkout_retry_backfills_missing_trusted_checkout_provenance(monkeypatch):
    client, key = _client_and_key(raise_server_exceptions=False)
    create_calls = []
    monkeypatch.setattr(main, "create_checkout", lambda *args, **kwargs: create_calls.append(True) or {
        "id": "cs_test_backfill_proof123",
        "url": "https://checkout.stripe.test/backfill-proof",
    })
    original_append = main.append_record
    failed_once = []

    def fail_first_checkout_proof(tenant_id, record_type, payload, *, deduplicate=False):
        if record_type == "stripe.checkout_created" and not failed_once:
            failed_once.append(True)
            raise RuntimeError("simulated evidence append interruption")
        return original_append(tenant_id, record_type, payload, deduplicate=deduplicate)

    monkeypatch.setattr(main, "append_record", fail_first_checkout_proof)
    first = _checkout(client, key, "checkout-proof-backfill-123")
    assert first.status_code == 500

    second = _checkout(client, key, "checkout-proof-backfill-123")
    assert second.status_code == 200, second.text
    assert len(create_calls) == 1
    with SessionLocal() as db:
        proofs = db.scalars(select(EvidenceRecord).where(
            EvidenceRecord.record_type == "stripe.checkout_created",
        )).all()
    matching = [row for row in proofs if json.loads(row.payload_json).get("ola_order_id") == second.json()["order_id"]]
    assert len(matching) == 1


def test_checkout_persists_the_authenticated_requester_identity(monkeypatch):
    from app.models import CheckoutOrderControl

    client, key = _client_and_key()
    monkeypatch.setattr(main, "create_checkout", lambda *args, **kwargs: {
        "id": "cs_test_requester_binding123",
        "url": "https://checkout.stripe.test/requester-binding",
    })
    response = _checkout(client, key, "requester-binding-12345")
    assert response.status_code == 200, response.text

    with SessionLocal() as db:
        key_row = db.scalar(select(ApiKey).where(
            ApiKey.key_hash == api_key_fingerprint(key)
        ))
        control = db.scalar(select(CheckoutOrderControl).where(
            CheckoutOrderControl.order_id == response.json()["order_id"]
        ))
    assert control is not None
    assert control.requester_id == key_row.id
    assert control.status == "CHECKOUT_CREATED"
    with SessionLocal() as db:
        order = db.get(CheckoutOrder, response.json()["order_id"])
        checkout_record = db.scalar(select(EvidenceRecord).where(
            EvidenceRecord.tenant_id == order.tenant_id,
            EvidenceRecord.record_type == "stripe.checkout_created",
        ))
        record = {
            "id": checkout_record.id,
            "tenant_id": checkout_record.tenant_id,
            "seq": checkout_record.seq,
            "prev_hash": checkout_record.prev_hash,
            "record_hash": checkout_record.record_hash,
            "record_type": checkout_record.record_type,
            "payload_json": checkout_record.payload_json,
        }
        checkout_payload = json.loads(checkout_record.payload_json)
    assert trusted_record(record)
    assert checkout_payload["requester_id"] == key_row.id
    assert checkout_payload["checkout_session_id"] == order.stripe_session_id
    assert checkout_payload["request_hash"] == order.request_hash


def test_checkout_retry_does_not_reset_a_paid_order_or_create_another_session(monkeypatch):
    from app.models import CheckoutOrderControl

    client, key = _client_and_key()
    calls = []
    monkeypatch.setattr(main, "create_checkout", lambda *args, **kwargs: calls.append(True) or {
        "id": "cs_test_paid_replay123",
        "url": "https://checkout.stripe.test/paid-replay",
    })
    first = _checkout(client, key, "paid-replay-123456")
    assert first.status_code == 200, first.text
    with SessionLocal() as db:
        order = db.get(CheckoutOrder, first.json()["order_id"])
        order.status = "PAID_PENDING_REVIEW"
        order.payment_result_json = json.dumps({
            "status": "PAID_PENDING_REVIEW",
            "order_id": order.id,
            "checkout_session_id": order.stripe_session_id,
            "payment": "CONFIRMED",
        })
        control = db.scalar(select(CheckoutOrderControl).where(
            CheckoutOrderControl.order_id == order.id
        ))
        control.status = "PAID_PENDING_REVIEW"
        db.commit()

    retry = _checkout(client, key, "paid-replay-123456")
    assert retry.status_code == 200, retry.text
    assert retry.json()["status"] == "PAID_PENDING_REVIEW"
    assert len(calls) == 1
    with SessionLocal() as db:
        order = db.get(CheckoutOrder, first.json()["order_id"])
        assert order.status == "PAID_PENDING_REVIEW"


def test_checkout_idempotency_replay_is_bound_to_original_requester_identity(monkeypatch):
    client, requester_key = _client_and_key()
    tenant_id = None
    with SessionLocal() as db:
        requester = db.scalar(select(ApiKey).where(
            ApiKey.key_hash == api_key_fingerprint(requester_key)
        ))
        tenant_id = requester.tenant_id
        second_key = f"different-checkout-identity-{uuid.uuid4()}"
        db.add(ApiKey(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            key_hash=api_key_fingerprint(second_key),
        ))
        db.commit()
    monkeypatch.setattr(main, "create_checkout", lambda *args, **kwargs: {
        "id": "cs_test_requester_replay123",
        "url": "https://checkout.stripe.test/requester-replay",
    })
    first = _checkout(client, requester_key, "identity-replay-12345")
    replay = _checkout(client, second_key, "identity-replay-12345")
    assert first.status_code == 200, first.text
    assert replay.status_code == 403, replay.text


def test_legacy_checkout_without_requester_provenance_is_not_reopened(monkeypatch):
    client, key = _client_and_key()
    with SessionLocal() as db:
        key_row = db.scalar(select(ApiKey).where(
            ApiKey.key_hash == api_key_fingerprint(key)
        ))
        task = "legacy order without requester provenance"
        db.add(CheckoutOrder(
            id=str(uuid.uuid4()),
            tenant_id=key_row.tenant_id,
            idempotency_key_hash=hashlib.sha256(b"legacy-order-123456").hexdigest(),
            request_hash=hashlib.sha256(task.encode()).hexdigest(),
            status="CREATING",
        ))
        db.commit()
    calls = []
    monkeypatch.setattr(main, "create_checkout", lambda *args, **kwargs: calls.append(True))
    response = _checkout(client, key, "legacy-order-123456", task)
    assert response.status_code == 409, response.text
    assert calls == []


def test_checkout_keeps_task_in_private_order_not_payment_evidence(monkeypatch):
    from app.models import StripeEvent
    task = "private customer workflow details " + uuid.uuid4().hex
    client, key = _client_and_key()
    def create(*args, **kwargs):
        return {"id": "cs_test_private_order_" + uuid.uuid4().hex[:12], "url": "https://checkout.stripe.test/private"}
    monkeypatch.setattr(main, "create_checkout", create)
    response = _checkout(client, key, "private-task-12345678", task)
    assert response.status_code == 200, response.text
    order_id = response.json()["order_id"]
    with SessionLocal() as db:
        order = db.get(CheckoutOrder, order_id)
        assert order.task == task
        records = db.scalars(select(EvidenceRecord).where(
            EvidenceRecord.tenant_id == order.tenant_id,
            EvidenceRecord.record_type == "revenue.checkout_created",
        )).all()
        assert records
        assert all(task not in row.payload_json for row in records)
        stripe_rows = db.scalars(select(StripeEvent)).all()
        assert all(row.task is None for row in stripe_rows)
