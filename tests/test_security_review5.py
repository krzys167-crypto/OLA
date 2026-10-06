"""Fifth review, application layer: request limits, headers, database append-only hardening."""
import hashlib
import json
import sqlite3
import threading
import time
import uuid

import pytest
from fastapi.testclient import TestClient

from app import database
from app.main import app
from app.models import ApiKey, Tenant
from app.database import SessionLocal, engine, install_append_only_triggers


def make_tenant():
    tenant_id, key = str(uuid.uuid4()), "r5-" + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="r5"))
        db.add(ApiKey(id=str(uuid.uuid4()), tenant_id=tenant_id, key_hash=hashlib.sha256(key.encode()).hexdigest()))
        db.commit()
    return tenant_id, key


client = TestClient(app, raise_server_exceptions=False)


# ------------------------------------------------------------------ request size
def test_a_large_body_is_413_before_authentication_and_parsing():
    r = client.post("/evidence", content=b"{" + b" " * 2_000_000 + b"}", headers={"Content-Type": "application/json"})
    assert r.status_code == 413, r.status_code            # not 401, not a parse of 2 MB


def test_a_chunked_body_without_content_length_is_cut_off():
    def gen():
        for _ in range(40):
            yield b" " * 65536
    r = client.post("/evidence", content=gen(), headers={"Content-Type": "application/json"})
    assert r.status_code == 413, r.status_code


def test_the_webhook_has_a_smaller_budget():
    r = client.post("/stripe/webhook", content=b"x" * 70_000, headers={"Stripe-Signature": "t=1,v1=00"})
    assert r.status_code == 413
    r = client.post("/stripe/webhook", content=b"{}", headers={"Stripe-Signature": "t=1,v1=00"})
    assert r.status_code == 400


def test_normal_requests_are_unaffected_and_the_limit_is_configurable(monkeypatch):
    _, key = make_tenant()
    r = client.post("/evidence", json={"payload": {"a": "x" * 100_000}}, headers={"X-API-Key": key})
    assert r.status_code == 200, r.text[:100]
    monkeypatch.setenv("OLA_MAX_BODY_BYTES", "1000")
    assert client.post("/evidence", json={"payload": {"a": "x" * 2000}}, headers={"X-API-Key": key}).status_code == 413


# ------------------------------------------------------------------ headers
def test_security_headers_on_the_page_and_the_api():
    page = client.get("/")
    assert page.status_code == 200
    csp = page.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in csp and "default-src 'self'" in csp and "connect-src 'self'" in csp
    for r in (page, client.get("/health")):
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["x-frame-options"] == "DENY" and r.headers["referrer-policy"] == "no-referrer"
        assert r.headers["cache-control"] == "no-store"
    assert "content-security-policy" not in client.get("/health").headers


# ------------------------------------------------------------------ database
def _insert(conn, verb="INSERT"):
    conn.exec_driver_sql(
        f"{verb} INTO evidence_records (id, tenant_id, seq, prev_hash, record_hash, record_type, payload_json) "
        "VALUES (?, ?, 0, ?, ?, 'generic', '{}')", (r5id, r5tenant, "0" * 64, "a" * 64))


r5id, r5tenant = "fixed-id", "fixed-tenant"


@pytest.mark.parametrize("verb", ["INSERT OR REPLACE", "REPLACE"])
def test_replace_cannot_overwrite_an_evidence_row(verb):
    global r5id, r5tenant
    r5id, r5tenant = str(uuid.uuid4()), str(uuid.uuid4())
    with engine.begin() as conn:
        conn.exec_driver_sql("INSERT INTO tenants (id, name) VALUES (?, 'x')", (r5tenant,))
        _insert(conn)
    with pytest.raises(Exception, match="append-only|constraint|UNIQUE"):
        with engine.begin() as conn:
            conn.exec_driver_sql(
                f"{verb} INTO evidence_records (id, tenant_id, seq, prev_hash, record_hash, record_type, payload_json) "
                "VALUES (?, ?, 0, ?, ?, 'generic', '{\"forged\": 1}')", (r5id, r5tenant, "0" * 64, "b" * 64))
    with engine.begin() as conn:
        assert conn.exec_driver_sql("SELECT payload_json FROM evidence_records WHERE id=?", (r5id,)).scalar() == "{}"


def test_every_connection_has_recursive_triggers_and_a_busy_timeout():
    with engine.connect() as conn:
        assert conn.exec_driver_sql("PRAGMA recursive_triggers").scalar() == 1
        assert conn.exec_driver_sql("PRAGMA busy_timeout").scalar() > 0


def test_wal_is_off_by_default_so_a_file_copy_of_the_db_is_complete():
    with engine.connect() as conn:
        assert conn.exec_driver_sql("PRAGMA journal_mode").scalar().lower() != "wal"


def test_a_neutered_trigger_is_replaced_at_startup():
    with engine.begin() as conn:
        conn.exec_driver_sql("DROP TRIGGER evidence_no_update")
        conn.exec_driver_sql("CREATE TRIGGER evidence_no_update BEFORE UPDATE ON evidence_records WHEN 0 "
                             "BEGIN SELECT 1; END;")
    install_append_only_triggers()
    with engine.begin() as conn:
        sql = conn.exec_driver_sql("SELECT sql FROM sqlite_master WHERE name='evidence_no_update'").scalar()
    assert "WHEN 0" not in sql and "append-only" in sql


def test_a_locked_database_is_503_with_retry_after_not_500(monkeypatch):
    _, key = make_tenant()
    monkeypatch.setenv("OLA_DB_BUSY_MS", "200")
    engine.dispose()                                      # new connections pick up the short timeout
    holder = sqlite3.connect(database.DB_PATH, timeout=1)
    try:
        holder.execute("BEGIN IMMEDIATE")
        t0 = time.time()
        r = client.post("/evidence", json={"payload": {"a": 1}}, headers={"X-API-Key": key})
        assert r.status_code == 503 and r.headers.get("retry-after") == "2", (r.status_code, r.text[:120])
        assert "SELECT" not in r.text and "INSERT" not in r.text
        assert time.time() - t0 < 20
    finally:
        holder.rollback()
        holder.close()
        monkeypatch.undo()
        engine.dispose()


# ------------------------------------------------------------------ invoices
INVOICE = {"invoice_id": "INV-1", "supplier": "S", "currency": "EUR", "net": 1000.0, "vat_rate": 0.21}


def _invoice(key, **over):
    return client.post("/business-invoice-run", json={"invoice": {**INVOICE, **over}}, headers={"X-API-Key": key})


def test_a_wrong_vat_rate_is_rejected_not_verified_and_not_approved():
    _, key = make_tenant()
    ok = _invoice(key).json()
    assert ok["status"] == "VERIFIED" and ok["final_result"]["payment_decision"] == "APPROVE_FOR_TEST_TRANSFER"
    for rate in (0.05, 0.0, 0.5):
        _, k = make_tenant()
        r = _invoice(k, vat_rate=rate)
        assert r.status_code == 200, r.text[:200]
        b = r.json()
        assert b["status"] == "BLOCK", b["status"]
        assert b["final_result"]["payment_decision"] == "REJECT_POLICY_MISMATCH"
        assert b["final_result"]["transfer_amount"] == 0.0 and b["final_result"]["transfer_status"] == "NOT_SENT"
        by_agent = {e["agent"]: e for e in b["execution"]}
        assert by_agent["self_reflection"]["status"] == "BLOCK" and "REJECTED" in by_agent["self_reflection"]["result"]
        assert "does NOT match" in by_agent["agentic_rag"]["result"]


@pytest.mark.parametrize("over", [
    {"net": -5000}, {"net": 0}, {"net": 1e300}, {"net": True}, {"net": "1000"}, {"net": 0.005}, {"net": None},
    {"net": [1]}, {"vat_rate": {}}, {"vat_rate": -0.1}, {"vat_rate": 7}, {"vat_rate": True}, {"currency": ["x"]},
    {"currency": "eur"}, {"currency": "EURO"}, {"invoice_id": ""}, {"invoice_id": 5}, {"supplier": ["s"]},
    {"supplier": "x" * 201}, {"invoice_id": "\ud800"}], ids=lambda o: str(o)[:30])
def test_invoice_fields_are_validated_not_coerced(over):
    _, key = make_tenant()
    r = client.post("/business-invoice-run", content=json.dumps({"invoice": {**INVOICE, **over}}),
                    headers={"X-API-Key": key, "Content-Type": "application/json"})
    assert r.status_code == 400, (r.status_code, r.text[:150])


def test_a_huge_or_non_finite_invoice_is_400():
    _, key = make_tenant()
    assert _invoice(key, note="x" * 70_000).status_code == 400
    r = client.post("/business-invoice-run", content=b'{"invoice": {"net": NaN}}',
                    headers={"X-API-Key": key, "Content-Type": "application/json"})
    assert r.status_code in (400, 422), r.status_code
    assert client.post("/business-invoice-run", json={"invoice": {**INVOICE, "x": float("1e5")}},
                       headers={"X-API-Key": key}).status_code == 200


# ------------------------------------------------------------------ Stripe
import hmac as _hmac

from app import stripe_webhook as sw
from app.models import StripeEvent
from sqlalchemy import select

WHSEC = "whsec_r5"


def _signed(event: dict) -> tuple[bytes, dict]:
    body = json.dumps(event).encode()
    ts = int(time.time())
    sig = _hmac.new(WHSEC.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return body, {"Stripe-Signature": f"t={ts},v1={sig}", "Content-Type": "application/json"}


def _checkout_event(tenant_id, event_id=None, **meta):
    return {"id": event_id or "evt_" + uuid.uuid4().hex, "type": "checkout.session.completed", "data": {"object": {
        "id": "cs_" + uuid.uuid4().hex, "payment_status": "paid", "status": "complete", "amount_total": 9900,
        "currency": "eur", "metadata": {"offer": sw.OLA_OFFER, "product": sw.OLA_PRODUCT, "task": "calculate 2 + 2",
                                         "tenant_id": tenant_id, **meta}}}}


@pytest.fixture
def stripe_env(monkeypatch):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", WHSEC)
    return monkeypatch


@pytest.mark.parametrize("meta", [{"product": ["x"]}, {"product": {"a": 1}}, {"offer": ["x"]}])
def test_stripe_unhashable_metadata_is_400_not_500(stripe_env, meta):
    tenant_id, _ = make_tenant()
    body, headers = _signed(_checkout_event(tenant_id, **meta))
    assert client.post("/stripe/webhook", content=body, headers=headers).status_code == 400


@pytest.mark.parametrize("status", [["complete"], {"a": 1}, 5])
def test_stripe_non_string_session_status_is_400_not_500(stripe_env, status):
    tenant_id, _ = make_tenant()
    event = _checkout_event(tenant_id)
    event["data"]["object"]["status"] = status
    body, headers = _signed(event)
    assert client.post("/stripe/webhook", content=body, headers=headers).status_code == 400


def test_a_failed_stripe_event_is_retried_once_and_a_completed_one_is_idempotent(stripe_env):
    tenant_id, _ = make_tenant()
    calls = []

    def flaky(tenant, task):
        calls.append(task)
        if len(calls) == 1:
            raise RuntimeError("transient")
        return {"status": "VERIFIED", "run_id": "run-" + uuid.uuid4().hex, "final_result": {"answer": 4}, "evidence_ids": []}

    stripe_env.setattr(sw, "run_agent_task", flaky)
    event = _checkout_event(tenant_id)
    body, headers = _signed(event)
    assert client.post("/stripe/webhook", content=body, headers=headers).status_code == 500
    with SessionLocal() as db:
        assert db.scalar(select(StripeEvent).where(StripeEvent.event_id == event["id"])).status == "FAILED"

    second = client.post("/stripe/webhook", content=body, headers=headers)      # Stripe re-delivers
    assert second.status_code == 200 and second.json()["status"] == "COMPLETED", second.text[:200]
    third = client.post("/stripe/webhook", content=body, headers=headers)
    assert third.status_code == 200 and third.json() == second.json()
    assert len(calls) == 2, "a COMPLETED event must never run the paid task again"


def test_only_one_concurrent_redelivery_may_claim_a_failed_event(stripe_env):
    tenant_id, _ = make_tenant()
    event = _checkout_event(tenant_id)
    with SessionLocal() as db:
        db.add(StripeEvent(id=str(uuid.uuid4()), event_id=event["id"], status="PROCESSING", task="calculate 2 + 2"))
        db.commit()
    body, headers = _signed(event)
    assert client.post("/stripe/webhook", content=body, headers=headers).status_code == 409   # in flight, not FAILED


# ------------------------------------------------------------------ standalone verifier provenance
@pytest.mark.parametrize("commit", ["", "UNKNOWN", "unknown", "  ", None])
def test_standalone_agent_verifier_refuses_a_blank_or_UNKNOWN_commit(commit):
    from scripts.verify_agent_runtime import verify
    out = verify("t", "r", commit, db_path="/nonexistent/never-opened.db")
    assert out["status"] == "BLOCK" and "provenance" in out["reason"], out


@pytest.mark.parametrize("sha", ["", "UNKNOWN", " unknown ", None])
def test_forensic_gate_does_not_bind_to_a_blank_or_UNKNOWN_source_sha(tmp_path, sha):
    from scripts.forensic_gate import _verify_source_binding
    for name, body in (("source.txt", "commit=UNKNOWN\n"), ("MANIFEST.json", '{"source_commit": "UNKNOWN"}'),
                       ("agent-run.json", '{"source_commit": "UNKNOWN"}'),
                       ("independent-verifier.json", '{"source_commit": "UNKNOWN"}')):
        (tmp_path / name).write_text(body)
    assert _verify_source_binding(tmp_path, sha)["status"] == "BLOCKED"


@pytest.mark.parametrize("content", [b"[]", b"null", b"not json", b'{"report_sha256": 5}', b'{"report_sha256": ["x"]}',
                                     b'{"report_sha256": "a", "report_sha256": "b"}', b'{"x": NaN, "report_sha256": "a"}',
                                     b"\xff\xfe", b""])
def test_decision_report_verifier_blocks_garbage_without_a_traceback(tmp_path, content):
    import subprocess, sys
    path = tmp_path / "r.json"
    path.write_bytes(content)
    r = subprocess.run([sys.executable, "scripts/verify_decision_report.py", str(path)], capture_output=True, text=True)
    assert r.returncode == 1 and "DECISION_REPORT=BLOCK" in r.stdout and "Traceback" not in r.stderr, (r.stdout, r.stderr[-200:])
    missing = subprocess.run([sys.executable, "scripts/verify_decision_report.py", str(tmp_path / "nope.json")],
                             capture_output=True, text=True)
    assert missing.returncode == 1 and "Traceback" not in missing.stderr


def test_every_workflow_declares_least_privilege_permissions():
    import pathlib
    missing = [p.name for p in sorted(pathlib.Path(".github/workflows").glob("*.yml"))
               if not any(line.startswith("permissions:") for line in p.read_text().splitlines())]
    assert missing == [], f"workflows without a top-level `permissions:` block: {missing}"


# ------------------------------------------------------------------ /chat honesty
def test_chat_rejects_malformed_messages_with_400(monkeypatch):
    _, key = make_tenant()
    monkeypatch.setattr("app.main.chat", lambda t, m: pytest.fail("the model must not be called"))
    for messages in ([{"role": "system", "content": "x"}], [{"role": ["user"], "content": "x"}],
                     [{"role": "user", "content": 5}], ["x"], [], "x"):
        r = client.post("/chat", json={"messages": messages}, headers={"X-API-Key": key})
        assert r.status_code == 400, (messages, r.status_code)
    r = client.post("/chat", content=json.dumps({"messages": [{"role": "user", "content": "\ud800"}]}),
                    headers={"X-API-Key": key, "Content-Type": "application/json"})
    assert r.status_code == 400


def test_chat_never_says_verified_without_an_independent_judge(monkeypatch):
    _, key = make_tenant()
    monkeypatch.setattr("app.main.chat", lambda t, m: {"status": "VERIFIED", "message": "hi", "model": "m"})
    r = client.post("/chat", json={"messages": [{"role": "user", "content": "q"}]}, headers={"X-API-Key": key})
    assert r.json()["status"] == "UNKNOWN" and r.json()["verification"] == "NOT_JUDGED"


# ------------------------------------------------------------------ task / reason validation
@pytest.mark.parametrize("route", ["/audit", "/agent-run"])
@pytest.mark.parametrize("task", [None, 5, ["x"], "", "   ", "x" * 8001, "\ud800"], ids=lambda t: str(t)[:12])
def test_task_routes_validate_the_task_with_400(route, task):
    _, key = make_tenant()
    r = client.post(route, content=json.dumps({"task": task}), headers={"X-API-Key": key, "Content-Type": "application/json"})
    assert r.status_code == 400, (route, r.status_code, r.text[:120])
