"""Sixth review, application layer: request guard, append-only trigger repair, database errors, input validation.

Findings covered: over-limit body (never run on a truncated prefix), trigger repair as one transaction, the
OperationalError / pool-timeout / unhandled-error handlers, one shared text validator, ambient retry budget,
blank-looking human names, security headers on 500 and CSP only on the product page, the webhook budget behind
--root-path, OLA_DB_BUSY_MS range, payload depth cap and /evidence/{id} readability, /chat without a text answer.
"""
import asyncio
import hashlib
import json
import logging
import os
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError

from app import ambient, database
from app import main as appmain
from app.database import SessionLocal, engine, install_append_only_triggers
from app.http_guard import HttpGuard, max_body_bytes, route_path
from app.main import app
from app.models import ApiKey, EvidenceRecord, Tenant

REPO_ROOT = Path(__file__).resolve().parents[1]
client = TestClient(app, raise_server_exceptions=False)
JSON = {"Content-Type": "application/json"}


def make_tenant():
    tenant_id, key = str(uuid.uuid4()), "r6-" + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="r6"))
        db.add(ApiKey(id=str(uuid.uuid4()), tenant_id=tenant_id, key_hash=hashlib.sha256(key.encode()).hexdigest()))
        db.commit()
    return tenant_id, key


def count_records(tenant_id):
    with SessionLocal() as db:
        return db.scalar(select(func.count()).select_from(EvidenceRecord).where(EvidenceRecord.tenant_id == tenant_id))


# ------------------------------------------------------------------ a tiny ASGI driver (no server, no socket)
class Reply:
    def __init__(self, sent, receive_calls):
        start = next((m for m in sent if m["type"] == "http.response.start"), None)
        self.status = start["status"] if start else None
        self.headers = {}
        for name, value in (start or {}).get("headers", []):
            self.headers.setdefault(name.decode().lower(), []).append(value.decode("latin-1"))
        self.body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
        self.starts = sum(1 for m in sent if m["type"] == "http.response.start")
        self.receive_calls = receive_calls

    def header(self, name):
        values = self.headers.get(name)
        return values[0] if values else None


def asgi(method, path, headers=(), chunks=(b"",), root_path="", target=None):
    """Delivers `chunks` as separate http.request messages (what a chunked upload looks like to the application)."""
    target = target or app
    scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1", "method": method,
             "scheme": "http", "path": path, "raw_path": path.encode(), "query_string": b"", "root_path": root_path,
             "headers": [(k.lower().encode(), v.encode()) for k, v in headers], "client": ("127.0.0.1", 1),
             "server": ("testserver", 80)}
    pending, sent, calls = list(chunks), [], {"receive": 0}

    async def receive():
        calls["receive"] += 1
        if pending:
            body = pending.pop(0)
            return {"type": "http.request", "body": body, "more_body": bool(pending)}
        await asyncio.sleep(0.05)
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    asyncio.run(target(scope, receive, send))
    return Reply(sent, calls["receive"])


# ------------------------------------------------------------------ 1. over-limit body
def test_an_over_limit_chunked_body_never_runs_the_handler():
    tenant, key = make_tenant()
    before = count_records(tenant)
    # a complete, valid JSON request followed by padding: the application used to run on that prefix and the caller
    # still got 413
    reply = asgi("POST", "/evidence", [("x-api-key", key), ("content-type", "application/json")],
                 chunks=[b'{"payload":{"a":1}}', b" " * 1_048_577])
    assert reply.status == 413 and reply.starts == 1
    assert count_records(tenant) == before, "a rejected request must have no side effect"
    # the same when the very first message already exceeds the budget
    reply = asgi("POST", "/evidence", [("x-api-key", key), ("content-type", "application/json")],
                 chunks=[b'{"payload":{"a":1}}' + b" " * 1_048_577])
    assert reply.status == 413 and count_records(tenant) == before


def test_the_budget_is_exact_and_the_413_closes_the_connection(monkeypatch):
    tenant, key = make_tenant()
    monkeypatch.setenv("OLA_MAX_BODY_BYTES", "2000")
    head = [("x-api-key", key), ("content-type", "application/json")]

    def body_of(size):
        raw = ('{"payload":{"a":"%s"}}' % ("x" * (size - 20))).encode()
        assert len(raw) == size
        return raw

    ok = asgi("POST", "/evidence", head, chunks=[body_of(2000)[:700], body_of(2000)[700:]])
    assert ok.status == 200, ok.body[:100]
    before = count_records(tenant)
    over = asgi("POST", "/evidence", head, chunks=[body_of(2001)[:700], body_of(2001)[700:]])
    assert over.status == 413 and over.header("connection") == "close" and count_records(tenant) == before
    declared = asgi("POST", "/evidence", head + [("content-length", "2001")], chunks=[body_of(2001)])
    assert declared.status == 413 and declared.header("connection") == "close"


@pytest.mark.parametrize("values", [["99999999", "10"], ["10", "99999999"], ["abc"], ["-1"], ["+5"], ["1_0"], [""], ["9" * 4400]],
                         ids=lambda v: "|".join(x[:12] for x in v))
def test_every_content_length_header_must_be_a_plain_number_within_the_budget(values):
    tenant, key = make_tenant()
    headers = [("x-api-key", key), ("content-type", "application/json")] + [("content-length", v) for v in values]
    reply = asgi("POST", "/evidence", headers, chunks=[b'{"payload":{}}'])
    assert reply.status == 413 and count_records(tenant) == 0


def test_a_plain_small_content_length_is_not_touched():
    tenant, key = make_tenant()
    body = b'{"payload":{}}'
    reply = asgi("POST", "/evidence", [("x-api-key", key), ("content-type", "application/json"),
                                       ("content-length", str(len(body)))], chunks=[body])
    assert reply.status == 200 and count_records(tenant) == 1


def test_a_failure_caused_by_the_abort_is_still_answered_with_413():
    async def fails_when_the_client_goes_away(scope, receive, send):
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                raise RuntimeError("client went away")
            if not message.get("more_body"):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"done"})

    reply = asgi("POST", "/x", chunks=[b"a" * 700_000, b"a" * 700_000], target=HttpGuard(fails_when_the_client_goes_away))
    assert reply.status == 413


def test_a_genuine_application_error_is_not_swallowed():
    async def broken(scope, receive, send):
        raise RuntimeError("real bug")

    with pytest.raises(RuntimeError, match="real bug"):
        asgi("GET", "/x", target=HttpGuard(broken))


def test_a_response_that_already_started_is_not_cut_short():
    async def answers_early(scope, receive, send):
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"text/plain"), (b"content-length", b"10")]})
        await send({"type": "http.response.body", "body": b"hello", "more_body": True})
        while True:
            message = await receive()
            if message["type"] == "http.disconnect" or not message.get("more_body"):
                break
        await send({"type": "http.response.body", "body": b"world", "more_body": False})

    reply = asgi("POST", "/x", chunks=[b"a" * 700_000, b"a" * 700_000], target=HttpGuard(answers_early))
    assert reply.status == 200 and reply.body == b"helloworld" and reply.starts == 1


def test_websocket_and_lifespan_scopes_pass_straight_through():
    seen = []

    async def probe(scope, receive, send):
        seen.append(scope["type"])

    async def go():
        guard = HttpGuard(probe)
        await guard({"type": "websocket", "path": "/stripe/webhook", "headers": []}, None, None)
        await guard({"type": "lifespan"}, None, None)

    asyncio.run(go())
    assert seen == ["websocket", "lifespan"]


def test_the_webhook_handler_is_not_called_for_an_over_budget_body(monkeypatch):
    calls = []
    monkeypatch.setattr(appmain, "process_checkout_event", lambda *a, **k: calls.append(a), raising=False)
    reply = asgi("POST", "/stripe/webhook", [("stripe-signature", "t=1,v1=00")], chunks=[b"{}", b" " * 70_000])
    assert reply.status == 413 and calls == []


# ------------------------------------------------------------------ 10. the webhook budget behind --root-path
def test_the_webhook_budget_survives_a_root_path():
    body = b"x" * 100_000
    headers = [("stripe-signature", "t=1,v1=00"), ("content-length", str(len(body)))]
    # uvicorn --root-path /api: scope["path"] is "/api/stripe/webhook", scope["root_path"] is "/api"
    assert asgi("POST", "/api/stripe/webhook", headers, chunks=[body], root_path="/api").status == 413
    assert asgi("POST", "/stripe/webhook", headers, chunks=[body]).status == 413
    assert asgi("POST", "/stripe/webhook/", headers, chunks=[body]).status == 413
    # every other route keeps the default budget under a prefix: 100 KB is not too big there (the route answers, here 422
    # for the missing key header, instead of the guard's 413)
    assert asgi("POST", "/api/evidence", headers[1:], chunks=[body], root_path="/api").status in (401, 422)


def test_route_path_and_budget_helpers():
    assert route_path({"path": "/api/stripe/webhook", "root_path": "/api"}) == "/stripe/webhook"
    assert route_path({"path": "/api", "root_path": "/api"}) == "/"
    assert route_path({"path": "/apix/y", "root_path": "/api"}) == "/apix/y"
    assert route_path({"path": "/a", "root_path": ""}) == "/a"
    assert max_body_bytes("/stripe/webhook") == 65_536 and max_body_bytes("/stripe/webhook/") == 65_536
    assert max_body_bytes("//stripe/webhook") == 1_048_576 and max_body_bytes("/evidence") == 1_048_576


# ------------------------------------------------------------------ 9. headers on 500, CSP only on the page
def test_an_unhandled_error_is_a_json_500_with_the_security_headers_and_no_details(monkeypatch):
    _, key = make_tenant()

    def boom(_key):
        raise RuntimeError("internal secret detail")

    monkeypatch.setattr(appmain, "tenant_from_key", boom)
    r = client.post("/evidence", json={"payload": {}}, headers={"X-API-Key": key})
    assert r.status_code == 500 and r.json() == {"detail": "internal server error"}
    assert "internal secret detail" not in r.text
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer" and r.headers["cache-control"] == "no-store"
    assert "content-security-policy" not in r.headers
    # the server still gets the exception (that is how it is logged)
    with pytest.raises(RuntimeError, match="internal secret detail"):
        TestClient(app).post("/evidence", json={"payload": {}}, headers={"X-API-Key": key})


def test_the_csp_is_only_on_the_product_page():
    page = client.get("/")
    assert page.status_code == 200 and "default-src 'self'" in page.headers["content-security-policy"]
    for path in ("/docs", "/redoc", "/openapi.json", "/health", "/nope"):
        r = client.get(path)
        assert "content-security-policy" not in r.headers, path
        assert r.headers["x-content-type-options"] == "nosniff", path
    assert "content-security-policy" in asgi("GET", "/api/", root_path="/api").headers


# ------------------------------------------------------------------ 11. OLA_DB_BUSY_MS
@pytest.fixture
def fresh_pool(monkeypatch):
    """Environment changes take effect on NEW connections: drop the pooled ones before and after."""
    engine.dispose()
    yield monkeypatch
    monkeypatch.undo()
    engine.dispose()


@pytest.mark.parametrize("raw,expected", [
    ("abc", 30000), ("", 30000), ("   ", 30000), ("-1", 30000), ("0", 30000), ("1e3", 30000), ("1_000", 30000), ("1.5", 30000),
    ("600001", 30000), ("2147483648", 30000), ("99999999999999999999", 30000), ("٣٠", 30000),
    ("1", 1), ("250", 250), (" 500 ", 500), ("600000", 600000)])
def test_busy_timeout_accepts_only_1_to_600000(fresh_pool, raw, expected):
    fresh_pool.setenv("OLA_DB_BUSY_MS", raw)
    assert database._busy_ms() == expected
    with engine.connect() as conn:
        assert conn.exec_driver_sql("PRAGMA busy_timeout").scalar() == expected


def test_busy_timeout_default_when_unset(fresh_pool):
    fresh_pool.delenv("OLA_DB_BUSY_MS", raising=False)
    assert database._busy_ms() == 30000


# ------------------------------------------------------------------ 2. trigger repair
@contextmanager
def traced_connections():
    statements = []

    def on_connect(dbapi_conn, _record):
        dbapi_conn.set_trace_callback(lambda sql: statements.append(" ".join(sql.split())[:90]))

    event.listen(engine, "connect", on_connect)
    engine.dispose()
    try:
        yield statements
    finally:
        event.remove(engine, "connect", on_connect)
        engine.dispose()


def neuter_triggers():
    with engine.begin() as conn:
        conn.exec_driver_sql("DROP TRIGGER IF EXISTS evidence_no_update")
        conn.exec_driver_sql("DROP TRIGGER IF EXISTS evidence_no_delete")
        conn.exec_driver_sql("CREATE TRIGGER evidence_no_update BEFORE UPDATE ON evidence_records WHEN 0 BEGIN SELECT 1; END;")
        conn.exec_driver_sql("CREATE TRIGGER evidence_no_delete BEFORE DELETE ON evidence_records WHEN 0 BEGIN SELECT 1; END;")


def triggers_are_right():
    with engine.connect() as conn:
        rows = dict(conn.exec_driver_sql("SELECT name, sql FROM sqlite_master WHERE type='trigger'").all())
    return all(name in rows and database._norm(rows[name]) == database._norm(sql) for name, sql in database._TRIGGERS.items())


def test_the_repair_is_one_write_transaction_and_a_second_run_changes_nothing():
    neuter_triggers()
    with traced_connections() as statements:
        install_append_only_triggers()
        first = list(statements)
        statements.clear()
        install_append_only_triggers()
        second = list(statements)
    assert triggers_are_right()
    begin, commit = first.index("BEGIN IMMEDIATE"), first.index("COMMIT")
    inside = first[begin + 1:commit]
    assert any(s.startswith("DROP TRIGGER IF EXISTS evidence_no_update") for s in inside)
    assert any(s.startswith("CREATE TRIGGER evidence_no_update") for s in inside)
    assert not any(s.upper().startswith(("BEGIN ", "COMMIT", "ROLLBACK")) for s in inside)
    assert not any(s.startswith(("DROP", "CREATE")) for s in second), second          # already right: nothing to do


def test_a_failing_repair_leaves_the_old_trigger_in_force(monkeypatch):
    tenant, key = make_tenant()
    record = client.post("/evidence", json={"payload": {"a": 1}}, headers={"X-API-Key": key}).json()
    with engine.begin() as conn:                      # protective, but not the expected text (an older release's message)
        conn.exec_driver_sql("DROP TRIGGER evidence_no_update")
        conn.exec_driver_sql("CREATE TRIGGER evidence_no_update BEFORE UPDATE ON evidence_records "
                             "BEGIN SELECT RAISE(ABORT, 'legacy append-only message'); END;")
    try:
        monkeypatch.setitem(database._TRIGGERS, "evidence_no_update",
                            "CREATE TRIGGER evidence_no_update BEFORE UPDATE ON evidence_records "
                            "BEGIN SELECT RAISE(ABORT, 'x') END;")                      # syntax error: the CREATE fails
        with pytest.raises(OperationalError):
            install_append_only_triggers()
        with engine.connect() as conn:
            stored = conn.exec_driver_sql("SELECT sql FROM sqlite_master WHERE name='evidence_no_update'").scalar()
        assert stored and "legacy append-only message" in stored, "the DROP must have been rolled back"
        with pytest.raises(Exception, match="legacy append-only message"):
            with engine.begin() as conn:
                conn.exec_driver_sql("UPDATE evidence_records SET payload_json='{}' WHERE id=?", (record["id"],))
    finally:
        monkeypatch.undo()
        install_append_only_triggers()
    assert triggers_are_right()


def test_a_locked_database_aborts_the_repair_without_touching_the_triggers(fresh_pool):
    neuter_triggers()
    fresh_pool.setenv("OLA_DB_BUSY_MS", "50")
    engine.dispose()
    holder = sqlite3.connect(database.DB_PATH, timeout=1)
    try:
        holder.execute("BEGIN IMMEDIATE")
        with pytest.raises(OperationalError, match="locked"):
            install_append_only_triggers()
    finally:
        holder.rollback()
        holder.close()
    with engine.connect() as conn:
        sql = conn.exec_driver_sql("SELECT sql FROM sqlite_master WHERE name='evidence_no_update'").scalar()
    assert sql and "WHEN 0" in sql                    # untouched (still the neutered one), not dropped
    fresh_pool.undo()
    install_append_only_triggers()
    assert triggers_are_right()


def test_several_threads_repairing_at_once_never_crash():
    errors = []
    workers = 6
    for _ in range(12):
        neuter_triggers()
        barrier = threading.Barrier(workers)

        def worker():
            try:
                barrier.wait(timeout=10)
                install_append_only_triggers()
            except Exception as exc:                  # noqa: BLE001
                errors.append(f"{type(exc).__name__}: {str(exc).splitlines()[0]}")

        threads = [threading.Thread(target=worker) for _ in range(workers)]
        [t.start() for t in threads]
        [t.join(timeout=60) for t in threads]
        assert triggers_are_right()
    assert errors == []


def test_several_processes_starting_at_once_never_crash():
    child = ("import os, sys, time\nsys.path.insert(0, os.getcwd())\nstart = float(sys.argv[1])\n"
             "from app.database import install_append_only_triggers\n"
             "while time.time() < start: pass\ninstall_append_only_triggers()\nprint('OK')\n")
    env = dict(os.environ, OLA_EG_DB_PATH=database.DB_PATH)
    for _ in range(3):
        neuter_triggers()
        start = time.time() + 3.0
        procs = [subprocess.Popen([sys.executable, "-c", child, str(start)], cwd=str(REPO_ROOT), env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(5)]
        for proc in procs:
            out, err = proc.communicate(timeout=120)
            assert proc.returncode == 0 and out.strip() == "OK", err[-400:]
        assert triggers_are_right()


# ------------------------------------------------------------------ 4/5. database error handlers
def _sqlite_error(message, code=None):
    err = sqlite3.OperationalError(message)
    if code is not None:
        err.sqlite_errorcode = code
    return err


@pytest.mark.parametrize("orig,expected", [
    (_sqlite_error("whatever", 5), True), (_sqlite_error("whatever", 6), True), (_sqlite_error("whatever", 5 | (1 << 8)), True),
    (_sqlite_error("database is locked"), True), (_sqlite_error("database table is locked"), True),
    (_sqlite_error("disk I/O error", 10), False), (_sqlite_error("attempt to write a readonly database", 8), False),
    (_sqlite_error("no such table: x"), False)])
def test_lock_errors_are_recognised_from_the_dbapi_error_only(orig, expected):
    exc = OperationalError("INSERT ... payload 'database is locked' busy", {"p": "locked busy database is locked"}, orig)
    assert appmain._is_lock_error(exc) is expected


def test_real_sqlite_errors_are_classified_correctly(fresh_pool):
    fresh_pool.setenv("OLA_DB_BUSY_MS", "50")
    engine.dispose()
    holder = sqlite3.connect(database.DB_PATH, timeout=1)
    try:
        holder.execute("BEGIN IMMEDIATE")
        with pytest.raises(OperationalError) as locked:
            with engine.begin() as conn:
                conn.exec_driver_sql("INSERT INTO tenants (id, name) VALUES ('r6-lock-probe', 'x')")
    finally:
        holder.rollback()
        holder.close()
    assert appmain._is_lock_error(locked.value)
    with engine.connect() as conn:
        conn.exec_driver_sql("PRAGMA query_only=ON")
        try:
            with pytest.raises(OperationalError) as readonly:
                conn.exec_driver_sql("INSERT INTO tenants (id, name) VALUES ('r6-ro-probe', 'locked busy')")
        finally:
            conn.rollback()
            conn.exec_driver_sql("PRAGMA query_only=OFF")
    assert not appmain._is_lock_error(readonly.value)


def test_a_non_lock_database_error_is_a_logged_500_whatever_the_payload_says(caplog):
    _, key = make_tenant()

    def read_only(dbapi_conn, _record):
        dbapi_conn.execute("PRAGMA query_only=ON")

    event.listen(engine, "connect", read_only)
    engine.dispose()                                  # every new connection is read-only: "attempt to write a readonly database"
    try:
        with caplog.at_level(logging.ERROR, logger="ola.app"):
            for note in ("plain", "busy", "locked", "database is locked"):
                r = client.post("/evidence", json={"payload": {"note": note}}, headers={"X-API-Key": key})
                assert r.status_code == 500 and r.json() == {"detail": "database error"}, (note, r.status_code, r.text[:80])
                assert "retry-after" not in r.headers
                assert "INSERT" not in r.text and "payload" not in r.text and "readonly" not in r.text
    finally:
        event.remove(engine, "connect", read_only)
        engine.dispose()
    messages = [rec.getMessage() for rec in caplog.records if rec.name == "ola.app"]
    assert len(messages) == 4 and all("readonly" in m for m in messages), messages
    assert not any("INSERT" in m or "busy" in m.replace("database busy", "") for m in messages), "no SQL/parameters in the log"


def test_pool_exhaustion_is_a_503_with_retry_after(monkeypatch):
    _, key = make_tenant()
    monkeypatch.setattr(engine.pool, "_timeout", 0.2)
    held = []
    try:
        while True:                                   # check out every connection the pool will give
            try:
                held.append(engine.connect())
            except PoolTimeoutError:
                break
        r = client.post("/evidence", json={"payload": {}}, headers={"X-API-Key": key})
    finally:
        for conn in held:
            conn.close()
    assert r.status_code == 503 and r.headers["retry-after"] == "2" and r.json() == {"detail": "database busy, retry"}


def test_a_pool_timeout_raised_anywhere_is_a_503(monkeypatch):
    def timeout(_key):
        raise PoolTimeoutError("QueuePool limit of size 5 overflow 10 reached, connection timed out, timeout 30.00")

    monkeypatch.setattr(appmain, "tenant_from_key", timeout)
    r = client.post("/evidence", json={"payload": {}}, headers={"X-API-Key": "k"})
    assert r.status_code == 503 and r.headers["retry-after"] == "2" and "QueuePool" not in r.text


# ------------------------------------------------------------------ 6. one text validator
def _post(route, body, key, raw=False):
    content = body if raw else json.dumps(body)
    return client.post(route, content=content, headers={**JSON, "X-API-Key": key})


BAD_TEXT = [("lone surrogate", "a\ud800b"), ("NUL", "a\x00b"), ("too long", "x" * 8001)]


def test_checkout_validates_before_the_stripe_session_is_created(monkeypatch):
    _, key = make_tenant()
    created = []

    def fake_create(task, success_url, cancel_url, tenant_id):
        created.append((task, success_url, cancel_url))
        return {"id": "cs_test", "url": "https://checkout.invalid/x", "amount_total": 9900}

    monkeypatch.setattr(appmain, "create_checkout", fake_create)
    for label, bad in BAD_TEXT + [("non-string", 5), ("list", ["x"]), ("blank", "   "), ("missing", None)]:
        r = _post("/checkout", {"task": bad}, key)
        assert r.status_code == 400, (label, r.status_code, r.text[:80])
    for field in ("success_url", "cancel_url"):
        for label, bad in BAD_TEXT[:2] + [("non-string", ["x"])]:
            r = _post("/checkout", {"task": "pay for audit", field: bad}, key)
            assert r.status_code == 400, (field, label, r.status_code)
    assert created == [], "no Stripe session may exist after a rejected request"
    ok = _post("/checkout", {"task": "  pay for audit  "}, key)
    assert ok.status_code == 200 and ok.json()["status"] == "READY_FOR_PAYMENT"
    assert created == [("pay for audit", "http://localhost:8000/payment-success", "http://localhost:8000/")]


def test_checkout_says_before_payment_whether_the_task_can_be_computed(monkeypatch):
    tenant_id, key = make_tenant()
    monkeypatch.setattr(appmain, "create_checkout", lambda task, ok, cancel, tenant: {
        "id": "cs_" + uuid.uuid4().hex, "url": "https://checkout.invalid/x", "amount_total": 9900})
    computable = _post("/checkout", {"task": "Calculate 17 * 23 and return the verified result."}, key).json()
    assert computable["status"] == "READY_FOR_PAYMENT"
    assert computable["computation_expected"] == "PERFORMED" and "notice" not in computable
    free_text = _post("/checkout", {"task": "summarise my supplier contract"}, key).json()
    assert free_text["status"] == "READY_FOR_PAYMENT", "a notice is not a refusal: refusing is a product decision"
    assert free_text["computation_expected"] == "NOT_PERFORMED"
    assert "UNKNOWN" in free_text["notice"] and "NOT_PERFORMED" in free_text["notice"]
    with SessionLocal() as db:
        recorded = [json.loads(row.payload_json) for row in db.scalars(
            select(EvidenceRecord).where(EvidenceRecord.tenant_id == tenant_id,
                                         EvidenceRecord.record_type == "revenue.checkout_created").order_by(EvidenceRecord.seq))]
    assert [p["computation_expected"] for p in recorded] == ["PERFORMED", "NOT_PERFORMED"]


@pytest.mark.parametrize("task", ["Calculate 17 * 23 and return the verified result.", "17 * 23", "calculate -4 + 10 // 3",
                                  "Calculate 1/0", "summarise my supplier contract", "calculate True", "calculate 2 ** 8",
                                  "calculate the VAT of my invoice"])
def test_what_checkout_announces_is_what_the_paid_run_then_does(task):
    from app.agent_runtime import run_agent_task, task_is_computable
    tenant_id, _ = make_tenant()
    announced = "PERFORMED" if task_is_computable(task) else "NOT_PERFORMED"
    ran = run_agent_task(tenant_id, task)
    assert ran["computation"] == announced, (task, ran["status"], ran["computation"])
    assert (ran["status"] == "VERIFIED") == (announced == "PERFORMED"), (task, ran["status"])


def test_a_task_that_is_not_text_is_not_computable():
    from app.agent_runtime import task_is_computable
    assert not task_is_computable(None) and not task_is_computable(5) and not task_is_computable(["1 + 1"])


@pytest.mark.parametrize("route", ["/nina-run", "/pipeline-run"])
def test_requested_tools_are_validated(route):
    _, key = make_tenant()
    base = {"task": "calculate 2 + 2", "human_approved": False}
    for label, bad in BAD_TEXT:
        r = _post(route, {**base, "requested_tools": [bad]}, key)
        assert r.status_code == 400, (route, label, r.status_code, r.text[:80])
    for label, bad in [("number", [5]), ("null", [None]), ("nested list", [["x"]]), ("dict", [{"a": 1}]), ("not a list", "x")]:
        r = _post(route, {**base, "requested_tools": bad}, key)
        assert r.status_code == 400, (route, label, r.status_code, r.text[:80])


def test_a_good_tool_list_still_runs():
    _, key = make_tenant()
    r = _post("/nina-run", {"task": "calculate 2 + 2", "requested_tools": ["safe_expression"]}, key)
    assert r.status_code == 200 and r.json()["nina"]["status"] != "BLOCK"


def test_firewall_approve_rejects_bad_text_with_400_not_500():
    _, key = make_tenant()
    good = {"request_id": "req-1", "approver_id": "approver", "reason": "looks fine"}
    for field in good:
        for label, bad in BAD_TEXT[:2]:
            r = _post("/firewall/approve", {**good, field: bad}, key)
            assert r.status_code == 400, (field, label, r.status_code, r.text[:80])
    assert _post("/firewall/approve", good, key).status_code != 500


def test_the_task_routes_reject_a_nul_character():
    _, key = make_tenant()
    for route in ("/audit", "/agent-run"):
        assert _post(route, {"task": "calculate 1\x00"}, key).status_code == 400


# ------------------------------------------------------------------ 7. ambient retry budget
def test_ambient_records_use_the_same_retry_budget_as_the_rest_of_the_app(monkeypatch):
    seen = {}

    def fake_append(tenant_id, rtype, payload, **kwargs):
        seen.update(kwargs)
        return {"seq": 0}

    monkeypatch.setattr(ambient.pb, "append_evidence", fake_append)
    ambient._record("t", "igor.shadow", "chat", "shadow", "task", "output",
                    {"verdict": "ACCEPT", "detail": "", "quality_score": 90, "judge": {}}, enforced=False)
    assert seen == {"attempts": 96}


def test_a_burst_of_ambient_records_for_one_tenant_all_land():
    tenant, _ = make_tenant()
    verdict = {"verdict": "ACCEPT", "detail": "", "quality_score": 90, "judge": {}}
    errors, barrier = [], threading.Barrier(24)

    def worker():
        barrier.wait(timeout=10)
        for _ in range(5):
            try:
                ambient._record(tenant, "igor.shadow", "chat", "shadow", "t", "o", verdict, enforced=False)
            except Exception as exc:                  # noqa: BLE001
                errors.append(f"{type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=worker) for _ in range(24)]
    [t.start() for t in threads]
    [t.join(timeout=120) for t in threads]
    assert errors == [] and count_records(tenant) == 120


# ------------------------------------------------------------------ 8. blank-looking human names
BLANKS = ["ㅤ", "ﾠ", "ᅟ", "ᅠ", "⠀", "​", "́", "͏", "឴", "᠋", " ", " ",
          "‮", "️", " \t\n", "ㅤ⠀́ "]


@pytest.mark.parametrize("blank", BLANKS, ids=lambda b: "U+" + "+".join(f"{ord(c):04X}" for c in b))
def test_a_name_that_renders_as_nothing_is_not_a_name(blank):
    with pytest.raises(appmain.HTTPException) as caught:
        appmain._visible_text(blank, "human_actor", 200, required=True)
    assert caught.value.status_code == 400


def test_the_human_gate_endpoint_refuses_blank_looking_actor_and_reason():
    _, key = make_tenant()
    for field in ("human_actor", "human_reason"):
        body = {"task": "calculate 2 + 2", "human_approved": True, "human_actor": "reviewer-1", "human_reason": "checked",
                field: "ㅤ⠀"}
        r = _post("/pipeline-run", body, key)
        assert r.status_code == 400 and "visible" in r.json()["detail"], (field, r.status_code, r.text[:100])


@pytest.mark.parametrize("name", ["reviewer-1", "Łukasz", "Zoë", "田中", "aㅤ", "ㅤb", "Jörg ", "x"])
def test_real_names_still_pass(name):
    assert appmain._visible_text(name, "human_actor", 200, required=True) == name


# ------------------------------------------------------------------ 12. payload depth and readability
def nested_dict(levels):
    node = {}
    for _ in range(levels - 1):
        node = {"k": node}
    return node


def nested_list(levels):
    node = []
    for _ in range(levels - 1):
        node = [node]
    return node


def test_payload_nesting_is_capped_at_32_levels():
    _, key = make_tenant()
    assert appmain._nesting_depth(nested_dict(32), 99) == 32 and appmain._nesting_depth({"a": 1}, 99) == 1
    for payload in (nested_dict(32), {"a": nested_list(31)}):                                   # 32 levels: accepted
        assert client.post("/evidence", json={"payload": payload}, headers={"X-API-Key": key}).status_code == 200
    for payload in (nested_dict(33), {"a": nested_list(32)}, {"a": [{"b": nested_dict(31)}]}):   # 33 levels: refused
        r = client.post("/evidence", json={"payload": payload}, headers={"X-API-Key": key})
        assert r.status_code == 400 and "nesting" in r.json()["detail"], r.text[:100]


def test_a_very_deep_payload_is_a_400_from_the_cap_not_a_stack_problem():
    _, key = make_tenant()
    for depth in (1000, 5000):
        raw = '{"payload":{"a":%s%s}}' % ("[" * depth, "]" * depth)
        r = client.post("/evidence", content=raw.encode(), headers={**JSON, "X-API-Key": key})
        assert r.status_code == 400 and "nesting" in r.json()["detail"], (depth, r.status_code, r.text[:100])
    raw = '{"payload":{"a":%s%s}}' % ("[" * 300_000, "]" * 300_000)                                # parser limit: still a 400
    assert client.post("/evidence", content=raw.encode(), headers={**JSON, "X-API-Key": key}).status_code == 400
    wide = {"payload": {f"k{i}": {"v": [i]} for i in range(5000)}}                                 # wide is fine
    assert client.post("/evidence", json=wide, headers={"X-API-Key": key}).status_code == 200


def test_a_stored_record_can_always_be_read_back():
    tenant, key = make_tenant()
    texts = {
        "normal": '{"a":1}',
        "deep (written before the cap)": '{"a":' + "[" * 200 + "]" * 200 + "}",
        "very deep (parser and encoder limits depend on the interpreter)": '{"a":' + "[" * 3000 + "]" * 3000 + "}",
        "NaN (written before NaN was refused)": '{"a":NaN}',
        "not JSON at all": "not json {",
        "absurdly deep": "[" * 250_000 + "]" * 250_000,
    }
    ids = {}
    with SessionLocal() as db:
        for seq, (label, text) in enumerate(texts.items()):
            row = EvidenceRecord(id=str(uuid.uuid4()), tenant_id=tenant, seq=seq, prev_hash="0" * 64,
                                 record_hash=hashlib.sha256(text.encode()).hexdigest(), record_type="generic", payload_json=text)
            db.add(row)
            ids[label] = row.id
        db.commit()
    for label, record_id in ids.items():
        r = client.get(f"/evidence/{record_id}", headers={"X-API-Key": key})
        assert r.status_code == 200, (label, r.status_code, r.text[:80])
        body = r.json()
        assert body["id"] == record_id and body["tenant_id"] == tenant and body["record_hash"]
        if label in ("normal", "deep (written before the cap)"):
            assert "payload_error" not in body and body["payload"] is not None
        elif label.startswith("very deep"):
            # readable where the interpreter's parser and encoder allow it, the raw text otherwise: never a 500
            assert (body["payload"] is not None and "payload_error" not in body) or (
                body["payload"] is None and body["payload_json"] == texts[label] and "payload_error" in body)
        else:
            assert body["payload"] is None and body["payload_json"] == texts[label] and "strict JSON" in body["payload_error"]
    # unchanged shape for a normal record written through the API
    posted = client.post("/evidence", json={"payload": {"a": [1, {"b": "é"}]}}, headers={"X-API-Key": key}).json()
    got = client.get(f"/evidence/{posted['id']}", headers={"X-API-Key": key}).json()
    assert got["payload"] == {"a": [1, {"b": "é"}]} and list(got) == ["id", "tenant_id", "seq", "record_type", "payload", "prev_hash", "record_hash"]


# ------------------------------------------------------------------ S1. /chat
@pytest.mark.parametrize("answer", [{"status": "VERIFIED", "model": "m"}, {"status": "VERIFIED", "message": None, "model": "m"},
                                    {"status": "VERIFIED", "message": 5, "model": "m"}, {"status": "VERIFIED", "message": ["x"], "model": "m"},
                                    {"status": "VERIFIED", "message": {"a": 1}, "model": "m"}], ids=str)
@pytest.mark.parametrize("mode", ["", "off", "shadow"])
def test_chat_never_passes_on_verified_without_a_text_answer(monkeypatch, mode, answer):
    _, key = make_tenant()
    monkeypatch.setenv("OLA_AMBIENT_IGOR", mode)
    monkeypatch.setattr(appmain, "chat", lambda tenant, messages: dict(answer))
    r = client.post("/chat", json={"messages": [{"role": "user", "content": "q"}]}, headers={"X-API-Key": key})
    assert r.status_code == 200
    assert r.json()["status"] == "BLOCK" and "verification" not in r.json() and "message" not in r.json(), r.text


def test_chat_with_a_text_answer_is_still_reported_as_not_judged(monkeypatch):
    _, key = make_tenant()
    monkeypatch.delenv("OLA_AMBIENT_IGOR", raising=False)
    monkeypatch.setattr(appmain, "chat", lambda tenant, messages: {"status": "VERIFIED", "message": "42", "model": "m"})
    body = client.post("/chat", json={"messages": [{"role": "user", "content": "q"}]}, headers={"X-API-Key": key}).json()
    assert body["status"] == "UNKNOWN" and body["verification"] == "NOT_JUDGED" and body["message"] == "42"
