"""SQLite-backed, atomic delivery leases. Not a replacement for OLA's audit store."""
import sqlite3
import time
import uuid


def connect(path):
    db = sqlite3.connect(path, timeout=10, isolation_level=None)
    db.execute("PRAGMA busy_timeout=10000")
    db.execute("""CREATE TABLE IF NOT EXISTS deliveries (
        id TEXT PRIMARY KEY, tenant TEXT NOT NULL, event_id TEXT NOT NULL,
        handler TEXT NOT NULL, payload TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending',
        attempts INTEGER NOT NULL DEFAULT 0, lease_until REAL NOT NULL DEFAULT 0,
        next_attempt REAL NOT NULL DEFAULT 0, claim_token TEXT,
        UNIQUE(tenant,event_id,handler))""")
    return db


def enqueue(db, tenant, event_id, handler, payload):
    if not all(isinstance(v, str) and v for v in (tenant,event_id,handler,payload)):
        raise ValueError("nonempty tenant, event, handler and payload required")
    cur = db.execute("INSERT OR IGNORE INTO deliveries(id,tenant,event_id,handler,payload) VALUES(?,?,?,?,?)",
                     (str(uuid.uuid4()),tenant,event_id,handler,payload))
    if cur.rowcount == 0:
        existing = db.execute("SELECT payload FROM deliveries WHERE tenant=? AND event_id=? AND handler=?",
                              (tenant,event_id,handler)).fetchone()
        if existing is None or existing[0] != payload:
            raise ValueError("conflicting duplicate delivery payload")


def claim(db, tenant, now=None, lease_seconds=30):
    if not tenant or lease_seconds <= 0:
        raise ValueError("invalid tenant or lease")
    now = time.time() if now is None else now
    token = str(uuid.uuid4())
    db.execute("BEGIN IMMEDIATE")
    try:
        row = db.execute("""SELECT id FROM deliveries WHERE tenant=? AND
            ((state='pending' AND next_attempt<=?) OR (state='leased' AND lease_until<=?))
            ORDER BY next_attempt,id LIMIT 1""", (tenant,now,now)).fetchone()
        if row is None:
            db.execute("COMMIT")
            return None
        db.execute("""UPDATE deliveries SET state='leased', lease_until=?, claim_token=?,
            attempts=attempts+1 WHERE id=?""", (now+lease_seconds,token,row[0]))
        result = db.execute("SELECT id,event_id,handler,payload,attempts FROM deliveries WHERE id=?",row).fetchone()
        db.execute("COMMIT")
        return (*result,token)
    except BaseException:
        db.execute("ROLLBACK")
        raise


def complete(db, tenant, delivery_id, token):
    cur = db.execute("""UPDATE deliveries SET state='done',claim_token=NULL,lease_until=0
        WHERE tenant=? AND id=? AND state='leased' AND claim_token=?""",(tenant,delivery_id,token))
    return cur.rowcount == 1


def fail(db, tenant, delivery_id, token, now=None, max_attempts=5):
    if max_attempts < 1:
        raise ValueError("max_attempts must be positive")
    now = time.time() if now is None else now
    cur = db.execute("""UPDATE deliveries SET
        state=CASE WHEN attempts>=? THEN 'dead' ELSE 'pending' END,
        next_attempt=? + MIN(3600, (1 << MIN(attempts, 10))),
        lease_until=0,claim_token=NULL
        WHERE tenant=? AND id=? AND state='leased' AND claim_token=?""",
        (max_attempts,now,tenant,delivery_id,token))
    return cur.rowcount == 1
