"""Idempotent schema upgrades for databases created by an older version (there is no Alembic here).

`Base.metadata.create_all` builds new tables with the current columns but never alters an existing one, so a
database created before stripe_events had its lease / per-session columns needs them added in place. Everything here
is safe to run on every start and from several processes at once."""
import json
import logging
import time

from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from . import database

log = logging.getLogger("ola.migrations")

STRIPE_EVENT_COLUMNS = {
    "claimed_at": "REAL",
    "checkout_session_id": "VARCHAR(255)",
    "payment_evidence_id": "VARCHAR(36)",
    "runtime_json": "TEXT",
}
SESSION_INDEX = ("CREATE UNIQUE INDEX IF NOT EXISTS uq_stripe_events_checkout_session "
                 "ON stripe_events (checkout_session_id) WHERE checkout_session_id IS NOT NULL")


def _columns(conn, table):
    return {row[1] for row in conn.exec_driver_sql(f"PRAGMA table_info({table})")}


def migrate_stripe_events(bind=None) -> list[str]:
    """Adds the missing stripe_events columns, back-fills the session id of rows that already completed, gives rows
    that were PROCESSING under the old code a lease clock, and creates the per-session unique index. Returns the
    list of changes it made ([] when the schema was already current or the table does not exist yet)."""
    changes: list[str] = []
    eng = bind or database.engine
    with eng.begin() as conn:
        columns = _columns(conn, "stripe_events")
        if not columns:                                   # no table yet: create_all builds it with the new columns
            return changes
        for name, ddl in STRIPE_EVENT_COLUMNS.items():
            if name in columns:
                continue
            try:
                conn.exec_driver_sql(f"ALTER TABLE stripe_events ADD COLUMN {name} {ddl}")
                changes.append(f"added column {name}")
            except OperationalError as exc:               # another process added it between our check and our ALTER
                if "duplicate column" not in str(exc).lower():
                    raise
        # Rows from before the migration: the first COMPLETED row of a session owns it (older code could complete one
        # session twice; the unique index below must not fail on that history, so later duplicates stay NULL).
        owners = {row[0] for row in conn.exec_driver_sql(
            "SELECT checkout_session_id FROM stripe_events WHERE checkout_session_id IS NOT NULL")}
        for rowid, result_json in conn.exec_driver_sql(
                "SELECT id, result_json FROM stripe_events WHERE checkout_session_id IS NULL AND status = 'COMPLETED' "
                "AND result_json IS NOT NULL ORDER BY rowid").fetchall():
            try:
                session_id = json.loads(result_json).get("checkout_session_id")
            except (TypeError, ValueError, AttributeError):
                continue
            if isinstance(session_id, str) and session_id and session_id not in owners:
                conn.exec_driver_sql("UPDATE stripe_events SET checkout_session_id = ? WHERE id = ?", (session_id, rowid))
                owners.add(session_id)
                changes.append("back-filled checkout_session_id")
        # PROCESSING rows written by the old code have no lease clock: start it now, so a row stuck by an old crash
        # becomes reclaimable after the lease instead of never (and a run that is in flight gets a full lease).
        stamped = conn.execute(text("UPDATE stripe_events SET claimed_at = :now WHERE status = 'PROCESSING' "
                                    "AND claimed_at IS NULL"), {"now": time.time()}).rowcount
        if stamped:
            changes.append(f"started the lease of {stamped} PROCESSING row(s)")
    try:
        with eng.begin() as conn:
            conn.exec_driver_sql(SESSION_INDEX)
    except Exception as exc:                              # e.g. duplicate session ids put there by hand
        log.warning("could not create the per-session unique index on stripe_events (%s); "
                    "the application-level session check still applies", exc)
    return changes


def run_migrations(bind=None) -> list[str]:
    return migrate_stripe_events(bind)
