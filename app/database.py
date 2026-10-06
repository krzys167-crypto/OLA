import os
import re
from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker

DB_PATH = os.getenv("OLA_EG_DB_PATH", "ola.db")
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False, "timeout": 30})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()


def _busy_ms() -> int:
    try:
        return max(0, int(os.environ.get("OLA_DB_BUSY_MS", "30000")))
    except ValueError:
        return 30000


@event.listens_for(engine, "connect")
def _pragmas(dbapi_conn, _record):
    cur = dbapi_conn.cursor()
    # recursive_triggers: without it INSERT OR REPLACE / REPLACE INTO delete the old row WITHOUT firing the DELETE
    # trigger, i.e. an evidence row could be overwritten in place
    cur.execute("PRAGMA recursive_triggers=ON")
    cur.execute(f"PRAGMA busy_timeout={_busy_ms()}")
    # WAL is opt-in: with WAL a plain file copy of the .db (what the standalone verifiers and CI do) silently misses
    # committed data that still sits in the -wal file. Operators who run the server (not file-copy flows) can set it.
    if DB_PATH != ":memory:" and os.environ.get("OLA_DB_WAL") == "1":
        cur.execute("PRAGMA journal_mode=WAL")
    cur.close()


_TRIGGERS = {
    "evidence_no_update": """CREATE TRIGGER evidence_no_update
        BEFORE UPDATE ON evidence_records
        BEGIN SELECT RAISE(ABORT, 'evidence_records is append-only'); END;""",
    "evidence_no_delete": """CREATE TRIGGER evidence_no_delete
        BEFORE DELETE ON evidence_records
        BEGIN SELECT RAISE(ABORT, 'evidence_records is append-only'); END;""",
}


def _norm(sql: str) -> str:
    return re.sub(r"\s+", " ", sql or "").strip().rstrip(";").strip().lower()


def install_append_only_triggers():
    """Creates the triggers AND re-creates one whose stored body is not the expected one (a trigger replaced by a
    no-op `WHEN 0` used to be kept by CREATE TRIGGER IF NOT EXISTS)."""
    with engine.begin() as conn:
        for name, sql in _TRIGGERS.items():
            row = conn.exec_driver_sql("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,)).first()
            if row is not None and _norm(row[0]) == _norm(sql):
                continue
            if row is not None:
                conn.exec_driver_sql(f"DROP TRIGGER {name}")
            conn.exec_driver_sql(sql)
