import os
from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker

DB_PATH = os.getenv("OLA_EG_DB_PATH", "ola.db")
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()


def install_append_only_triggers():
    with engine.begin() as conn:
        conn.exec_driver_sql("""
        CREATE TRIGGER IF NOT EXISTS evidence_no_update
        BEFORE UPDATE ON evidence_records
        BEGIN SELECT RAISE(ABORT, 'evidence_records is append-only'); END;
        """)
        conn.exec_driver_sql("""
        CREATE TRIGGER IF NOT EXISTS evidence_no_delete
        BEFORE DELETE ON evidence_records
        BEGIN SELECT RAISE(ABORT, 'evidence_records is append-only'); END;
        """)

def ensure_evidence_hash_schema():
    """Additive, idempotent SQLite change; never rewrite or rehash old evidence.

    Legacy rows retain hash_version=1; only newly appended rows use v2.
    Caller must retain an external trusted backup/anchor before production GO.
    """
    with engine.connect() as connection:
        # Writers from multiple workers must not race to ALTER the same table.
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        try:
            cols = {row[1] for row in connection.exec_driver_sql(
                "PRAGMA table_info(evidence_records)"
            ).fetchall()}
            if not cols:
                raise RuntimeError("evidence_records table must exist")
            if "hash_version" not in cols:
                connection.exec_driver_sql(
                    "ALTER TABLE evidence_records "
                    "ADD COLUMN hash_version INTEGER NOT NULL DEFAULT 1"
                )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
