"""Real PostgreSQL tests. Set OLA_TEST_POSTGRES_URL to enable them."""
import os
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

POSTGRES_URL = os.getenv("OLA_TEST_POSTGRES_URL", "").strip()
pytestmark = pytest.mark.skipif(not POSTGRES_URL, reason="OLA_TEST_POSTGRES_URL is not configured")


@pytest.fixture
def postgres_db(monkeypatch):
    from app import database
    from app.models import Tenant

    admin_engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
    schema = "ola_test_" + uuid.uuid4().hex
    runtime_role = "ola_rt_" + uuid.uuid4().hex[:12]
    with admin_engine.begin() as conn:
        conn.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        conn.exec_driver_sql(f'CREATE ROLE "{runtime_role}" NOLOGIN')

    search_path = f"-csearch_path={schema}"
    migration_engine = create_engine(
        POSTGRES_URL,
        pool_pre_ping=True,
        connect_args={"options": search_path},
    )
    runtime_engine = None
    try:
        database.migrate_postgres_schema(migration_engine)
        with admin_engine.begin() as conn:
            conn.exec_driver_sql(f'GRANT USAGE ON SCHEMA "{schema}" TO "{runtime_role}"')
            conn.exec_driver_sql(
                f'GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA "{schema}" TO "{runtime_role}"'
            )
            conn.exec_driver_sql(
                f'REVOKE UPDATE, DELETE, TRUNCATE ON TABLE "{schema}".evidence_records FROM "{runtime_role}"'
            )
            conn.exec_driver_sql(
                f'REVOKE UPDATE, DELETE, TRUNCATE ON TABLE "{schema}".capability_replay_ledger FROM "{runtime_role}"'
            )
            conn.exec_driver_sql(
                f'REVOKE ALL ON TABLE "{schema}".ola_schema_migrations FROM "{runtime_role}"'
            )
            conn.exec_driver_sql(
                f'GRANT SELECT ON TABLE "{schema}".ola_schema_migrations TO "{runtime_role}"'
            )

        runtime_engine = create_engine(
            POSTGRES_URL,
            pool_pre_ping=True,
            connect_args={"options": search_path},
        )

        @event.listens_for(runtime_engine, "connect")
        def assume_runtime_role(dbapi_connection, _connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute(f'SET ROLE "{runtime_role}"')
            cursor.close()
            # SET ROLE is transactional: persist the session role before the
            # SQLAlchemy pool can roll back a check-in transaction.
            dbapi_connection.commit()

        monkeypatch.setattr(database, "SessionLocal", sessionmaker(
            bind=runtime_engine, autocommit=False, autoflush=False,
        ))
        database.verify_postgres_schema(runtime_engine)
        yield database, runtime_engine, migration_engine, admin_engine, runtime_role, schema
    finally:
        if runtime_engine is not None:
            runtime_engine.dispose()
        migration_engine.dispose()
        with admin_engine.begin() as conn:
            conn.exec_driver_sql(f'DROP OWNED BY "{runtime_role}"')
            conn.exec_driver_sql(f'DROP ROLE IF EXISTS "{runtime_role}"')
            conn.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        admin_engine.dispose()


def test_postgres_concurrent_evidence_appends_are_serialized_and_immutable(postgres_db):
    database, runtime_engine, migration_engine, _admin_engine, runtime_role, _schema = postgres_db
    from app.igor_evidence_verifier import verify_chain
    from app.models import EvidenceRecord, Tenant

    # The restricted runtime role has only SELECT/INSERT on evidence_records.
    database.verify_postgres_schema(runtime_engine)
    tenant_id = str(uuid.uuid4())
    with database.SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="PostgreSQL integration tenant"))
        db.commit()

    def append_event(index):
        return database.append_evidence_atomic(
            tenant_id, "integration.append", {"index": index},
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(append_event, range(32)))

    assert len({item["id"] for item in results}) == 32
    with database.SessionLocal() as db:
        rows = db.scalars(
            select(EvidenceRecord)
            .where(EvidenceRecord.tenant_id == tenant_id)
            .order_by(EvidenceRecord.seq.asc())
        ).all()
    assert [row.seq for row in rows] == list(range(32))
    records = [{
        "id": row.id, "tenant_id": row.tenant_id, "seq": row.seq,
        "prev_hash": row.prev_hash, "record_hash": row.record_hash,
        "record_type": row.record_type, "payload_json": row.payload_json,
    } for row in rows]
    assert verify_chain(records)[0] is True

    # The DB-level triggers still protect against privileged accidental writes.
    with migration_engine.begin() as conn:
        with pytest.raises(DBAPIError):
            conn.exec_driver_sql(
                "UPDATE evidence_records SET payload_json = '{}' WHERE id = %s",
                (rows[0].id,),
            )
    with migration_engine.begin() as conn:
        with pytest.raises(DBAPIError):
            conn.exec_driver_sql(
                "DELETE FROM evidence_records WHERE id = %s",
                (rows[0].id,),
            )

    # The runtime startup check must reject an accidentally over-privileged role.
    with _admin_engine.begin() as conn:
        conn.exec_driver_sql(
            f'GRANT UPDATE, TRUNCATE ON TABLE "{_schema}".evidence_records TO "{runtime_role}"'
        )
    with pytest.raises(RuntimeError, match="must not have UPDATE, DELETE or TRUNCATE"):
        database.verify_postgres_schema(runtime_engine)
    with _admin_engine.begin() as conn:
        conn.exec_driver_sql(
            f'REVOKE UPDATE, TRUNCATE ON TABLE "{_schema}".evidence_records FROM "{runtime_role}"'
        )
    database.verify_postgres_schema(runtime_engine)


def test_postgres_capability_replay_ledger_is_atomic_durable_and_append_only(postgres_db):
    database, runtime_engine, migration_engine, admin_engine, runtime_role, schema = postgres_db
    from app.capability_broker import (
        ExecutionRequest, PostgresReplayLedger, VoucherIssuer, VoucherVerifier,
    )
    from app.models import CapabilityReplay, Tenant

    tenant_id = str(uuid.uuid4())
    with database.SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name="PostgreSQL replay integration tenant"))
        db.commit()

    secret = b"postgres-replay-test-secret-material-32!"
    request = ExecutionRequest(
        run_id="run-postgres-1",
        tenant_id=tenant_id,
        principal_id="principal-postgres-1",
        capability="calculate",
        arguments={"expression": "2+2"},
        policy_version="policy-v1",
    )
    issuer = VoucherIssuer(secret, {"calculate"}, ttl_seconds=30)
    voucher = issuer.issue(request, now=90)
    verifiers = [
        VoucherVerifier(
            secret, {"calculate"}, replay_ledger=PostgresReplayLedger(), clock=lambda: 100,
        )
        for _ in range(2)
    ]

    def consume(verifier):
        try:
            verifier.verify_and_consume(voucher, request)
            return "accepted"
        except PermissionError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(consume, verifiers))
    assert sorted(outcomes) == ["accepted", "rejected"]

    with database.SessionLocal() as db:
        rows = db.scalars(select(CapabilityReplay).where(
            CapabilityReplay.tenant_id == tenant_id,
        )).all()
    assert len(rows) == 1
    assert rows[0].nonce == voucher.nonce
    assert rows[0].voucher_id == voucher.voucher_id
    assert rows[0].consumed_at == 100

    # Migration-role writes still hit append-only triggers.
    with migration_engine.begin() as conn:
        with pytest.raises(DBAPIError):
            conn.exec_driver_sql(
                "UPDATE capability_replay_ledger SET consumed_at = 101 WHERE voucher_id = %s",
                (voucher.voucher_id,),
            )
    with migration_engine.begin() as conn:
        with pytest.raises(DBAPIError):
            conn.exec_driver_sql(
                "DELETE FROM capability_replay_ledger WHERE voucher_id = %s",
                (voucher.voucher_id,),
            )

    # Runtime must be read-only except for atomic replay insertion.
    with admin_engine.begin() as conn:
        conn.exec_driver_sql(
            f'GRANT UPDATE ON TABLE "{schema}".capability_replay_ledger TO "{runtime_role}"'
        )
    with pytest.raises(RuntimeError, match="must have SELECT/INSERT"):
        database.verify_postgres_schema(runtime_engine)
    with admin_engine.begin() as conn:
        conn.exec_driver_sql(
            f'REVOKE UPDATE ON TABLE "{schema}".capability_replay_ledger FROM "{runtime_role}"'
        )
    database.verify_postgres_schema(runtime_engine)
