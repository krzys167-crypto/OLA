import uuid
from sqlalchemy import Column, Float, Index, String, Integer, Text, ForeignKey, UniqueConstraint, text
from .database import Base


def uid():
    return str(uuid.uuid4())


class Tenant(Base):
    __tablename__ = "tenants"
    id = Column(String(36), primary_key=True)
    name = Column(String(255), nullable=False)


class ApiKey(Base):
    __tablename__ = "api_keys"
    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    key_hash = Column(String(64), nullable=False, unique=True)


class EvidenceRecord(Base):
    __tablename__ = "evidence_records"
    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(36), nullable=False, index=True)
    seq = Column(Integer, nullable=False)
    record_type = Column(String(100), nullable=False)
    payload_json = Column(Text, nullable=False)
    prev_hash = Column(String(64), nullable=False)
    record_hash = Column(String(64), nullable=False)
    __table_args__ = (UniqueConstraint("tenant_id", "seq", name="uq_evidence_tenant_seq"),)



class StripeEvent(Base):
    """One row per paid checkout session (its first event id); later event ids for the same session are aliases.
    status: PROCESSING (claimed_at is the lease clock and the fencing token) -> COMPLETED, or FAILED (retryable).
    payment_evidence_id / run_id / runtime_json are persisted as soon as that step is done, so a retry reuses them
    instead of paying for (and recording) the same work twice. app/migrations.py upgrades databases created before
    these columns existed."""
    __tablename__ = "stripe_events"
    id = Column(String(36), primary_key=True)
    event_id = Column(String(255), nullable=False, unique=True, index=True)
    status = Column(String(32), nullable=False)
    run_id = Column(String(36), nullable=True)
    task = Column(Text, nullable=True)
    result_json = Column(Text, nullable=True)
    claimed_at = Column(Float, nullable=True)
    checkout_session_id = Column(String(255), nullable=True)
    payment_evidence_id = Column(String(36), nullable=True)
    runtime_json = Column(Text, nullable=True)
    __table_args__ = (
        Index("uq_stripe_events_checkout_session", "checkout_session_id", unique=True,
              sqlite_where=text("checkout_session_id IS NOT NULL")),
    )
