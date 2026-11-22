import uuid
import time
from sqlalchemy import Column, String, Integer, Text, ForeignKey, UniqueConstraint
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
    role = Column(String(32), nullable=False, default="tenant")


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
    __tablename__ = "stripe_events"
    id = Column(String(36), primary_key=True)
    event_id = Column(String(255), nullable=False, unique=True, index=True)
    status = Column(String(32), nullable=False)
    run_id = Column(String(36), nullable=True)
    task = Column(Text, nullable=True)
    result_json = Column(Text, nullable=True)


class CheckoutOrder(Base):
    """Durable, tenant-scoped intent to create one Stripe Checkout Session."""
    __tablename__ = "checkout_orders"
    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    idempotency_key_hash = Column(String(64), nullable=False)
    request_hash = Column(String(64), nullable=False)
    task = Column(Text, nullable=True)
    status = Column(String(32), nullable=False)
    created_at = Column(Integer, nullable=False, default=lambda: int(time.time()))
    stripe_session_id = Column(String(255), nullable=True, unique=True, index=True)
    checkout_url = Column(Text, nullable=True)
    payment_event_id = Column(String(255), nullable=True, unique=True)
    payment_result_json = Column(Text, nullable=True)
    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key_hash", name="uq_checkout_order_tenant_idempotency"),
    )


class CheckoutOrderControl(Base):
    """Identity-bound Human Gate state for one paid Checkout order.

    The row is created with the order reservation. Legacy orders without this
    row are deliberately not approvable because their requester identity is
    not proven.
    """
    __tablename__ = "checkout_order_controls"
    id = Column(String(36), primary_key=True)
    order_id = Column(String(36), ForeignKey("checkout_orders.id"), nullable=False, unique=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    requester_id = Column(String(36), ForeignKey("api_keys.id"), nullable=False)
    status = Column(String(32), nullable=False)
    payment_evidence_id = Column(String(36), nullable=True)
    approver_id = Column(String(36), ForeignKey("api_keys.id"), nullable=True)
    approval_reason = Column(Text, nullable=True)
    approved_tip_hash = Column(String(64), nullable=True)
    approval_record_hash = Column(String(64), nullable=True)
    created_at = Column(Integer, nullable=False, default=lambda: int(time.time()))
    approved_at = Column(Integer, nullable=True)


class CheckoutExecutionJob(Base):
    """Durable, single-attempt outbox job created with Human Gate approval."""
    __tablename__ = "checkout_execution_jobs"
    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    order_id = Column(String(36), ForeignKey("checkout_orders.id"), nullable=False, unique=True, index=True)
    approval_record_hash = Column(String(64), nullable=False)
    task = Column(Text, nullable=False)
    status = Column(String(40), nullable=False, index=True)
    attempt_count = Column(Integer, nullable=False, default=0)
    claim_token = Column(String(36), nullable=True)
    started_at = Column(Integer, nullable=True)
    finished_at = Column(Integer, nullable=True)
    run_id = Column(String(36), nullable=True)
    result_json = Column(Text, nullable=True)
    error_code = Column(String(100), nullable=True)
    created_at = Column(Integer, nullable=False, default=lambda: int(time.time()))


class CheckoutReportReview(Base):
    """Independent, tenant-scoped review gate for a completed customer report."""
    __tablename__ = "checkout_report_reviews"
    id = Column(String(36), primary_key=True)
    order_id = Column(String(36), ForeignKey("checkout_orders.id"), nullable=False, unique=True, index=True)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    reviewer_id = Column(String(36), ForeignKey("api_keys.id"), nullable=False)
    status = Column(String(32), nullable=False)
    report_sha256 = Column(String(64), nullable=False)
    reviewed_tip_hash = Column(String(64), nullable=False)
    reason = Column(Text, nullable=False)
    approval_evidence_id = Column(String(36), nullable=True)
    reviewed_at = Column(Integer, nullable=False, default=lambda: int(time.time()))
    delivery_evidence_id = Column(String(36), nullable=True)
    delivered_at = Column(Integer, nullable=True)


class CapabilityReplay(Base):
    """Append-only, PostgreSQL-backed one-use voucher replay record."""
    __tablename__ = "capability_replay_ledger"
    id = Column(String(36), primary_key=True, default=uid)
    tenant_id = Column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    nonce = Column(String(32), nullable=False)
    voucher_id = Column(String(32), nullable=False)
    consumed_at = Column(Integer, nullable=False)
    __table_args__ = (
        UniqueConstraint("tenant_id", "nonce", name="uq_capability_replay_tenant_nonce"),
        UniqueConstraint("tenant_id", "voucher_id", name="uq_capability_replay_tenant_voucher"),
    )
