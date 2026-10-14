"""Transactional local permit pilot. No external effects or production identity adapter.

Only SHA-256 of bounded text is implemented. Calculation, receipt, state change and
hash-chained evidence share one SQLite transaction. External effects MUST NOT be
added under the assumption that this transaction makes them exactly-once.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import time
import uuid

from sqlalchemy import select
from .database import SessionLocal
from .models import ExecutionPermit, EvidenceRecord
from .hashchain import canonical_json, compute_record_hash
from .execution_binding import capture_source, digest


class PermitDenied(ValueError):
    pass


@dataclass(frozen=True)
class Actor:
    issuer: str
    subject: str
    tenant_id: str
    role: str
    authenticated_at: int

    def identity(self):
        return {"issuer": self.issuer, "subject": self.subject, "tenant_id": self.tenant_id}


def unavailable_identity(_credential):
    raise PermitDenied("production identity adapter is not configured")


def current_binding():
    source = capture_source()
    if source.get("status") != "LOCAL":
        raise PermitDenied("local source unavailable")
    raw = (Path(__file__).resolve().parents[1] / "policies/local-permit-v1.json").read_bytes()
    policy = json.loads(raw)
    expected = {"id":"OLA-LOCAL-PERMIT-v1","operation":"sha256-text","max_utf8_bytes":65536,
        "ttl_seconds":300,"approver_role":"owner","executor_role":"executor",
        "external_effects":False,"production_allowed":False}
    if policy != expected:
        raise PermitDenied("unsupported permit policy")
    return {"source_sha":source["sha"],"source_files_digest":source["files_digest"],
            "policy_digest":hashlib.sha256(raw).hexdigest()}


def _event(db, tenant, kind, payload):
    last = db.scalar(select(EvidenceRecord).where(EvidenceRecord.tenant_id == tenant)
                     .order_by(EvidenceRecord.seq.desc()).limit(1))
    seq, prev = (last.seq + 1, last.record_hash) if last else (0, "0" * 64)
    rid, encoded = str(uuid.uuid4()), canonical_json(payload)
    rh = compute_record_hash(tenant, seq, prev, encoded, record_id=rid, record_type=kind, hash_version=2)
    db.add(EvidenceRecord(id=rid, tenant_id=tenant, seq=seq, prev_hash=prev,
        record_hash=rh, record_type=kind, hash_version=2, payload_json=encoded))


class PermitService:
    def __init__(self, *, resolve_identity=unavailable_identity, binding_provider=current_binding,
                 sessions=SessionLocal, clock=time.time):
        # Both providers are trusted server adapters, never request-supplied data.
        self.resolve_identity = resolve_identity
        self.binding_provider = binding_provider
        self.sessions = sessions
        self.clock = clock

    def _actor(self, credential, role):
        actor = self.resolve_identity(credential)
        now = int(self.clock())
        if (not isinstance(actor, Actor) or actor.role != role or not actor.issuer or
                not actor.subject or not actor.tenant_id or type(actor.authenticated_at) is not int or
                not 0 <= now - actor.authenticated_at <= 300):
            raise PermitDenied("role or fresh authentication required")
        return actor

    def prepare(self, credential, text):
        actor = self._actor(credential, "executor")
        if not isinstance(text, str) or len(text.encode("utf-8")) > 65536:
            raise PermitDenied("invalid text")
        binding = self.binding_provider()
        pid, now = str(uuid.uuid4()), int(self.clock())
        subject = {"schema":"ola.execution-permit.v1", "permit_id":pid,
            "tenant_id":actor.tenant_id,"requester":actor.identity(),"operation":"sha256-text",
            "parameters":{"text":text},"resource":f"tenant:{actor.tenant_id}:result:{pid}",
            "binding":binding,"issued_at":now,"expires_at":now+300}
        with self.sessions() as db:
            db.connection().exec_driver_sql("BEGIN IMMEDIATE")
            db.add(ExecutionPermit(id=pid,tenant_id=actor.tenant_id,subject_json=canonical_json(subject),
                subject_digest=digest(subject),state="PENDING"))
            _event(db,actor.tenant_id,"permit.prepared",{"subject":subject,"subject_digest":digest(subject)})
            db.commit()
        return {"permit_id":pid,"subject":subject,"subject_digest":digest(subject),"state":"PENDING"}

    def _load(self, db, pid, actor, claimed_digest):
        row = db.get(ExecutionPermit,pid)
        if row is None or row.tenant_id != actor.tenant_id:
            raise PermitDenied("permit not found")
        subject = json.loads(row.subject_json)
        if digest(subject) != row.subject_digest or claimed_digest != row.subject_digest:
            raise PermitDenied("subject mismatch")
        if not subject["issued_at"] <= int(self.clock()) < subject["expires_at"]:
            raise PermitDenied("permit expired or clock moved backwards")
        if subject["binding"] != self.binding_provider():
            raise PermitDenied("source or policy changed")
        return row,subject

    def approve(self, credential, pid, subject_digest):
        owner = self._actor(credential,"owner")
        with self.sessions() as db:
            db.connection().exec_driver_sql("BEGIN IMMEDIATE")
            row,subject = self._load(db,pid,owner,subject_digest)
            if row.state != "PENDING" or owner.identity() == subject["requester"]:
                raise PermitDenied("not eligible for owner approval")
            approval = {"subject_digest":subject_digest,"owner":owner.identity(),
                "authenticated_at":owner.authenticated_at,"approved_at":int(self.clock())}
            row.approval_json, row.state = canonical_json(approval),"APPROVED"
            _event(db,owner.tenant_id,"permit.approved",{"permit_id":pid,"approval":approval})
            db.commit()
        return {"state":"APPROVED","approval":approval}

    def execute(self, credential, pid, subject_digest):
        actor = self._actor(credential,"executor")
        with self.sessions() as db:
            db.connection().exec_driver_sql("BEGIN IMMEDIATE")
            row,subject = self._load(db,pid,actor,subject_digest)
            if row.state != "APPROVED" or actor.identity() != subject["requester"]:
                raise PermitDenied("permit not executable")
            approval = json.loads(row.approval_json)
            if approval.get("subject_digest") != subject_digest:
                raise PermitDenied("approval mismatch")
            # No caller parameters at execution: execute the frozen subject only.
            if subject["operation"] != "sha256-text":
                raise PermitDenied("unsupported operation")
            result = hashlib.sha256(subject["parameters"]["text"].encode("utf-8")).hexdigest()
            receipt = {"schema":"ola.local-permit-receipt.v1","subject_digest":subject_digest,
                "approval_digest":digest(approval),"result":result,"executor":actor.identity(),
                "finished_at":int(self.clock()),"assurance":"UNKNOWN","production_eligible":False}
            if receipt["finished_at"] >= subject["expires_at"]:
                raise PermitDenied("permit expired during calculation")
            row.receipt_json, row.state = canonical_json(receipt),"COMPLETED"
            _event(db,actor.tenant_id,"permit.completed",{"permit_id":pid,"receipt":receipt})
            db.commit()
        return {"subject":subject,"approval":approval,"receipt":receipt}

    def revoke(self, credential, pid, subject_digest):
        actor = self._actor(credential,"owner")
        with self.sessions() as db:
            db.connection().exec_driver_sql("BEGIN IMMEDIATE")
            row,subject = self._load(db,pid,actor,subject_digest)
            if row.state not in {"PENDING","APPROVED"}:
                raise PermitDenied("permit cannot be revoked")
            if row.approval_json and json.loads(row.approval_json)["owner"] != actor.identity():
                raise PermitDenied("different owner")
            row.state = "REVOKED"
            _event(db,actor.tenant_id,"permit.revoked",{"permit_id":pid,"owner":actor.identity()})
            db.commit()
        return {"state":"REVOKED"}
