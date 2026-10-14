import os
import sys
import tempfile
from pathlib import Path

# Make the repository root explicit on sys.path so CI and local pytest use
# the same application import boundary regardless of pytest import mode.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

TEST_DB_PATH = os.path.join(tempfile.mkdtemp(prefix="ola_pytest_"), "pytest.db")
os.environ["OLA_EG_DB_PATH"] = TEST_DB_PATH
# CI-only pepper; never use this public value for real client credentials.
os.environ.setdefault("OLA_API_KEY_PEPPER", "CI-ONLY-OLA-API-KEY-PEPPER-DO-NOT-USE-IN-PRODUCTION-20261012")

# Import the application database only after the test DB path is fixed.
from app.database import Base, engine
from app import models  # noqa: F401

Base.metadata.create_all(bind=engine)

import pytest


@pytest.fixture
def local_binding_source(monkeypatch):
    """Explicit mock of source observer for API unit tests, not source proof."""
    import importlib
    binding = importlib.import_module("app.execution_binding")
    main = importlib.import_module("app.main")
    source = {"status": "LOCAL", "sha": "a" * 40, "files_digest": "b" * 64,
              "boundary": "git-app-and-policies-on-disk-v1"}
    monkeypatch.setattr(binding, "capture_source", lambda: dict(source))
    monkeypatch.setattr(main, "capture_source", lambda: dict(source))
    monkeypatch.setenv("OLA_RUNTIME_COMMIT", source["sha"])
    return source


def bound_candidate_fields(tenant, requester, run):
    import time
    from app.execution_binding import prepare_binding
    from app.decision_report_v2 import build_decision_report_v2
    binding = prepare_binding(tenant, requester, "Calculate 17 * 23", ["safe_expression"])
    legacy = {"schema": "ola.decision-report.v1", "run_id": run, "execution_binding": binding}
    report = build_decision_report_v2(legacy_report=legacy,
        source_sha=binding["source"]["sha"], policy_digest=binding["policy_digest"], evidence_root="c" * 64)
    from sqlalchemy import select
    from app.database import SessionLocal
    from app.models import EvidenceRecord
    with SessionLocal() as db:
        previous = db.scalar(select(EvidenceRecord.record_hash).where(
            EvidenceRecord.tenant_id == tenant).order_by(EvidenceRecord.seq.desc()).limit(1))
    report = build_decision_report_v2(legacy_report=legacy,
        source_sha=binding["source"]["sha"], policy_digest=binding["policy_digest"],
        evidence_root=previous or "0" * 64)
    now = int(time.time())
    return {"decision_report_v2": report, "execution_binding": binding,
            "review_issued_at": now, "review_expires_at": now + 900}


def review_body(tenant, run, tip):
    import json
    from sqlalchemy import select
    from app.database import SessionLocal
    from app.models import EvidenceRecord
    with SessionLocal() as db:
        rows = db.scalars(select(EvidenceRecord).where(EvidenceRecord.tenant_id == tenant,
            EvidenceRecord.record_type == "decision.candidate").order_by(EvidenceRecord.seq.desc())).all()
        for row in rows:
            candidate = json.loads(row.payload_json)
            if candidate.get("run_id") == run:
                return {"tip_hash": tip, "scope": "review-result",
                        "report_sha256": candidate["decision_report_v2"]["report_sha256"]}
    raise AssertionError("candidate absent")
