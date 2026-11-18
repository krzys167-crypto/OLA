import hashlib
import uuid

from fastapi.testclient import TestClient

from app import blogger_capability, main
from app.database import SessionLocal
from app.models import ApiKey, Tenant


def _key_id(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def test_blogger_http_flow_is_tenant_scoped_read_only_and_reviewed_once(monkeypatch):
    tenant_id = str(uuid.uuid4())
    other_tenant_id = str(uuid.uuid4())
    initiator_key = "blogger-e2e-initiator-" + str(uuid.uuid4())
    reviewer_key = "blogger-e2e-reviewer-" + str(uuid.uuid4())
    other_tenant_key = "blogger-e2e-other-tenant-" + str(uuid.uuid4())

    with SessionLocal() as db:
        db.add_all([
            Tenant(id=tenant_id, name="blogger-e2e"),
            Tenant(id=other_tenant_id, name="blogger-e2e-other"),
            ApiKey(id=str(uuid.uuid4()), tenant_id=tenant_id, key_hash=_key_id(initiator_key)),
            ApiKey(id=str(uuid.uuid4()), tenant_id=tenant_id, key_hash=_key_id(reviewer_key)),
            ApiKey(id=str(uuid.uuid4()), tenant_id=other_tenant_id, key_hash=_key_id(other_tenant_key)),
        ])
        db.commit()

    adapter_calls = []

    def fake_adapter(blog_id: str):
        adapter_calls.append(blog_id)
        result = {
            "success": True,
            "provider": "google_blogger",
            "operation": "blogs.get",
            "blog_id": blog_id,
            "blog_url": "https://ola-blogger-e2e.blogspot.com/",
            "verified": True,
            "http_status": 200,
            "request_id": "mock-google-request",
            "timestamp": "2026-11-18T00:00:00+00:00",
            "error": None,
            "adapter_version": "1.0.0",
        }
        result["result_sha256"] = blogger_capability._digest_result(result)
        return result

    def run_with_mocked_google(tenant, blog_id, *, initiator_key_id=None):
        return blogger_capability.run_blogger_metadata(
            tenant,
            blog_id,
            adapter=fake_adapter,
            initiator_key_id=initiator_key_id,
        )

    monkeypatch.setattr(main, "run_blogger_metadata", run_with_mocked_google)

    with TestClient(main.app) as client:
        invalid = client.post(
            "/blogger/metadata",
            headers={"X-API-Key": initiator_key},
            json={"blog_id": "https://attacker.example/"},
        )
        assert invalid.status_code == 400
        assert adapter_calls == []

        started = client.post(
            "/blogger/metadata",
            headers={"X-API-Key": initiator_key},
            json={"blog_id": "123456789"},
        )
        assert started.status_code == 200, started.text
        run = started.json()
        assert run["status"] == "REVIEW_REQUIRED"
        assert run["human_gate"] == "REVIEW_REQUIRED"
        assert run["execution"] == "NOT_PERFORMED"
        assert run["verification"]["status"] == "VERIFIED"
        assert run["verification"]["checks"]["chain"] is True
        assert run["verification"]["checks"]["igor_capability"] is True
        assert adapter_calls == ["123456789"]

        review_body = {
            "run_id": run["run_id"],
            "blog_id": "123456789",
            "human_approved": True,
            "human_reason": "Independent E2E reviewer verified the metadata evidence.",
        }

        same_key = client.post(
            "/blogger/review",
            headers={"X-API-Key": initiator_key},
            json=review_body,
        )
        assert same_key.status_code == 403

        cross_tenant = client.post(
            "/blogger/review",
            headers={"X-API-Key": other_tenant_key},
            json=review_body,
        )
        assert cross_tenant.status_code == 404

        reviewed = client.post(
            "/blogger/review",
            headers={"X-API-Key": reviewer_key},
            json=review_body,
        )
        assert reviewed.status_code == 200, reviewed.text
        review = reviewed.json()
        assert review["status"] == "REVIEW_APPROVED_BY_SEPARATE_KEY"
        assert review["human_gate"]["status"] == "VERIFIED"
        assert review["execution"] == "NOT_PERFORMED"
        assert review["reviewer_identity"].startswith("authenticated API-key principal")

        replay = client.post(
            "/blogger/review",
            headers={"X-API-Key": reviewer_key},
            json=review_body,
        )
        assert replay.status_code == 409

        # Review must not trigger another upstream Blogger request.
        assert adapter_calls == ["123456789"]

    records = blogger_capability.load_chain(tenant_id)
    event_types = [row["record_type"] for row in records]
    assert event_types == [
        "blogger.execution.started",
        "blogger.metadata.result",
        "blogger.execution.ended",
        "blogger.human_review",
    ]
    assert all(row["tenant_id"] == tenant_id for row in records)
