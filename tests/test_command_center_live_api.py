"""Read-only control plane must never forge verification or cross tenant boundaries."""
import copy
import uuid
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from app.api_key_crypto import hash_api_key
from app.database import SessionLocal
from app.main import app, append_record
from app.models import ApiKey, Tenant
from app.control_plane import get_overview, get_run_detail


def seed():
    name = "control_" + uuid.uuid4().hex
    token = "control-key-" + uuid.uuid4().hex
    tenant_id = str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name=name))
        db.add(ApiKey(id=str(uuid.uuid4()), tenant_id=tenant_id, key_hash=hash_api_key(token)))
        db.commit()
    return tenant_id, token


def test_auth_scope_no_evidence_made_up():
    a_id, a_key = seed()
    b_id, b_key = seed()
    client = TestClient(app)
    assert client.get("/control/overview").status_code == 401
    assert client.get("/control/overview", headers={"X-API-Key": "invalid"}).status_code == 401
    untouched = client.get("/control/overview", headers={"X-API-Key": a_key})
    assert untouched.status_code == 200
    body = untouched.json()
    assert body["tenant_id"] == a_id
    assert body["evidence"]["status"] == "UNKNOWN"
    assert body["runs"] == []
    assert body["production"]["status"] == "NO-GO"
    assert body["llm"]["connectivity"] == "UNKNOWN"
    append_record(a_id, "test.scope", {"secret": "never shown in overview", "run_id": str(uuid.uuid4())})
    a_view = client.get("/control/overview", headers={"X-API-Key": a_key}).json()
    b_view = client.get("/control/overview", headers={"X-API-Key": b_key}).json()
    assert a_view["evidence"]["status"] == "VERIFIED"
    assert a_view["evidence"]["record_count"] == 1
    assert b_view["evidence"]["status"] == "UNKNOWN"
    assert b_view["tenant_id"] == b_id
    assert "never shown" not in str(a_view)


def test_repeated_audit_verifies_complete_chain_not_sliced_new_events():
    _, token = seed()
    client = TestClient(app)
    for _ in range(2):
        response = client.post(
            "/audit", headers={"X-API-Key": token},
            json={"task": "controlled incident", "scenario": "fault_then_recovery"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "VERIFIED"
        assert body["evidence_count"] == 5
        assert body["verification_scope"] == "CONTROLLED_SIMULATION"
    overview = client.get("/control/overview", headers={"X-API-Key": token}).json()
    assert overview["evidence"]["record_count"] == 10
    assert overview["evidence"]["status"] == "VERIFIED"


def test_run_replay_is_tenant_scoped_and_not_claimed_as_production():
    _, a_key = seed()
    _, b_key = seed()
    client = TestClient(app)
    created = client.post(
        "/nina-run",
        headers={"X-API-Key": a_key},
        json={"task": "17 * 23", "requested_tools": ["safe_expression"]},
    )
    assert created.status_code == 200
    run_id = created.json()["run_id"]
    detail = client.get(f"/control/runs/{run_id}", headers={"X-API-Key": a_key})
    assert detail.status_code == 200
    result = detail.json()
    assert result["run_id"] == run_id
    assert result["status"] == "VERIFIED"
    assert result["scope"] == "LOCAL_HASH_AND_REPLAY_ONLY"
    assert result["production"] == "NO-GO"
    assert result["independent_release_verification"] == "UNKNOWN"
    assert len(result["records"]) >= 6
    cross = client.get(f"/control/runs/{run_id}", headers={"X-API-Key": b_key})
    assert cross.status_code == 404
    assert client.get("/control/runs/invalid-id", headers={"X-API-Key": a_key}).status_code == 404
    overview = client.get("/control/overview", headers={"X-API-Key": a_key}).json()
    assert overview["runs"][0]["run_id"] == run_id
    assert overview["runs"][0]["verified_from_source"] is False


def test_corrupt_or_truncated_chain_never_becomes_verified(monkeypatch):
    tenant_id, _ = seed()
    append_record(tenant_id, "test.event", {"run_id": str(uuid.uuid4())})
    from app import control_plane
    rows = control_plane.load_tenant_records(tenant_id)
    corrupt = copy.deepcopy(rows)
    corrupt[0]["payload_json"] = '{"run_id":"tampered"}'
    monkeypatch.setattr(control_plane, "load_tenant_records", lambda tenant: corrupt)
    overview = get_overview(tenant_id)
    assert overview["evidence"]["status"] == "BLOCK"
    assert overview["runs"] == []
    assert get_run_detail(tenant_id, "00000000-0000-0000-0000-000000000000") is None
    monkeypatch.setattr(control_plane, "load_tenant_records", lambda tenant: None)
    overflow = get_overview(tenant_id)
    assert overflow["evidence"]["status"] == "UNKNOWN"
    assert overflow["evidence"]["tip_hash"] is None


def test_parallel_append_keeps_single_tenant_sequence_atomic():
    tenant_id, _ = seed()
    def produce(i):
        return append_record(tenant_id, "test.parallel", {"index": i})
    with ThreadPoolExecutor(max_workers=5) as pool:
        records = list(pool.map(produce, range(8)))
    assert sorted(row["seq"] for row in records) == list(range(8))
    assert get_overview(tenant_id)["evidence"]["status"] == "VERIFIED"
