import importlib
import json
from pathlib import Path
import subprocess
import time
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import execution_binding as eb
from app.api_key_crypto import hash_api_key
from app.database import SessionLocal
from app.models import ApiKey, Tenant, EvidenceRecord
from conftest import bound_candidate_fields, review_body

main = importlib.import_module("app.main")


@pytest.fixture
def source_repo(tmp_path, monkeypatch):
    monkeypatch.delenv("OLA_RUNTIME_COMMIT", raising=False)
    (tmp_path / 'app').mkdir()
    (tmp_path / 'policies').mkdir()
    (tmp_path / 'app/main.py').write_text('print("test source")\n')
    (tmp_path / 'policies/nina-review-v1.json').write_bytes(eb.POLICY_PATH.read_bytes())
    def git(*args):
        return subprocess.check_output(['git', '-C', str(tmp_path), *args], stderr=subprocess.DEVNULL)
    git('init'); git('add', '.')
    git('-c', 'user.name=Local test', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'fixture')
    return tmp_path


def test_source_observer_reads_actual_committed_bytes(source_repo):
    result = eb.capture_source(source_repo)
    assert result['status'] == 'LOCAL'
    assert len(result['sha']) == 40
    (source_repo / 'app/main.py').write_text('changed')
    assert eb.capture_source(source_repo)['status'] == 'UNKNOWN'


def test_source_rejects_untracked_code_and_false_env(source_repo, monkeypatch):
    monkeypatch.setenv('OLA_RUNTIME_COMMIT', 'f' * 40)
    assert eb.capture_source(source_repo)['status'] == 'UNKNOWN'
    monkeypatch.delenv('OLA_RUNTIME_COMMIT')
    (source_repo / 'app/extra.py').write_text('pass')
    assert eb.capture_source(source_repo)['status'] == 'UNKNOWN'


def test_source_rejects_symlink(source_repo):
    (source_repo / 'app/main.py').unlink()
    (source_repo / 'app/main.py').symlink_to('/etc/hosts')
    assert eb.capture_source(source_repo)['status'] == 'UNKNOWN'


def test_missing_repository_is_unknown(tmp_path):
    assert eb.capture_source(tmp_path)['status'] == 'UNKNOWN'


def test_policy_denies_unknown_capability(local_binding_source):
    with pytest.raises(ValueError, match='capability denied'):
        eb.prepare_binding('t', 'u', 'hello', ['shell'])


def setup_candidate():
    tenant, requester, approver = (uuid.uuid4().hex for _ in range(3))
    request_key, review_key = 'req-' + uuid.uuid4().hex, 'rev-' + uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(Tenant(id=tenant, name='binding-tests')); db.flush()
        db.add_all([ApiKey(id=requester, tenant_id=tenant, key_hash=hash_api_key(request_key)),
                    ApiKey(id=approver, tenant_id=tenant, key_hash=hash_api_key(review_key))]); db.commit()
    run = uuid.uuid4().hex
    candidate = {'run_id': run, 'requester_id': requester,
        'status_fields': {'RUNTIME':'VERIFIED','EVIDENCE':'VERIFIED','REPLAY_INTEGRITY':'VERIFIED',
                         'POLICY':'VERIFIED','HUMAN_GATE':'REVIEW','EXECUTION_ALLOWED':'REVIEW'},
        'candidate_status':'REVIEW', **bound_candidate_fields(tenant, requester, run)}
    return tenant, requester, request_key, review_key, run, candidate


@pytest.mark.parametrize('mutation', ['report', 'policy', 'source', 'expiry', 'tenant', 'legacy'])
def test_approval_rejects_mutated_bindings(local_binding_source, mutation):
    tenant, requester, _, key, run, candidate = setup_candidate()
    if mutation == 'report': candidate['decision_report_v2']['bindings']['evidence_root'] = 'd' * 64
    if mutation == 'policy': candidate['execution_binding']['policy_digest'] = 'e' * 64
    if mutation == 'source': candidate['execution_binding']['source']['sha'] = 'e' * 40
    if mutation == 'expiry':
        candidate['review_issued_at'] -= 1000; candidate['review_expires_at'] -= 1000
    if mutation == 'tenant': candidate['execution_binding']['tenant_id'] = 'other'
    if mutation == 'legacy': candidate.pop('execution_binding')
    tip = main.append_record(tenant, 'decision.candidate', candidate)['record_hash']
    result = TestClient(main.app).post(f'/nina-run/{run}/approve',
        headers={'Authorization': 'Bearer ' + key}, json=review_body(tenant, run, tip))
    assert result.status_code == 409, result.text


def test_review_expiry_revocation_and_scope(local_binding_source, monkeypatch):
    tenant, requester, reqkey, key, run, candidate = setup_candidate()
    tip = main.append_record(tenant, 'decision.candidate', candidate)['record_hash']
    client = TestClient(main.app)
    headers = {'Authorization': 'Bearer ' + key}
    body = review_body(tenant, run, tip)
    assert client.post(f'/nina-run/{run}/approve', headers=headers,
                       json={**body, 'scope': 'execute'}).status_code == 400
    assert client.post(f'/nina-run/{run}/approve', headers=headers,
                       json={**body, 'report_sha256': '0' * 64}).status_code == 409
    response = client.post(f'/nina-run/{run}/approve', headers=headers, json=body)
    assert response.status_code == 200, response.text
    approval = response.json()
    assert approval['status'] == 'APPROVED' and approval['assurance'] == 'UNKNOWN'
    assert client.get(f'/nina-run/{run}/approval', headers=headers).json()['status'] == 'APPROVED'
    with monkeypatch.context() as m:
        m.setattr(eb.time, 'time', lambda: candidate['review_expires_at'])
        assert client.get(f'/nina-run/{run}/approval', headers=headers).json()['status'] == 'BLOCKED'
    revoke = {'human_approval_digest': approval['human_approval_digest']}
    assert client.post(f'/nina-run/{run}/approval/revoke',
        headers={'Authorization': 'Bearer ' + reqkey}, json=revoke).status_code == 403
    assert client.post(f'/nina-run/{run}/approval/revoke', headers=headers, json=revoke).status_code == 200
    assert client.get(f'/nina-run/{run}/approval', headers=headers).json()['status'] == 'REVOKED'


def test_unknown_source_blocks_before_execution(local_binding_source, monkeypatch):
    _, _, key, _, _, _ = setup_candidate()
    monkeypatch.setattr(eb, 'capture_source', lambda: {'status':'UNKNOWN'})
    def forbidden(*args):
        pytest.fail('executor must not run without source binding')
    monkeypatch.setattr(main.NinaOrchestrator, 'execute', forbidden)
    result = TestClient(main.app).post('/nina-run', headers={'X-API-Key':key},
        json={'task':'Calculate 17 * 23','requested_tools':['safe_expression']})
    assert result.status_code == 409


def test_new_evidence_invalidates_review(local_binding_source):
    tenant, _, _, key, run, candidate = setup_candidate()
    tip = main.append_record(tenant, 'decision.candidate', candidate)['record_hash']
    client = TestClient(main.app); headers = {'Authorization':'Bearer ' + key}
    assert client.post(f'/nina-run/{run}/approve', headers=headers,
                       json=review_body(tenant, run, tip)).status_code == 200
    main.append_record(tenant, 'generic', {'new':'event'})
    assert client.get(f'/nina-run/{run}/approval', headers=headers).json()['status'] == 'STALE'


def test_container_inventory_and_mutations(source_repo, monkeypatch):
    from scripts.build_source_manifest import build
    manifest = build(source_repo)
    path = source_repo / 'source-manifest.json'
    path.write_text(json.dumps(manifest))
    monkeypatch.setenv('OLA_SOURCE_MODE', 'build-inventory')
    result = eb.capture_source(source_repo)
    assert result['status'] == 'LOCAL'
    assert result['boundary'] == 'unsigned-build-inventory-on-disk-v1'
    monkeypatch.setenv('OLA_RUNTIME_COMMIT', 'f' * 40)
    assert eb.capture_source(source_repo)['status'] == 'UNKNOWN'
    monkeypatch.delenv('OLA_RUNTIME_COMMIT')
    (source_repo / 'app/extra.py').write_text('pass')
    assert eb.capture_source(source_repo)['status'] == 'UNKNOWN'
    (source_repo / 'app/extra.py').unlink()
    (source_repo / 'app/main.py').write_text('tampered')
    assert eb.capture_source(source_repo)['status'] == 'UNKNOWN'


def test_inventory_not_automatic_git_fallback(source_repo, monkeypatch):
    from scripts.build_source_manifest import build
    manifest = build(source_repo)
    (source_repo / 'app/main.py').write_text('tampered')
    import hashlib
    manifest['files']['app/main.py'] = hashlib.sha256(b'tampered').hexdigest()
    (source_repo / 'source-manifest.json').write_text(json.dumps(manifest))
    assert eb.capture_source(source_repo)['status'] == 'UNKNOWN'
    with pytest.raises(ValueError, match='clean Git source required'):
        build(source_repo)


def test_inventory_rejects_missing_duplicate_and_symlink(source_repo, monkeypatch):
    from scripts.build_source_manifest import build
    manifest = build(source_repo)
    monkeypatch.setenv('OLA_SOURCE_MODE', 'build-inventory')
    path = source_repo / 'source-manifest.json'
    assert eb.capture_source(source_repo)['status'] == 'UNKNOWN'
    path.write_text(json.dumps(manifest)[:-1] + ', "schema":"ola-local-build-v1"}')
    assert eb.capture_source(source_repo)['status'] == 'UNKNOWN'
    path.write_text(json.dumps(manifest))
    (source_repo / 'app/link').symlink_to(source_repo / 'app/main.py')
    assert eb.capture_source(source_repo)['status'] == 'UNKNOWN'
