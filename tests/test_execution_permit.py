import concurrent.futures
import uuid
import pytest
from sqlalchemy import select
from app import execution_permit as ep
from app.models import ExecutionPermit, EvidenceRecord
from app.database import SessionLocal


@pytest.fixture
def setup():
    tenant = uuid.uuid4().hex
    now = [1000]
    binding = {'source_sha':'a'*40,'source_files_digest':'b'*64,'policy_digest':'c'*64}
    actors = {'owner':ep.Actor('test-only','human',tenant,'owner',1000),
              'worker':ep.Actor('test-only','service',tenant,'executor',1000),
              'other-key':ep.Actor('test-only','service',tenant,'owner',1000),
              'foreign':ep.Actor('test-only','foreign','other','owner',1000)}
    def resolve(token): return actors[token]
    def service():return ep.PermitService(resolve_identity=resolve,
        binding_provider=lambda:dict(binding),clock=lambda:now[0])
    return service,now,binding


def prepare_approved(factory):
    s=factory();p=s.prepare('worker','OLA proof')
    s.approve('owner',p['permit_id'],p['subject_digest'])
    return p


def test_default_identity_adapter_fails_closed():
    with pytest.raises(ep.PermitDenied,match='not configured'):
        ep.PermitService().prepare('arbitrary-key','text')


def test_durable_completion_prevents_reuse_from_new_service(setup):
    factory,_,_=setup;p=prepare_approved(factory)
    result=factory().execute('worker',p['permit_id'],p['subject_digest'])
    assert result['receipt']['assurance']=='UNKNOWN'
    with pytest.raises(ep.PermitDenied):factory().execute('worker',p['permit_id'],p['subject_digest'])


def test_no_owner_approval_no_execution(setup):
    factory,_,_=setup;p=factory().prepare('worker','text')
    with pytest.raises(ep.PermitDenied):factory().execute('worker',p['permit_id'],p['subject_digest'])


@pytest.mark.parametrize('actor',['worker','other-key','foreign'])
def test_role_subject_and_tenant_are_distinct_checks(setup,actor):
    factory,_,_=setup;p=factory().prepare('worker','text')
    with pytest.raises(ep.PermitDenied):factory().approve(actor,p['permit_id'],p['subject_digest'])


@pytest.mark.parametrize('field',['source_sha','policy_digest','source_files_digest'])
def test_binding_change_blocks_execution(setup,field):
    factory,_,binding=setup;p=prepare_approved(factory);binding[field]='d'*len(binding[field])
    with pytest.raises(ep.PermitDenied):factory().execute('worker',p['permit_id'],p['subject_digest'])


def test_expiry_and_parameter_digest(setup):
    factory,now,_=setup;p=prepare_approved(factory)
    with pytest.raises(ep.PermitDenied):factory().execute('worker',p['permit_id'],'e'*64)
    now[0]=1300
    with pytest.raises(ep.PermitDenied):factory().execute('worker',p['permit_id'],p['subject_digest'])


def test_revoked_cannot_execute(setup):
    factory,_,_=setup;p=prepare_approved(factory)
    factory().revoke('owner',p['permit_id'],p['subject_digest'])
    with pytest.raises(ep.PermitDenied):factory().execute('worker',p['permit_id'],p['subject_digest'])


def test_racing_executors_commit_once(setup):
    factory,_,_=setup;p=prepare_approved(factory)
    def execute(_):
        try:factory().execute('worker',p['permit_id'],p['subject_digest']);return 'done'
        except ep.PermitDenied:return 'blocked'
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results=list(pool.map(execute,range(4)))
    assert results.count('done')==1
    with SessionLocal() as db:
        row=db.get(ExecutionPermit,p['permit_id'])
        assert row.state=='COMPLETED'
        events=db.scalars(select(EvidenceRecord).where(EvidenceRecord.tenant_id==row.tenant_id,
            EvidenceRecord.record_type=='permit.completed')).all()
        assert len(events)==1


def test_failure_before_commit_rolls_back_local_result_and_consumption(setup,monkeypatch):
    factory,_,_=setup;p=prepare_approved(factory)
    original=ep._event
    def crash(db,tenant,kind,payload):
        if kind=='permit.completed':raise RuntimeError('simulated failure before commit')
        return original(db,tenant,kind,payload)
    with monkeypatch.context() as m:
        m.setattr(ep,'_event',crash)
        with pytest.raises(RuntimeError):factory().execute('worker',p['permit_id'],p['subject_digest'])
    with SessionLocal() as db:assert db.get(ExecutionPermit,p['permit_id']).state=='APPROVED'
    assert factory().execute('worker',p['permit_id'],p['subject_digest'])['receipt']['result']


def test_separate_inspector_rejects_mutation(setup,tmp_path):
    import json,subprocess,sys
    factory,_,binding=setup;p=prepare_approved(factory)
    artifact=factory().execute('worker',p['permit_id'],p['subject_digest'])
    path=tmp_path/'receipt.json';path.write_text(json.dumps(artifact))
    command=[sys.executable,'scripts/inspect_permit_receipt.py',str(path),
        '--source-sha',binding['source_sha'],'--policy-digest',binding['policy_digest']]
    good=subprocess.run(command,capture_output=True,text=True)
    assert good.returncode==0 and json.loads(good.stdout)['integrity']=='LOCAL'
    artifact['receipt']['result']='0'*64;path.write_text(json.dumps(artifact))
    bad=subprocess.run(command,capture_output=True,text=True)
    assert bad.returncode==1
