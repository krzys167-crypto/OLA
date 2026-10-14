"""Browser → actual FastAPI routes E2E, without network deployment.

Only the external LLM response is stubbed. All auth, tenant checks, NINA,
IGOR, evidence, replay and Human Gate execute the real OLA Python code.
This test proves CI integration, not a remote production server.
"""
import json
import os
from pathlib import Path
import tempfile
import uuid
import sys

# Support direct execution from tests/ in CI.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from playwright.sync_api import sync_playwright

WORK = Path(tempfile.mkdtemp(prefix="aurora-browser-e2e-"))
os.environ['OLA_EG_DB_PATH'] = str(WORK / 'ola-e2e.db')
import subprocess
os.environ['OLA_RUNTIME_COMMIT'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
os.environ['OLA_LLM_MODE'] = 'deterministic'
os.environ['OLA_LLM_PROVIDER'] = 'openai'
os.environ.pop('OPENAI_API_KEY', None)
# Disposable CI-only pepper, never use this public fixture value in production.
os.environ.setdefault('OLA_API_KEY_PEPPER', 'CI-ONLY-OLA-API-KEY-PEPPER-DO-NOT-USE-IN-PRODUCTION-20261012')

from fastapi.testclient import TestClient  # noqa: E402
from app.database import SessionLocal  # noqa: E402
from app.api_key_crypto import hash_api_key  # noqa: E402
from app.models import ApiKey, Tenant  # noqa: E402
from app import main as core  # noqa: E402

PAGE = Path(__file__).resolve().parents[1] / 'web' / 'index.html'
OUT = Path(os.getenv('AURORA_EVIDENCE_DIR', str(WORK / 'evidence')))
OUT.mkdir(parents=True, exist_ok=True)


def seed(tenant_name: str, count: int = 1):
    tenant_id = str(uuid.uuid4())
    raw_keys = [f'aurora-e2e-{uuid.uuid4().hex}' for _ in range(count)]
    with SessionLocal() as db:
        db.add(Tenant(id=tenant_id, name=tenant_name))
        db.flush()
        for token in raw_keys:
            db.add(ApiKey(id=str(uuid.uuid4()), tenant_id=tenant_id, key_hash=hash_api_key(token)))
        db.commit()
    return tenant_id, raw_keys


def run():
    tenant, (requester, approver) = seed('aurora-tenant-A', 2)
    _, (other_tenant,) = seed('aurora-tenant-B')
    def fake_chat(tenant_id, messages):
        assert tenant_id == tenant
        assert messages[-1] == {'role':'user','content':'Cześć OLA'}
        return {'status':'VERIFIED','message':'NINA działa. <img src=x onerror=alert(1)>'}
    core.chat = fake_chat  # only external LLM boundary is stubbed

    client = TestClient(core.app)
    calls = []
    def fastapi_bridge(path, options):
        method = options.get('method','GET')
        headers = options.get('headers') or {}
        body = options.get('body')
        response = client.request(method,path,headers=headers,content=body)
        calls.append({'path':path,'method':method,'code':response.status_code})
        return {'ok':response.is_success,'status':response.status_code,'body':response.json()}

    fetch_override = r'''(() => {
        window.fetch = async (path, opts = {}) => {
            const response = await window.pythonApi(path, opts);
            return {ok: response.ok, status: response.status, json: async () => response.body};
        };
    })()'''
    html=PAGE.read_text(encoding='utf-8').replace("<script>\n'use strict';", "<script>" + fetch_override + "</script><script>\n'use strict';")
    assert html.count('window.pythonApi') == 1, 'fetch override was not installed'
    with sync_playwright() as browser_tools:
        browser=browser_tools.chromium.launch(headless=True)
        page=browser.new_page(viewport={'width':1280,'height':900})
        page.set_default_timeout(12000)
        js_errors=[]
        page.on('pageerror', lambda e: js_errors.append(str(e)))
        page.expose_function('pythonApi',fastapi_bridge)
        page.set_content(html, wait_until='domcontentloaded')
        page.locator('#healthStatus').get_by_text('ONLINE').wait_for()
        page.screenshot(path=str(OUT/'aurora-desktop.png'), animations='disabled')

        page.locator('[data-view="settings"]').first.click()
        page.locator('#apiKey').fill(requester)
        page.locator('[data-view="chat"]').first.click()
        page.locator('#chatInput').fill('Cześć OLA')
        page.locator('#chatSend').click()
        page.get_by_text('NINA działa.').wait_for()
        assert page.locator('.message img').count() == 0, 'HTML injection into chat output'

        page.locator('.column-side [data-view="audit"]').click()
        page.locator('#auditTask').fill('controlled end-to-end recovery')
        page.locator('#auditForm button').click()
        page.get_by_text('"evidence_count": 5').wait_for()
        audit=json.loads(page.locator('#auditResult').text_content())
        assert audit['status']=='VERIFIED' and audit['evidence_count']==5
        record_id=audit['evidence_ids'][0]

        # Actual browser UI -> authenticated read-only five-layer control plane.
        # The external LLM is stubbed; FastAPI, database, authorization and
        # evidence verification are real in this isolated CI environment.
        page.locator('[data-view="settings"]').first.click()
        page.locator('#verifyApiKey').click()
        page.locator('#keyState').get_by_text('UWIERZYTELNIONY').wait_for()
        page.locator('[data-view="control"]').first.click()
        page.locator('#ccRefresh').click()
        page.locator('#ccL1').get_by_text('VERIFIED').wait_for()
        snapshot=json.loads(page.locator('#ccMonitorDetails').text_content())
        assert snapshot['tenant_id']==tenant
        assert snapshot['evidence']['record_count']==5
        assert snapshot['production']['status']=='NO-GO'
        assert 'evidence_trust' in snapshot
        assert requester not in page.locator('#ccMonitorDetails').text_content()
        assert page.locator('#ccL2').text_content()=='UNKNOWN'
        page.screenshot(path=str(OUT/'ola-control-plane-e2e.png'), animations='disabled')

        page.locator('[data-view="evidence"]').first.click()
        page.locator('#evidenceId').fill(record_id)
        page.locator('#evidenceForm button').click()
        page.wait_for_function("record_id => document.getElementById('evidenceResult').textContent.includes(record_id)", arg=record_id)
        evidence=json.loads(page.locator('#evidenceResult').text_content())
        assert evidence['tenant_id']==tenant
        page.locator('[data-view="settings"]').first.click()
        page.locator('#apiKey').fill(other_tenant)
        assert record_id not in page.locator('#evidenceResult').text_content(), 'Sensitive evidence from prior tenant remained visible'
        page.locator('[data-view="evidence"]').first.click()
        page.locator('#evidenceForm button').click()
        page.locator('#toast').get_by_text('HTTP 404').wait_for()
        assert 'tenant_id' not in page.locator('#toast').text_content()

        page.locator('[data-view="settings"]').first.click()
        page.locator('#apiKey').fill(requester)
        page.locator('[data-view="operations"]').first.click()
        page.locator('#runTask').fill('Calculate 17 * 23 and return the verified result.')
        page.locator('#runSend').click()
        page.get_by_text('"tip_hash"').wait_for()
        run=json.loads(page.locator('#runResult').text_content())
        assert run['status']=='REVIEW',run
        assert run['nina']['status']=='VERIFIED',run
        assert run['igor']['status']=='VERIFIED',run
        assert run['replay_verification']['status']=='VERIFIED',run
        assert page.locator('#approveSend').is_enabled()
        page.locator('#approverKey').fill(approver)
        page.locator('#approveSend').click()
        try:
            page.get_by_text('"approved_tip_hash"').wait_for()
        except Exception as exc:
            diagnostic = {'approval_result': page.locator('#approvalResult').text_content(), 'toast': page.locator('#toast').text_content(), 'approval_calls': [c for c in calls if '/approve' in c['path']], 'last_calls': calls[-5:]}
            (OUT/'approval-failure.json').write_text(json.dumps(diagnostic, indent=2), encoding='utf-8')
            page.screenshot(path=str(OUT/'aurora-approval-failure.png'), animations='disabled')
            raise AssertionError('Human approval E2E failure: '+json.dumps(diagnostic)) from exc
        approval=json.loads(page.locator('#approvalResult').text_content())
        assert approval['status']=='APPROVED' and approval['assurance']=='UNKNOWN',approval
        assert approval['approved_tip_hash']==run['tip_hash']

        # Run explorer reads stored hashes + independent replay, not fake stats.
        page.locator('[data-view="settings"]').first.click()
        page.locator('#verifyApiKey').click()
        page.locator('#keyState').get_by_text('UWIERZYTELNIONY').wait_for()
        page.locator('[data-view="control"]').first.click()
        page.locator('#ccRefresh').click()
        page.wait_for_function("() => document.getElementById('ccRunSelect').options.length > 1")
        page.locator('#ccRunSelect').select_option(run['run_id'])
        page.locator('#ccInspectRun').click()
        page.wait_for_function("id => document.getElementById('ccMonitorDetails').textContent.includes(id) && document.getElementById('ccMonitorDetails').textContent.includes('LOCAL_HASH_AND_REPLAY_ONLY')", arg=run['run_id'])
        replay_view=json.loads(page.locator('#ccMonitorDetails').text_content())
        assert replay_view['run_id']==run['run_id']
        assert replay_view['status']=='VERIFIED'
        assert replay_view['production']=='NO-GO'
        assert replay_view['independent_release_verification']=='UNKNOWN'
        assert requester not in page.locator('#ccMonitorDetails').text_content()

        page.locator('[data-view="settings"]').first.click()
        page.locator('#forgetKey').click()
        assert page.locator('#apiKey').input_value()==''
        assert page.locator('#approverKey').input_value()==''
        assert not js_errors,js_errors
        phone=browser.new_page(viewport={'width':390,'height':844})
        phone.expose_function('pythonApi',fastapi_bridge)
        phone.set_content(html,wait_until='domcontentloaded')
        assert phone.evaluate('document.documentElement.scrollWidth <= window.innerWidth + 1')
        phone.screenshot(path=str(OUT/'aurora-mobile.png'), animations='disabled')
        browser.close()
    statuses={path:sum(x['path']==path for x in calls) for path in ('/health','/auth/session','/control/overview','/control/runs/'+run['run_id'],'/chat','/audit','/nina-run','/nina-run/'+run['run_id']+'/approve')}
    result={'status':'PASS','scope':'CI in-process actual FastAPI and real NINA/IGOR/REPLAY; LLM stubbed','routes':statuses,'tenant_isolation':'PASS','independent_approval':'PASS','html_injection':'BLOCKED','mobile':'PASS','production_live':'NOT_TESTED'}
    (OUT/'result.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,indent=2))

if __name__=='__main__':run()