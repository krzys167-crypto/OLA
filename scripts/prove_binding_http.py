#!/usr/bin/env python3
"""Real loopback HTTP proof from a clean Git checkout; deterministic model only."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main():
    with tempfile.TemporaryDirectory(prefix="ola-binding-proof-") as directory:
        os.environ.update(OLA_EG_DB_PATH=str(Path(directory) / "proof.db"),
            OLA_API_KEY_PEPPER="LOCAL-PROOF-ONLY-" + uuid.uuid4().hex,
            OLA_RUNTIME_COMMIT=subprocess.check_output(['git','rev-parse','HEAD'], cwd=ROOT,text=True).strip(),
            OLA_LLM_PROVIDER="local", OLA_LLM_MODE="deterministic")
        from app.main import app
        from app.database import SessionLocal
        from app.api_key_crypto import hash_api_key
        from app.models import Tenant, ApiKey
        from app.execution_binding import capture_source
        source = capture_source()
        assert source['status'] == 'LOCAL', source
        tenant, requester, reviewer = (uuid.uuid4().hex for _ in range(3))
        request_key, review_key = uuid.uuid4().hex, uuid.uuid4().hex
        with SessionLocal() as db:
            db.add(Tenant(id=tenant,name="local-http-proof")); db.flush()
            db.add_all([ApiKey(id=requester,tenant_id=tenant,key_hash=hash_api_key(request_key)),
                        ApiKey(id=reviewer,tenant_id=tenant,key_hash=hash_api_key(review_key))]); db.commit()
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0)); port = sock.getsockname()[1]
        with open(Path(directory)/'server.log','w') as log:
            server = subprocess.Popen([sys.executable,'-m','uvicorn','app.main:app',
                '--host','127.0.0.1','--port',str(port)],cwd=ROOT,env=os.environ.copy(),stdout=log,stderr=log)
            try:
                import httpx
                with httpx.Client(base_url=f'http://127.0.0.1:{port}',timeout=30, trust_env=False) as client:
                    for _ in range(100):
                        try:
                            if client.get('/health').status_code == 200: break
                        except httpx.ConnectError: pass
                        time.sleep(.1)
                    else: raise RuntimeError('server did not start')
                    denied = client.post('/agent-run', headers={'X-API-Key':request_key},
                        json={'task':'Calculate 17 * 23','requested_tools':['safe_expression']})
                    assert denied.status_code == 200 and denied.json()['reason'] == 'TOOL_SCOPE_DENIED'
                    assert denied.json()['execution'] == []
                    response = client.post('/nina-run',headers={'X-API-Key':request_key},
                        json={'task':'Calculate 17 * 23','requested_tools':['safe_expression','local_mcp_tool_registry.sha256']})
                    assert response.status_code == 200, response.text
                    run = response.json(); report = run['decision_report_v2']
                    assert report['bindings']['source_sha'] == source['sha']
                    assert report['assurance']['status'] == 'UNKNOWN'
                    assert run['nina']['status'] == 'VERIFIED', run
                    headers = {'Authorization':'Bearer ' + review_key}
                    body = {'tip_hash':run['tip_hash'],'report_sha256':report['report_sha256'],'scope':'review-result'}
                    wrong = client.post(f"/nina-run/{run['run_id']}/approve",headers=headers,
                        json={**body,'report_sha256':'0'*64})
                    assert wrong.status_code == 409
                    approved = client.post(f"/nina-run/{run['run_id']}/approve",headers=headers,json=body)
                    assert approved.status_code == 200, approved.text
                    approval = approved.json()
                    assert approval['status'] == 'APPROVED' and approval['production_eligible'] is False
                    state_url = f"/nina-run/{run['run_id']}/approval"
                    assert client.get(state_url,headers=headers).json()['status'] == 'APPROVED'
                    repeat = client.post(f"/nina-run/{run['run_id']}/approve",headers=headers,json=body)
                    assert repeat.status_code == 409
                    revoked = client.post(state_url+'/revoke',headers=headers,
                        json={'human_approval_digest':approval['human_approval_digest']})
                    assert revoked.status_code == 200
                    assert client.get(state_url,headers=headers).json()['status'] == 'REVOKED'
                    print(json.dumps({'result':'PASS','source':source,
                        'transport':'real-loopback-http','model':'local-deterministic',
                        'source_observer_mocked':False,'report_sha256':report['report_sha256'],
                        'policy_digest':report['bindings']['policy_digest'],
                        'human_approval_digest':approval['human_approval_digest'],
                        'unauthorized_tool_scope':'BLOCKED_BEFORE_EXECUTION','wrong_report':'BLOCKED','repeat':'BLOCKED','revocation':'REVOKED',
                        'assurance':'UNKNOWN','production':'NO-GO',
                        'run_response':run,'approval_response':approval,
                        'revocation_response':revoked.json()},indent=2))
            finally:
                server.terminate()
                try: server.wait(timeout=10)
                except subprocess.TimeoutExpired: server.kill(); server.wait()


if __name__ == '__main__':
    main()
