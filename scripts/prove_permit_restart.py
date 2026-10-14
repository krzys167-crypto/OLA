#!/usr/bin/env python3
"""Pilot process restart proof. Identity resolver is an explicit TEST FIXTURE."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def worker(action,pid=None,claimed=None):
    from app.main import app
    from app.execution_permit import Actor,PermitService,PermitDenied
    from app.execution_binding import capture_source
    tenant=os.environ['OLA_PILOT_TENANT']
    def fixture_identity(credential):
        roles={'fixture-owner':('owner','test-human'),'fixture-executor':('executor','test-service')}
        role,subject=roles[credential]
        return Actor('LOCAL-TEST-FIXTURE',subject,tenant,role,int(time.time()))
    service=PermitService(resolve_identity=fixture_identity)
    try:
        if action=='prepare':out=service.prepare('fixture-executor','OLA harmless permit proof')
        elif action=='approve':out=service.approve('fixture-owner',pid,claimed)
        else:out=service.execute('fixture-executor',pid,claimed)
        return {'result':'PASS','data':out}
    except PermitDenied as exc:return {'result':'BLOCKED','reason':str(exc)}


def main():
    if len(sys.argv)>1:
        print(json.dumps(worker(*sys.argv[1:]),ensure_ascii=False));return
    with tempfile.TemporaryDirectory(prefix='ola-permit-proof-') as d:
        env=os.environ.copy();env.update(OLA_EG_DB_PATH=str(Path(d)/'proof.db'),
            OLA_PILOT_TENANT=uuid.uuid4().hex,OLA_API_KEY_PEPPER='LOCAL-PILOT-ONLY',
            OLA_RUNTIME_COMMIT=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip())
        def invoke(*args):
            output=subprocess.check_output([sys.executable,str(Path(__file__).resolve()),*args],env=env,cwd=ROOT,text=True)
            return json.loads(output)
        p=invoke('prepare');assert p['result']=='PASS',p
        pid,sd=p['data']['permit_id'],p['data']['subject_digest']
        assert invoke('execute',pid,sd)['result']=='BLOCKED'
        approval=invoke('approve',pid,sd);assert approval['result']=='PASS',approval
        completed=invoke('execute',pid,sd);assert completed['result']=='PASS',completed
        repeated=invoke('execute',pid,sd);assert repeated['result']=='BLOCKED',repeated
        print(json.dumps({'result':'PASS','source_sha':env['OLA_RUNTIME_COMMIT'],
            'identity':'LOCAL-TEST-FIXTURE; NOT USER AUTHENTICATION',
            'execution':'sha256-text only; no external effects',
            'fresh_process_per_step':True,'without_approval':'BLOCKED','repeat_after_restart':'BLOCKED',
            'evidence':completed['data'],'production':'NO-GO'},indent=2))


if __name__=='__main__':main()
