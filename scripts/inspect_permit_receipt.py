#!/usr/bin/env python3
"""Separate-process LOCAL consistency inspector. No signature authentication."""
import argparse
import hashlib
import json
import sys


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),
        ensure_ascii=False,allow_nan=False).encode()).hexdigest()


def unique(pairs):
    out={}
    for key,value in pairs:
        if key in out:raise ValueError('duplicate JSON key')
        out[key]=value
    return out


def inspect(bundle,source_sha,policy_digest):
    try:
        s,a,r=(bundle[k] for k in ('subject','approval','receipt'))
        sd=digest(s)
        return (s['schema']=='ola.execution-permit.v1' and s['operation']=='sha256-text'
            and s['binding']['source_sha']==source_sha and s['binding']['policy_digest']==policy_digest
            and s['resource']==f"tenant:{s['tenant_id']}:result:{s['permit_id']}"
            and s['requester']['tenant_id']==s['tenant_id']==a['owner']['tenant_id']
            and a['owner']!=s['requester'] and r['executor']==s['requester']
            and s['expires_at']-s['issued_at']==300
            and s['issued_at']<=a['approved_at']<=r['finished_at']<s['expires_at']
            and 0<=a['approved_at']-a['authenticated_at']<=300
            and a['subject_digest']==sd==r['subject_digest'] and r['approval_digest']==digest(a)
            and r['schema']=='ola.local-permit-receipt.v1'
            and r['assurance']=='UNKNOWN' and r['production_eligible'] is False
            and len(s['parameters']['text'].encode())<=65536
            and r['result']==hashlib.sha256(s['parameters']['text'].encode()).hexdigest())
    except (KeyError,TypeError,ValueError,AttributeError):return False


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('file');p.add_argument('--source-sha',required=True)
    p.add_argument('--policy-digest',required=True);args=p.parse_args()
    try:
        with open(args.file) as handle:bundle=json.load(handle,object_pairs_hook=unique)
        ok=inspect(bundle,args.source_sha,args.policy_digest)
    except (OSError,ValueError):ok=False
    print(json.dumps({'integrity':'LOCAL' if ok else 'BLOCKED','execution_assurance':'UNKNOWN',
                      'production_eligible':False}))
    return 0 if ok else 1


if __name__=='__main__':sys.exit(main())
