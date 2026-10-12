#!/usr/bin/env python3
"""Independent fail-closed policy check for machine-generated OLA release claims.

Passing this checker NEVER authorizes a production deployment or Human Gate.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import sys

SHA=re.compile(r"^[0-9a-f]{40}$")
DIGEST=re.compile(r"^[0-9a-f]{64}$")
REQUIRED={"ci","state-continuity","stability","provenance","signatures",
          "real-runtime","stress","tamper","replay","human-gate"}
STATES={"BLOCKED","PREMERGE_CI_PASSED","ATTESTED_PENDING_HUMAN"}
REQUIRED_EXACT_CI=frozenset({
    "Nina TDD",
    "OLA DI-OS Product Gate",
    "NINA IGOR Ollama Full Flow",
    "OLA Decision Evidence Gate",
    "Revenue Surface Gate",
    "OLA E2E Gate",
    "Evidence Graph v0.1",
    "Real LLM Ollama Runtime Gate",
    "Provenance Mutation Gate",
    "Provenance Gate Final",
    "Nina Igor Gate",
    "Nina Real Runtime Provenance Gate (OpenAI optional)",
    "OLA State Continuity and Stability",
    "OLA Real Runtime Stress Gate",
})
REQUIRED_REFERENCE_CI=frozenset({"OLA Frontier Baseline"})

class PolicyError(ValueError):
    pass

def need(test, message):
    if not test:raise PolicyError(message)

def data(path):
    try: obj=json.loads(path.read_text(encoding="utf-8"))
    except (OSError,ValueError) as exc:
        raise PolicyError("evidence unavailable or invalid: "+path.name) from exc
    need(isinstance(obj,dict),"evidence is not an object: "+path.name)
    return obj

def digest_checked(path, sumfile):
    need(path.is_file() and sumfile.is_file(),"release subject/checksum missing")
    rows=sumfile.read_text(encoding="utf-8").strip().splitlines()
    need(len(rows)==1,"checksum missing or ambiguous")
    entry=rows[0].split(maxsplit=1)
    need(len(entry)==2 and DIGEST.fullmatch(entry[0]),"invalid checksum")
    need(entry[1].lstrip("*")==path.name,"release subject name differs from checksum")
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1048576),b""):h.update(chunk)
    need(h.hexdigest()==entry[0],"release subject digest mismatch")

def validate(m,*,source,event,event_sha,ref,root):
    need(isinstance(source,str) and SHA.fullmatch(source),"invalid expected source")
    need(isinstance(event_sha,str) and SHA.fullmatch(event_sha),"invalid workflow event SHA")
    need(m.get("schema")=="ola-production-evidence-v1","unsupported schema")
    need(m.get("commit")==source,"SOURCE_SHA mismatch")
    need(m.get("workflow_event")==event and m.get("workflow_event_sha")==event_sha,
         "workflow identity mismatch")
    gates=m.get("required_gates")
    need(isinstance(gates,list) and len(gates)==len(REQUIRED) and set(gates)==REQUIRED,
         "missing, unexpected or duplicate evidence gates")
    need(m.get("human_gate")=="PENDING","untrusted Human Gate approval claim")
    need(m.get("production_deployment")=="NOT_PERFORMED","untrusted deployment claim")
    need(m.get("go_no_go")=="NO-GO","unauthorized production GO")
    status=m.get("final_status")
    need(status in STATES,"false production VERIFIED/GO claim")
    signature=m.get("commit_signature_gate")
    need(signature in ("BLOCKED","AUTHORIZED_GPG_VERIFIED","GITHUB_COMMIT_VERIFIED"),
         "invalid signer status")
    if event=="pull_request":
        need(status in ("BLOCKED","PREMERGE_CI_PASSED"),"PR cannot claim production release")
        need(signature in ("BLOCKED","AUTHORIZED_GPG_VERIFIED"),"invalid PR signer")
        need(m.get("source_snapshot") is None and m.get("release_image") is None,
             "PR cannot claim release artifacts")
        if status=="PREMERGE_CI_PASSED":
            need(signature=="AUTHORIZED_GPG_VERIFIED","PR signature gate missing")
            need(m.get("source_attestation")=="PR_ONLY_NOT_RELEASE" and
                 m.get("image_attestation")=="PR_ONLY_NOT_RELEASE","invalid PR attestation")
        else:
            need(m.get("source_attestation")=="NOT_PERFORMED" and
                 m.get("image_attestation")=="NOT_PERFORMED","blocked PR attestation claim")
        if signature=="AUTHORIZED_GPG_VERIFIED":
            p=data(root/"signature-gate-result.json")
            need(p.get("status")=="VERIFIED" and p.get("head_sha")==source and
                 p.get("production_go")=="NO-GO" and type(p.get("verified_count")) is int
                 and p["verified_count"]>0,"unbound PR GPG proof")
    elif event=="push":
        need(ref=="refs/heads/main" and source==event_sha,"not exact main push")
        need(status in ("BLOCKED","ATTESTED_PENDING_HUMAN"),"invalid main push claim")
        need(signature in ("BLOCKED","GITHUB_COMMIT_VERIFIED"),"invalid main signer")
        if status=="ATTESTED_PENDING_HUMAN":
            need(signature=="GITHUB_COMMIT_VERIFIED","main signer gate missing")
            need(m.get("source_snapshot")==f"ola-source-{source}.tar.gz" and
                 m.get("release_image")=="ola-release-image.tar","unbound release subjects")
            need(m.get("source_attestation")=="VERIFIED" and
                 m.get("image_attestation")=="VERIFIED","missing attestation claims")
            digest_checked(root/m["source_snapshot"],root/"source-sha256.txt")
            digest_checked(root/m["release_image"],root/"image-sha256.txt")
        else:
            need(m.get("source_snapshot") is None and m.get("release_image") is None,
                 "blocked push claims release subjects")
            need(m.get("source_attestation")=="NOT_PERFORMED" and
                 m.get("image_attestation")=="NOT_PERFORMED","blocked push attestation claim")
        if signature=="GITHUB_COMMIT_VERIFIED":
            p=data(root/"main-signature-result.json")
            need(p.get("status")=="VERIFIED" and p.get("head_sha")==source and
                 p.get("production_go")=="NO-GO" and type(p.get("verified_count")) is int
                 and p["verified_count"]>0,"unbound main GPG proof")
    else:
        need(event=="workflow_dispatch" and status=="BLOCKED" and signature=="BLOCKED",
             "unauthorized trigger or manual promotion")
        need(m.get("source_snapshot") is None and m.get("release_image") is None and
             m.get("source_attestation")=="NOT_PERFORMED" and
             m.get("image_attestation")=="NOT_PERFORMED","manual dispatch claims release")
    if status!="BLOCKED":
        p=data(root/"gate-status.json")
        need(all(not p.get(k) for k in ("missing","pending","failed")),
             "evidence gate missing, pending or failed")
        for group,required in (
            ("exact_source_gates",REQUIRED_EXACT_CI),
            ("reference_gates",REQUIRED_REFERENCE_CI),
        ):
            checks=p.get(group)
            need(isinstance(checks,dict),"required CI group absent")
            actual=set(checks)
            need(not (required-actual),"missing required CI gate: "+",".join(sorted(required-actual)))
            need(not (actual-required),"unexpected CI gate: "+",".join(sorted(actual-required)))
            for name,run in checks.items():
                need(isinstance(run,dict) and run.get("status")=="completed" and
                     run.get("conclusion")=="success","required CI failed: "+name)
                need(type(run.get("id")) is int and run["id"]>0,
                     "CI run identity missing: "+name)
                expected_event=event if group=="exact_source_gates" else "push"
                need(run.get("event")==expected_event,"CI event mismatch: "+name)
                if group=="exact_source_gates":
                    need(run.get("head_sha")==source,"CI source SHA drift: "+name)
                else:
                    need(isinstance(run.get("head_sha"),str) and
                         SHA.fullmatch(run["head_sha"]) is not None,
                         "reference CI SHA invalid: "+name)
    return status

def main():
    try:
        status=validate(data(Path("production-manifest.json")),
            source=os.getenv("EXPECTED_SOURCE_SHA",""),
            event=os.getenv("GITHUB_EVENT_NAME",""),
            event_sha=os.getenv("GITHUB_SHA",""),
            ref=os.getenv("GITHUB_REF",""),root=Path.cwd())
    except (PolicyError,OSError,ValueError,TypeError) as exc:
        print("MANIFEST_POLICY=BLOCKED "+str(exc),file=sys.stderr)
        return 1
    print("MANIFEST_POLICY=PASS state="+status+" production=NO-GO")
    return 0

if __name__=="__main__":sys.exit(main())
