#!/usr/bin/env python3
"""Fail closed on every new main-push commit, including merge ancestors."""
from __future__ import annotations
import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Callable

HEX=re.compile(r"^[0-9a-f]{40}$")
OWNER_KEY_URL="https://github.com/krzysztofcieciwa07-ship-it.gpg"
GITHUB_WEBFLOW_KEY_URL="https://github.com/web-flow.gpg"
GITHUB_WEBFLOW_SIGNER_FPR="968479A1AFF927E37D1A566BB5690EEEBB952194"

class GateBlocked(Exception):
    pass

def checked_sha(value:object)->str:
    if not isinstance(value,str) or not HEX.fullmatch(value) or value=="0"*40:
        raise GateBlocked("invalid commit SHA")
    return value

def allowlist(value:str)->set[str]:
    keys=[x.upper() for x in re.split(r"[,;\s]+",value.strip()) if x]
    if not keys or any(not re.fullmatch(r"(?:[0-9A-F]{40}|[0-9A-F]{64})",x) for x in keys):
        raise GateBlocked("trusted signing-key allowlist missing or invalid")
    return set(keys)

def validate_main_push(*,before:str,head:str,commits:list[str],allowed_fprs:str,
                       fetch:Callable[[str],object],verify:Callable[[str,str,str,set[str]],str])->dict:
    before,head=checked_sha(before),checked_sha(head)
    allowed=allowlist(allowed_fprs)
    if before==head or not isinstance(commits,list) or not 1<=len(commits)<=250:
        raise GateBlocked("empty or unsupported push commit range")
    shas=[checked_sha(x) for x in commits]
    if len(set(shas))!=len(shas):
        raise GateBlocked("duplicate commit SHA in push")
    if shas[-1]!=head or before in shas:
        raise GateBlocked("invalid commit range head or previous SHA")
    seen={before}
    graph={}
    owner_count=merge_count=0
    output=[]
    for sha in shas:
        try:
            d=fetch(sha)
        except Exception as exc:
            raise GateBlocked(f"GitHub API failure for {sha}: {type(exc).__name__}") from exc
        if not isinstance(d,dict) or d.get("sha")!=sha:
            raise GateBlocked("GitHub commit SHA mismatch")
        parents=d.get("parents")
        if not isinstance(parents,list) or len(parents) not in (1,2):
            raise GateBlocked("unexpected parent count")
        parent_shas=[checked_sha(p.get("sha") if isinstance(p,dict) else None) for p in parents]
        if any(p not in seen for p in parent_shas):
            raise GateBlocked("incomplete merge ancestry or non-topological push range")
        graph[sha]=parent_shas
        data=d.get("commit") or {}
        proof=data.get("verification") or {}
        if proof.get("verified") is not True or proof.get("reason")!="valid":
            raise GateBlocked(f"GitHub-unverified commit: {sha}")
        signature,payload=proof.get("signature"),proof.get("payload")
        if not isinstance(signature,str) or not signature.startswith("-----BEGIN PGP SIGNATURE-----") or not isinstance(payload,str) or not payload:
            raise GateBlocked(f"signed payload or PGP signature missing: {sha}")
        if len(parents)==2:
            committer=data.get("committer") or {}
            if committer.get("name")!="GitHub" or committer.get("email")!="noreply@github.com":
                raise GateBlocked("untrusted merge identity")
            try:
                signer=verify(signature,payload,"noreply@github.com",{GITHUB_WEBFLOW_SIGNER_FPR}).upper()
            except GateBlocked:raise
            except Exception as exc:
                raise GateBlocked(f"independent GitHub merge verification failed: {type(exc).__name__}") from exc
            if signer!=GITHUB_WEBFLOW_SIGNER_FPR:
                raise GateBlocked("untrusted GitHub merge signature")
            merge_count+=1
            kind="GITHUB_SIGNED_MERGE"
        else:
            email=(data.get("author") or {}).get("email")
            if not isinstance(email,str) or not email:
                raise GateBlocked("source author email missing")
            try:
                signer=verify(signature,payload,email,allowed).upper()
            except GateBlocked:raise
            except Exception as exc:
                raise GateBlocked(f"independent GPG verification failed: {type(exc).__name__}") from exc
            if signer not in allowed:
                raise GateBlocked("unapproved signer")
            owner_count+=1
            kind="OWNER_GPG_VERIFIED"
        output.append({"sha":sha,"classification":kind,"signer":signer})
        seen.add(sha)
    reachable=set()
    def visit(node):
        if node==before or node in reachable:return
        reachable.add(node)
        for p in graph.get(node,[]):visit(p)
    visit(head)
    if reachable!=set(shas):
        raise GateBlocked("extraneous commits outside new HEAD ancestry")
    return {"status":"VERIFIED","gate":"OLA_MAIN_PUSH_SIGNED_ANCESTRY",
            "before_sha":before,"head_sha":head,"verified_count":len(output),
            "owner_signed_count":owner_count,"github_merge_count":merge_count,
            "commits":output,"human_gate":"PENDING","production_go":"NO-GO"}

def _get_commit(repo:str,token:str,sha:str)->object:
    req=urllib.request.Request(f"https://api.github.com/repos/{repo}/commits/{sha}",headers={
        "Authorization":"Bearer "+token,"Accept":"application/vnd.github+json",
        "X-GitHub-Api-Version":"2022-11-28","User-Agent":"OLA-main-signature-gate/1"})
    with urllib.request.urlopen(req,timeout=20) as response:return json.load(response)

def _rev_list(before:str,head:str)->list[str]:
    for args in (["git","rev-parse","--verify",f"{before}^{{commit}}"],
                 ["git","rev-parse","--verify",f"{head}^{{commit}}"],
                 ["git","merge-base","--is-ancestor",before,head]):
        r=subprocess.run(args,capture_output=True,text=True,timeout=30)
        if r.returncode:raise GateBlocked("main push before/head Git objects or ancestry invalid")
    r=subprocess.run(["git","rev-list","--reverse","--topo-order",f"{before}..{head}"],
                     capture_output=True,text=True,timeout=30)
    if r.returncode:raise GateBlocked("git rev-list failed")
    return [x for x in r.stdout.splitlines() if x]

def main()->int:
    output=Path("main-signature-result.json")
    result={"status":"BLOCKED","gate":"OLA_MAIN_PUSH_SIGNED_ANCESTRY",
            "human_gate":"PENDING","production_go":"NO-GO"}
    verifier=None
    github_verifier=None
    try:
        from verify_github_signatures import GPG as GPGVerifier
        repo=os.environ.get("GITHUB_REPOSITORY","")
        if repo!="krzysztofcieciwa07-ship-it/OLA":
            raise GateBlocked("unexpected target repository")
        if os.environ.get("GITHUB_REF")!="refs/heads/main" or os.environ.get("GITHUB_EVENT_NAME")!="push":
            raise GateBlocked("not a main push")
        token=os.environ.get("GITHUB_TOKEN","")
        if not token:raise GateBlocked("GitHub token unavailable")
        allowed_raw=os.environ.get("OLA_ALLOWED_SIGNER_FPRS","")
        approved=allowlist(allowed_raw)
        if GITHUB_WEBFLOW_SIGNER_FPR in approved:
            raise GateBlocked("GitHub merge signing key cannot authorize owner source commits")
        before,head=checked_sha(os.environ.get("PUSH_BEFORE_SHA")),checked_sha(os.environ.get("SOURCE_SHA"))
        if subprocess.run(["git","rev-parse","HEAD"],capture_output=True,text=True,check=True).stdout.strip()!=head:
            raise GateBlocked("checked out source is not push HEAD")
        shas=_rev_list(before,head)
        request=urllib.request.Request(OWNER_KEY_URL,headers={"User-Agent":"OLA-main-signature-gate/1"})
        with urllib.request.urlopen(request,timeout=20) as resp:keys=resp.read(1_000_001)
        if len(keys)>1_000_000:raise GateBlocked("owner key bundle too large")
        verifier=GPGVerifier(keys)
        request=urllib.request.Request(GITHUB_WEBFLOW_KEY_URL,headers={"User-Agent":"OLA-main-signature-gate/1"})
        with urllib.request.urlopen(request,timeout=20) as resp:github_keys=resp.read(1_000_001)
        if len(github_keys)>1_000_000:raise GateBlocked("GitHub merge key bundle too large")
        github_verifier=GPGVerifier(github_keys)
        def independent_verify(signature,payload,email,allowed):
            selected=github_verifier if allowed=={GITHUB_WEBFLOW_SIGNER_FPR} else verifier
            return selected.verify(signature,payload,email,allowed)
        result=validate_main_push(before=before,head=head,commits=shas,allowed_fprs=allowed_raw,
                                  fetch=lambda sha:_get_commit(repo,token,sha),verify=independent_verify)
        rc=0
    except Exception as exc:
        result["reason"]=str(exc) if isinstance(exc,GateBlocked) else type(exc).__name__
        rc=1
    finally:
        if github_verifier is not None:github_verifier.close()
        if verifier is not None:verifier.close()
    output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf8")
    print(json.dumps(result,sort_keys=True))
    return rc

if __name__=="__main__":sys.exit(main())
