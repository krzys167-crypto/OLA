#!/usr/bin/env python3
"""Verify every PR commit using GitHub metadata AND independent GPG verification.

This must execute from the base branch on pull_request_target. Never run PR code.
"""
from __future__ import annotations
import json, os, re, subprocess, sys, tempfile, time, urllib.request
from pathlib import Path

SHA=re.compile(r"^[0-9a-f]{40}$")
FPR=re.compile(r"^(?:[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$")
KEYS_URL="https://github.com/krzysztofcieciwa07-ship-it.gpg"

class Blocked(Exception):
    pass

def allowed_keys(raw):
    keys=[x.upper() for x in re.split(r"[,;\s]+",raw.strip()) if x]
    if not keys or any(not FPR.fullmatch(x) for x in keys):
        raise Blocked("trusted fingerprint allowlist missing or invalid")
    return set(keys)

def sha(value, name):
    if not isinstance(value,str) or not SHA.fullmatch(value):
        raise Blocked("invalid "+name)
    return value

def gate(*,repo,pr_number,head,base,fingerprints,fetch,verify):
    allowed=allowed_keys(fingerprints)
    sha(head,"head");sha(base,"base")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",repo) or not isinstance(pr_number,int) or pr_number<1:
        raise Blocked("invalid repository or PR number")
    def get(path):
        try:
            return fetch(path)
        except Exception as exc:
            raise Blocked("GitHub API failed for "+path+" ("+type(exc).__name__+")") from exc
    def refs():
        p=get("pulls/"+str(pr_number))
        if not isinstance(p,dict) or p.get("state")!="open":raise Blocked("PR not open")
        if p.get("head",{}).get("sha")!=head:raise Blocked("head drift")
        if p.get("base",{}).get("sha")!=base or p.get("base",{}).get("ref")!="main":raise Blocked("base drift")
        n=p.get("commits")
        if type(n) is not int or not 1<=n<=250:raise Blocked("commit count unsupported")
        return n
    n=refs()
    items=[]
    for page in range(1,5):
        data=get(f"pulls/{pr_number}/commits?per_page=100&page={page}")
        if not isinstance(data,list) or len(data)>100:raise Blocked("invalid pagination")
        items.extend(data)
        if len(items)>250:raise Blocked("pagination overflow")
        if len(data)<100:break
    else:
        raise Blocked("pagination limit")
    if len(items)!=n:raise Blocked("commit count/pagination mismatch")
    shas=[sha(x.get("sha") if isinstance(x,dict) else None,"commit SHA") for x in items]
    if len(set(shas))!=n:raise Blocked("duplicate commit SHA")
    if shas[-1]!=head:raise Blocked("last PR commit not head")
    previous=base
    attestations=[]
    for current in shas:
        c=get("commits/"+current)
        if not isinstance(c,dict) or c.get("sha")!=current:raise Blocked("commit detail SHA mismatch")
        parents=c.get("parents")
        if not isinstance(parents,list) or len(parents)!=1 or parents[0].get("sha")!=previous:
            raise Blocked("nonlinear ancestry or base changed")
        detail=c.get("commit") or {}
        v=detail.get("verification") or {}
        if v.get("verified") is not True or v.get("reason")!="valid":
            raise Blocked("unsigned or unverified commit "+current)
        signature,payload=v.get("signature"),v.get("payload")
        email=(detail.get("author") or {}).get("email")
        if not isinstance(signature,str) or "-----BEGIN PGP SIGNATURE-----" not in signature or not isinstance(payload,str) or not payload or not isinstance(email,str) or not email:
            raise Blocked("detached signature, payload or author UID missing")
        signer=verify(signature,payload,email,allowed)
        if signer.upper() not in allowed:raise Blocked("unapproved signer")
        attestations.append({"sha":current,"fingerprint":signer.upper(),"github_verified":True,"gpg_verified":True})
        previous=current
    if refs()!=n:raise Blocked("PR changed during verification")
    return {"status":"VERIFIED","head_sha":head,"base_sha":base,"verified_count":n,"commits":attestations,"human_gate":"PENDING","production_go":"NO-GO"}

class GPG:
    def __init__(self,public_keys):
        self.t=tempfile.TemporaryDirectory(prefix="ola-signed-gate-")
        self.home=Path(self.t.name)
        if not public_keys:raise Blocked("owner public keys missing")
        p=subprocess.run(["gpg","--homedir",str(self.home),"--batch","--no-tty","--import"],input=public_keys,capture_output=True)
        if p.returncode:raise Blocked("public signing key import failed")
    def close(self):
        self.t.cleanup()
    def verify(self,signature,payload,email,allowed):
        with tempfile.TemporaryDirectory(dir=self.home) as d:
            signature_file=Path(d)/"signature.asc"
            message_file=Path(d)/"payload"
            signature_file.write_text(signature,encoding="utf8")
            message_file.write_bytes(payload.encode("utf8"))
            p=subprocess.run(["gpg","--homedir",str(self.home),"--batch","--no-tty","--status-fd","1","--verify",str(signature_file),str(message_file)],capture_output=True,text=True)
            if p.returncode:raise Blocked("GPG signature invalid/expired/revoked")
            lines=[line.split()[2:] for line in p.stdout.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
            if len(lines)!=1:raise Blocked("VALIDSIG missing/ambiguous")
            fields=lines[0]
            primary=fields[-1].upper() if len(fields)>9 and FPR.fullmatch(fields[-1]) else fields[0].upper()
            if primary not in allowed:raise Blocked("unapproved signer")
            q=subprocess.run(["gpg","--homedir",str(self.home),"--batch","--with-colons","--list-keys",primary],capture_output=True,text=True)
            if q.returncode:raise Blocked("approved key not imported")
            key_ok=uid_ok=False
            for line in q.stdout.splitlines():
                f=line.split(":")
                if len(f)<10:continue
                invalid=any(c in f[1].lower() for c in "reid") or (f[6].isdigit() and int(f[6])<=int(time.time()))
                if f[0]=="pub":key_ok=not invalid
                if f[0]=="uid" and not invalid:
                    uid_ok|=any(address.casefold()==email.casefold() for address in re.findall(r"<([^<>]+)>",f[9]))
            if not (key_ok and uid_ok):raise Blocked("owner public key or matching author UID is invalid")
            return primary

def github(repo,token,path):
    request=urllib.request.Request("https://api.github.com/repos/"+repo+"/"+path,headers={
        "Authorization":"Bearer "+token,
        "Accept":"application/vnd.github+json",
        "X-GitHub-Api-Version":"2022-11-28",
        "User-Agent":"OLA-signature-gate/1"})
    with urllib.request.urlopen(request,timeout=20) as response:return json.load(response)

def main():
    result={"status":"BLOCKED","human_gate":"PENDING","production_go":"NO-GO"}
    verifier=None
    try:
        repo=os.environ.get("GITHUB_REPOSITORY","")
        token=os.environ.get("GITHUB_TOKEN","")
        number=os.environ.get("PR_NUMBER","")
        keys=os.environ.get("OLA_ALLOWED_SIGNER_FPRS","")
        allowed_keys(keys)
        if not token or not number.isdecimal():raise Blocked("token/PR number missing")
        request=urllib.request.Request(KEYS_URL,headers={"User-Agent":"OLA-signature-gate/1"})
        with urllib.request.urlopen(request,timeout=20) as response:public_keys=response.read(1000001)
        if len(public_keys)>1000000:raise Blocked("public key too large")
        verifier=GPG(public_keys)
        result=gate(repo=repo,pr_number=int(number),head=os.environ.get("EXPECTED_HEAD_SHA",""),
                    base=os.environ.get("EXPECTED_BASE_SHA",""),fingerprints=keys,
                    fetch=lambda path:github(repo,token,path),verify=verifier.verify)
        code=0
    except Exception as exc:
        result["reason"]=str(exc) if isinstance(exc,Blocked) else type(exc).__name__
        code=1
    finally:
        if verifier:verifier.close()
    Path("signature-gate-result.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf8")
    print(json.dumps(result,sort_keys=True))
    return code

if __name__=="__main__":sys.exit(main())
