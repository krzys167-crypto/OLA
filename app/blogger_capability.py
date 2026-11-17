"""Dedicated OLA dispatcher for the read-only Blogger metadata capability."""
from __future__ import annotations
import hashlib, json, re, uuid
from typing import Any
from .blogger_adapter import BloggerAdapterError, get_blog_metadata
from .hashchain import verify_chain
from .nina import NinaOrchestrator, NinaTask
from .pipeline_bridge import append_evidence, load_chain

TOOL_NAME = "blogger.read_metadata"
START, RESULT, END = "blogger.execution.started", "blogger.metadata.result", "blogger.execution.ended"
BLOG_ID_RE = re.compile(r"^[0-9]{1,32}$")

def _digest_result(result: dict[str, Any]) -> str:
    body = {k:v for k,v in result.items() if k != "result_sha256"}
    return hashlib.sha256(json.dumps(body,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()

def verify_blogger_evidence(records: list[dict], run_id: str, blog_id: str) -> dict:
    ok, reason = verify_chain(records)
    if not ok: return {"status":"BLOCK","reason":reason,"checks":{"chain":False}}
    scoped=[]
    for row in records:
        try: payload=json.loads(row["payload_json"])
        except (KeyError,TypeError,ValueError): continue
        if isinstance(payload,dict) and payload.get("run_id")==run_id:
            scoped.append((row.get("record_type"),payload))
    if [x[0] for x in scoped] != [START,RESULT,END]:
        return {"status":"UNKNOWN","reason":"missing, duplicate, or reordered Blogger events",
                "checks":{"chain":True,"event_order":False}}
    start,result_event,end=[x[1] for x in scoped]
    result=result_event.get("result")
    checks={"chain":True,"event_order":True,
        "tenant_binding":bool(records) and all(r.get("tenant_id")==records[0].get("tenant_id") for r in records),
        "blog_id_binding":all(p.get("blog_id")==blog_id for p in (start,result_event,end)),
        "run_binding":all(p.get("run_id")==run_id for p in (start,result_event,end)),
        "terminal_state":end.get("status")=="REVIEW_REQUIRED",
        "operation_binding":result_event.get("operation")=="blogs.get",
        "result_digest":isinstance(result,dict) and result.get("result_sha256")==_digest_result(result)}
    if not all(checks.values()):
        return {"status":"BLOCK","reason":"Blogger evidence semantic verification failed","checks":checks}
    return {"status":"VERIFIED","reason":"local evidence checks passed; Google authorship is not proven",
            "checks":checks,"human_gate":"REVIEW_REQUIRED"}

def run_blogger_metadata(tenant_id: str, blog_id: str, *, adapter=get_blog_metadata) -> dict:
    if not isinstance(blog_id,str) or not BLOG_ID_RE.fullmatch(blog_id):
        return {"status":"BLOCK","reason":"INVALID_BLOG_ID","human_gate":"BLOCK"}
    task=NinaTask.create(tenant_id,f"Read Blogger metadata for blog {blog_id}",[TOOL_NAME])
    plan=NinaOrchestrator(registered_tools=("safe_expression","local_mcp_tool_registry.sha256",TOOL_NAME)).plan(task)
    if plan.status!="ALLOW": return {"status":"BLOCK","reason":plan.reason,"human_gate":"BLOCK"}
    run_id=str(uuid.uuid4())
    append_evidence(tenant_id,START,{"run_id":run_id,"blog_id":blog_id,"tool":TOOL_NAME})
    try:
        data=adapter(blog_id)
        if not isinstance(data,dict) or data.get("success") is not True or data.get("blog_id")!=blog_id or data.get("operation")!="blogs.get":
            raise BloggerAdapterError("ADAPTER_RESULT_INVALID")
        append_evidence(tenant_id,RESULT,{"run_id":run_id,"blog_id":blog_id,"operation":"blogs.get","result":data})
        append_evidence(tenant_id,END,{"run_id":run_id,"blog_id":blog_id,"status":"REVIEW_REQUIRED"})
        verification=verify_blogger_evidence(load_chain(tenant_id),run_id,blog_id)
        return {"status":"REVIEW_REQUIRED" if verification["status"]=="VERIFIED" else verification["status"],
                "run_id":run_id,"blog_id":blog_id,"result":data,"verification":verification,
                "human_gate":"REVIEW_REQUIRED","execution":"NOT_PERFORMED"}
    except BloggerAdapterError as exc:
        append_evidence(tenant_id,END,{"run_id":run_id,"blog_id":blog_id,"status":"BLOCK","error":exc.code})
        return {"status":"BLOCK","run_id":run_id,"blog_id":blog_id,"reason":exc.code,
                "human_gate":"BLOCK","execution":"NOT_PERFORMED"}
