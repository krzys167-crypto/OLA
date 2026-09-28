from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient
from evidence_graph import GraphInvariantError, GraphStore, TenantBoundaryError, create_app

def ts(s=0): return (datetime(2026,1,1,tzinfo=timezone.utc)+timedelta(seconds=s)).isoformat()
def N(t,typ,c,s=0): return dict(tenant_id=t,node_type=typ,canonical_id=c,label=c,source_type="canonical",source_id=c,status="ACTIVE",created_at=ts(s),updated_at=ts(s),metadata={})
def P(i): return dict(source_type="canonical",source_id=i,source_hash="sha256:"+i,source_version="1",captured_at=ts(1),created_at=ts(1))

def chain(s):
    ids={}
    for x in [N("t1","REQUEST","req",1),N("t1","POLICY","pol",2),N("t1","RISK","risk",3),N("t1","ASSERTION","ass",4),N("t1","VERIFIER","ver",5),N("t1","EXECUTION","exe",6),N("t1","EVIDENCE","ev",7)]: ids[x["canonical_id"]]=s.add_node(**x)
    return ids

def test_edge_and_invariants():
    s=GraphStore(); a=s.add_node(**N("t1","REQUEST","a")); b=s.add_node(**N("t1","POLICY","b"))
    e=s.add_edge("t1",a,b,"GOVERNS","OBSERVED",None,**P("e")); assert s.get_edge(e)["relation"]=="GOVERNS"
    with pytest.raises(GraphInvariantError): s.add_edge("t1",a,"missing","GOVERNS","OBSERVED",None,**P("x"))
    c=s.add_node(**N("t2","POLICY","c"))
    with pytest.raises(TenantBoundaryError): s.add_edge("t1",a,c,"GOVERNS","OBSERVED",None,**P("x"))

def test_inferred_needs_confidence_and_verification_path():
    s=GraphStore(); a=s.add_node(**N("t1","EVIDENCE","a")); b=s.add_node(**N("t1","ASSERTION","b")); e=s.add_edge("t1",a,b,"SUPPORTS","INFERRED",.99,**P("i")); assert s.get_edge(e)["status"]=="INFERRED"
    with pytest.raises(GraphInvariantError): s.promote_to_verified(e,"bad","bad")
    v=s.add_node(**N("t1","VERIFIER","v")); ev=s.add_node(**N("t1","EVIDENCE","ev")); s.promote_to_verified(e,v,ev); assert s.get_edge(e)["status"]=="VERIFIED"

def test_rejected_cannot_reactivate_and_follows_orders():
    s=GraphStore(); a=s.add_node(**N("t1","REQUEST","a",2)); b=s.add_node(**N("t1","REQUEST","b",1))
    with pytest.raises(GraphInvariantError): s.add_edge("t1",a,b,"FOLLOWS","OBSERVED",None,**P("f"))
    s2=GraphStore(); x=s2.add_node(**N("t1","EVIDENCE","x")); y=s2.add_node(**N("t1","ASSERTION","y")); e=s2.add_edge("t1",x,y,"SUPPORTS","INFERRED",.2,**P("r")); s2.reject_edge(e)
    with pytest.raises(GraphInvariantError): s2.promote_to_verified(e,x,y)

def test_default_forensic_path_excludes_inferred():
    s=GraphStore(); a=s.add_node(**N("t1","REQUEST","a")); b=s.add_node(**N("t1","ASSERTION","b")); c=s.add_node(**N("t1","EVIDENCE","c"))
    s.add_edge("t1",a,b,"ASSERTS","INFERRED",.9,**P("i")); s.add_edge("t1",b,c,"SUPPORTS","OBSERVED",None,**P("o")); assert s.path(a,c)==[]
    assert [n["canonical_id"] for n in s.path(a,c,allowed_statuses={"INFERRED","OBSERVED"})]==["a","b","c"]

def test_reconstruction_and_lineage():
    canon={"nodes":[N("t1","REQUEST","r",1),N("t1","EXECUTION","x",2),N("t1","EVIDENCE","e",3)],"edges":[{"tenant_id":"t1","from_canonical_id":"r","to_canonical_id":"x","relation":"REQUESTED","status":"OBSERVED","confidence":None,**P("1")},{"tenant_id":"t1","from_canonical_id":"x","to_canonical_id":"e","relation":"PRODUCES","status":"OBSERVED","confidence":None,**P("2")}]}
    a,b=GraphStore(),GraphStore(); a.rebuild_from_canonical(canon); b.rebuild_from_canonical(canon); assert a.normalized_projection()==b.normalized_projection()
    ev=[x["node_id"] for x in a.normalized_projection()["nodes"] if x["canonical_id"]=="e"][0]
    out=a.evidence_lineage(ev); assert [n["canonical_id"] for n in out["nodes"]]==["e","r","x"]

def test_discovery_is_candidate_only_and_api_is_read_only_for_graph_facts():
    s=GraphStore(); n=s.add_node(**N("t1","REQUEST","n")); d=s.create_discovery("t1",[n],"hyp","AFFECTS",.8,"assert","reason"); assert d["status"]=="OPEN" and not hasattr(s,"authorize_execution")
    app=create_app(s,lambda t,r:t=="t1" and r in {"graph_reader","graph_discovery"}); c=TestClient(app)
    assert c.get(f"/api/v1/graph/nodes/{n}",headers={"X-Tenant-ID":"t1"}).status_code==200
    assert c.get(f"/api/v1/graph/nodes/{n}",headers={"X-Tenant-ID":"t1","X-Role":"other"}).status_code==403
    assert c.post("/api/v1/graph/execute",headers={"X-Tenant-ID":"t1"},json={}).status_code==404

def test_full_chain_is_traversable_without_graph_execution_authority():
    s=GraphStore(); ids=chain(s)
    for i,(a,b,r) in enumerate([("req","pol","GOVERNS"),("pol","risk","ASSESSES"),("risk","ass","ASSESSES"),("ass","ver","VERIFIED_BY"),("ver","exe","EXECUTES"),("exe","ev","PRODUCES")]): s.add_edge("t1",ids[a],ids[b],r,"OBSERVED",None,**P(str(i)))
    assert [x["canonical_id"] for x in s.path(ids["req"],ids["ev"],allowed_relations={"GOVERNS","ASSESSES","VERIFIED_BY","EXECUTES","PRODUCES"})]==["req","pol","risk","ass","ver","exe","ev"]

def test_cross_tenant_api_visibility():
    s=GraphStore(); a=s.add_node(**N("t1","REQUEST","a")); b=s.add_node(**N("t2","REQUEST","b"))
    app=create_app(s,lambda t,r:True); c=TestClient(app)
    assert c.get(f"/api/v1/graph/nodes/{a}",headers={"X-Tenant-ID":"t1"}).status_code==200
    assert c.get(f"/api/v1/graph/nodes/{b}",headers={"X-Tenant-ID":"t1"}).status_code==404


def test_label_and_complete_provenance_are_required():
    s=GraphStore()
    n=s.add_node(**N("t1","REQUEST","req"))
    assert s.get_node(n)["label"]=="req"
    m=s.add_node(**N("t1","EVIDENCE","ev"))
    with pytest.raises(GraphInvariantError):
        s.add_edge("t1",n,m,"PRODUCES","OBSERVED",None,source_type="canonical",source_id="x",source_hash="",source_version="1",captured_at=ts(1),created_at=ts(1))


def test_decision_to_evidence_is_representable_without_execution_authority():
    s=GraphStore()
    decision=s.add_node(**N("t1","DECISION","decision"))
    evidence=s.add_node(**N("t1","EVIDENCE","evidence"))
    s.add_edge("t1",decision,evidence,"PRODUCES","OBSERVED",None,**P("decision-evidence"))
    assert [n["canonical_id"] for n in s.path(decision,evidence)]==["decision","evidence"]
    assert not hasattr(s,"authorize_execution")
