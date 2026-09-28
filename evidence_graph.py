from __future__ import annotations
import json, sqlite3, threading, uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable, Iterable
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

NODE_TYPES={"REQUEST","POLICY","RISK","ASSERTION","VERIFIER","EXECUTION","EVIDENCE","DECISION","RESOURCE","ARTIFACT","INCIDENT","AGENT","MISSION"}
RELATIONS={"REQUESTED","GOVERNS","ASSESSES","ASSERTS","VERIFIED_BY","EXECUTES","PRODUCES","SUPPORTS","DERIVED_FROM","DEPENDS_ON","AFFECTS","FOLLOWS"}
STATUSES={"OBSERVED","INFERRED","VERIFIED","REJECTED"}

class GraphInvariantError(ValueError): pass
class TenantBoundaryError(GraphInvariantError): pass
def _now(): return datetime.now(timezone.utc).isoformat()
def _j(v): return json.dumps(v if v is not None else {},sort_keys=True,separators=(",",":"))
def _id(*parts): return str(uuid.uuid5(uuid.NAMESPACE_URL,"ola-evidence-graph:"+"|".join(parts)))

class GraphStore:
    def __init__(self,database=":memory:"):
        self.db=sqlite3.connect(database,check_same_thread=False); self.db.row_factory=sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON"); self._lock=threading.RLock(); self._schema()
    def close(self):
        with self._lock:self.db.close()
    def _schema(self):
        with self._lock:
            self.db.executescript("""CREATE TABLE IF NOT EXISTS nodes(
              node_id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,node_type TEXT NOT NULL,canonical_id TEXT NOT NULL,
              source_type TEXT NOT NULL,source_id TEXT NOT NULL,status TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,
              metadata_json TEXT NOT NULL,UNIQUE(tenant_id,canonical_id));
            CREATE TABLE IF NOT EXISTS edges(
              edge_id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,from_node_id TEXT NOT NULL REFERENCES nodes(node_id),
              to_node_id TEXT NOT NULL REFERENCES nodes(node_id),relation TEXT NOT NULL,status TEXT NOT NULL,confidence REAL,
              source_type TEXT NOT NULL,source_id TEXT NOT NULL,source_hash TEXT NOT NULL,source_version TEXT NOT NULL,
              captured_at TEXT NOT NULL,created_at TEXT NOT NULL,verified_at TEXT,verifier_node_id TEXT REFERENCES nodes(node_id),
              evidence_node_id TEXT REFERENCES nodes(node_id),metadata_json TEXT NOT NULL,
              CHECK(relation IN ('REQUESTED','GOVERNS','ASSESSES','ASSERTS','VERIFIED_BY','EXECUTES','PRODUCES','SUPPORTS','DERIVED_FROM','DEPENDS_ON','AFFECTS','FOLLOWS')),
              CHECK(status IN ('OBSERVED','INFERRED','VERIFIED','REJECTED')),
              CHECK(confidence IS NULL OR (confidence>=0 AND confidence<=1)),
              CHECK(status<>'INFERRED' OR confidence IS NOT NULL),
              CHECK(status<>'VERIFIED' OR (verifier_node_id IS NOT NULL AND evidence_node_id IS NOT NULL)));
            CREATE TABLE IF NOT EXISTS discoveries(
              discovery_id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,input_nodes_json TEXT NOT NULL,hypothesis TEXT NOT NULL,
              proposed_relation TEXT NOT NULL,confidence REAL NOT NULL,proposed_assertion TEXT NOT NULL,reason TEXT NOT NULL,
              created_at TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('OPEN','CONFIRMED','REJECTED','EXPIRED')));
            CREATE TRIGGER IF NOT EXISTS edge_tenant_insert BEFORE INSERT ON edges BEGIN
              SELECT CASE WHEN (SELECT tenant_id FROM nodes WHERE node_id=NEW.from_node_id)<>NEW.tenant_id
                OR (SELECT tenant_id FROM nodes WHERE node_id=NEW.to_node_id)<>NEW.tenant_id
                THEN RAISE(ABORT,'cross-tenant edge') END; END;
            CREATE TRIGGER IF NOT EXISTS reject_reactivation BEFORE UPDATE OF status ON edges
              WHEN OLD.status='REJECTED' AND NEW.status<>'REJECTED' BEGIN
              SELECT RAISE(ABORT,'rejected edge cannot be reactivated'); END;"""); self.db.commit()
    def add_node(self,*,tenant_id,node_type,canonical_id,source_type,source_id,status,created_at,updated_at,metadata=None,node_id=None):
        if node_type not in NODE_TYPES: raise GraphInvariantError(f"invalid node_type: {node_type}")
        if not all((tenant_id,canonical_id,source_type,source_id)): raise GraphInvariantError("required node fields missing")
        node_id=node_id or str(uuid.uuid4())
        with self._lock:
            try:self.db.execute("INSERT INTO nodes VALUES(?,?,?,?,?,?,?,?,?,?)",(node_id,tenant_id,node_type,canonical_id,source_type,source_id,status,created_at,updated_at,_j(metadata))); self.db.commit()
            except sqlite3.IntegrityError as e:raise GraphInvariantError(str(e)) from e
        return node_id
    def _node(self,r):
        d=dict(r); d["metadata"]=json.loads(d.pop("metadata_json")); return d
    def get_node(self,node_id,tenant_id=None):
        with self._lock:r=self.db.execute("SELECT * FROM nodes WHERE node_id=?",(node_id,)).fetchone()
        if r is None:raise GraphInvariantError("node not found")
        if tenant_id is not None and r["tenant_id"]!=tenant_id:raise TenantBoundaryError("tenant boundary violation")
        return self._node(r)
    def add_edge(self,tenant_id,from_node_id,to_node_id,relation,status,confidence,*,source_type,source_id,source_hash,source_version,captured_at,created_at=None,verifier_node_id=None,evidence_node_id=None,metadata=None,edge_id=None):
        if relation not in RELATIONS or status not in STATUSES:raise GraphInvariantError("invalid relation or status")
        if status=="INFERRED" and confidence is None:raise GraphInvariantError("INFERRED requires confidence")
        if confidence is not None and not 0<=confidence<=1:raise GraphInvariantError("confidence must be 0..1")
        a,b=self.get_node(from_node_id),self.get_node(to_node_id)
        if a["tenant_id"]!=tenant_id or b["tenant_id"]!=tenant_id:raise TenantBoundaryError("cross-tenant edge")
        if relation=="FOLLOWS" and a["created_at"]>b["created_at"]:raise GraphInvariantError("FOLLOWS violates recorded order")
        if verifier_node_id:
            v=self.get_node(verifier_node_id)
            if v["tenant_id"]!=tenant_id or v["node_type"]!="VERIFIER":raise GraphInvariantError("invalid verifier reference")
        if evidence_node_id:
            e=self.get_node(evidence_node_id)
            if e["tenant_id"]!=tenant_id or e["node_type"]!="EVIDENCE":raise GraphInvariantError("invalid evidence reference")
        if status=="VERIFIED" and (not verifier_node_id or not evidence_node_id):raise GraphInvariantError("VERIFIED requires verifier and evidence")
        edge_id=edge_id or str(uuid.uuid4())
        with self._lock:
            try:self.db.execute("INSERT INTO edges VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(edge_id,tenant_id,from_node_id,to_node_id,relation,status,confidence,source_type,source_id,source_hash,source_version,captured_at,created_at or _now(),_now() if status=="VERIFIED" else None,verifier_node_id,evidence_node_id,_j(metadata))); self.db.commit()
            except sqlite3.IntegrityError as e:
                if "cross-tenant" in str(e):raise TenantBoundaryError(str(e)) from e
                raise GraphInvariantError(str(e)) from e
        return edge_id
    def get_edge(self,edge_id):
        with self._lock:r=self.db.execute("SELECT * FROM edges WHERE edge_id=?",(edge_id,)).fetchone()
        if r is None:raise GraphInvariantError("edge not found")
        d=dict(r);d["metadata"]=json.loads(d.pop("metadata_json"));return d
    def reject_edge(self,edge_id):
        with self._lock:
            try:self.db.execute("UPDATE edges SET status='REJECTED' WHERE edge_id=?",(edge_id,));self.db.commit()
            except sqlite3.IntegrityError as e:raise GraphInvariantError(str(e)) from e
    def promote_to_verified(self,edge_id,verifier_node_id,evidence_node_id):
        e=self.get_edge(edge_id)
        if e["status"]=="REJECTED":raise GraphInvariantError("rejected edge cannot be reactivated")
        v=self.get_node(verifier_node_id,tenant_id=e["tenant_id"]); ev=self.get_node(evidence_node_id,tenant_id=e["tenant_id"])
        if v["node_type"]!="VERIFIER" or ev["node_type"]!="EVIDENCE":raise GraphInvariantError("invalid verification references")
        with self._lock:
            self.db.execute("UPDATE edges SET status='VERIFIED',verified_at=?,verifier_node_id=?,evidence_node_id=? WHERE edge_id=?",( _now(),verifier_node_id,evidence_node_id,edge_id));self.db.commit()
    def neighbors(self,node_id,*,direction="out",relation=None,statuses=None,node_type=None,tenant_id=None):
        self.get_node(node_id,tenant_id=tenant_id); statuses=statuses or {"OBSERVED","VERIFIED"}
        if statuses-STATUSES:raise GraphInvariantError("invalid statuses")
        if direction=="out":where="e.from_node_id=?";join="n.node_id=e.to_node_id"
        elif direction=="in":where="e.to_node_id=?";join="n.node_id=e.from_node_id"
        elif direction=="both":
            rows=self.neighbors(node_id,direction="out",relation=relation,statuses=statuses,node_type=node_type,tenant_id=tenant_id);seen={x["node_id"] for x in rows}
            for x in self.neighbors(node_id,direction="in",relation=relation,statuses=statuses,node_type=node_type,tenant_id=tenant_id):
                if x["node_id"] not in seen:rows.append(x);seen.add(x["node_id"])
            return rows
        else:raise GraphInvariantError("direction must be out, in or both")
        params=[node_id,*sorted(statuses)]; sql=f"SELECT n.*,e.edge_id,e.relation,e.status AS edge_status,e.confidence,e.source_type AS edge_source_type,e.source_id AS edge_source_id FROM edges e JOIN nodes n ON {join} WHERE {where} AND e.status IN ({','.join('?' for _ in statuses)})"
        if relation:sql+=" AND e.relation=?";params.append(relation)
        if node_type:sql+=" AND n.node_type=?";params.append(node_type)
        with self._lock:rows=self.db.execute(sql,params).fetchall()
        out=[]
        for r in rows:
            d=self._node(r);d["edge"]={"edge_id":r["edge_id"],"relation":r["relation"],"status":r["edge_status"],"confidence":r["confidence"],"source_type":r["edge_source_type"],"source_id":r["edge_source_id"]};out.append(d)
        return out
    def path(self,start_node_id,target_node_id,*,max_depth=8,allowed_relations=None,allowed_statuses=None,tenant_id=None):
        start=self.get_node(start_node_id,tenant_id=tenant_id);self.get_node(target_node_id,tenant_id=start["tenant_id"]);statuses=allowed_statuses or {"OBSERVED","VERIFIED"};q=deque([(start_node_id,[start])]);seen={start_node_id}
        while q:
            nid,p=q.popleft()
            if nid==target_node_id:return p
            if len(p)-1>=max_depth:continue
            for n in self.neighbors(nid,statuses=statuses,tenant_id=start["tenant_id"]):
                if allowed_relations and n["edge"]["relation"] not in allowed_relations:continue
                if n["node_id"] not in seen:seen.add(n["node_id"]);q.append((n["node_id"],p+[n]))
        return []
    def subgraph(self,node_id,*,max_depth=1,allowed_statuses=None,tenant_id=None):
        root=self.get_node(node_id,tenant_id=tenant_id);statuses=allowed_statuses or {"OBSERVED","VERIFIED"};nodes={root["node_id"]:root};edges={};q=deque([(node_id,0)]);seen={node_id}
        while q:
            nid,d=q.popleft()
            if d>=max_depth:continue
            for direction in ("out","in"):
                for n in self.neighbors(nid,direction=direction,statuses=statuses,tenant_id=root["tenant_id"]):
                    nodes[n["node_id"]]=n;edges[n["edge"]["edge_id"]]=n["edge"]
                    if n["node_id"] not in seen:seen.add(n["node_id"]);q.append((n["node_id"],d+1))
        return {"nodes":sorted(nodes.values(),key=lambda x:x["canonical_id"]),"edges":sorted(edges.values(),key=lambda x:x["edge_id"])}
    def evidence_lineage(self,evidence_id,*,max_depth=32,tenant_id=None):
        root=self.get_node(evidence_id,tenant_id=tenant_id);nodes={root["node_id"]:root};edges={};q=deque([(evidence_id,0)]);seen={evidence_id}
        while q:
            nid,d=q.popleft()
            if d>=max_depth:continue
            for direction in ("out","in"):
                for n in self.neighbors(nid,direction=direction,statuses={"OBSERVED","VERIFIED"},tenant_id=root["tenant_id"]):
                    nodes[n["node_id"]]=n;edges[n["edge"]["edge_id"]]=n["edge"]
                    if n["node_id"] not in seen:seen.add(n["node_id"]);q.append((n["node_id"],d+1))
        return {"nodes":sorted(nodes.values(),key=lambda x:x["canonical_id"]),"edges":sorted(edges.values(),key=lambda x:x["edge_id"])}
    def create_discovery(self,tenant_id,input_nodes:Iterable[str],hypothesis,proposed_relation,confidence,proposed_assertion,reason):
        if proposed_relation not in RELATIONS or not 0<=confidence<=1:raise GraphInvariantError("invalid discovery relation/confidence")
        ids=list(input_nodes)
        for nid in ids:self.get_node(nid,tenant_id=tenant_id)
        d={"discovery_id":str(uuid.uuid4()),"tenant_id":tenant_id,"input_nodes":ids,"hypothesis":hypothesis,"proposed_relation":proposed_relation,"confidence":confidence,"proposed_assertion":proposed_assertion,"reason":reason,"created_at":_now(),"status":"OPEN"}
        with self._lock:self.db.execute("INSERT INTO discoveries VALUES(?,?,?,?,?,?,?,?,?,?)",(d["discovery_id"],tenant_id,_j(ids),hypothesis,proposed_relation,confidence,proposed_assertion,reason,d["created_at"],"OPEN"));self.db.commit()
        return d
    def rebuild_from_canonical(self,canonical):
        with self._lock:self.db.execute("DELETE FROM edges");self.db.execute("DELETE FROM discoveries");self.db.execute("DELETE FROM nodes");self.db.commit()
        mapping={}
        for n in canonical.get("nodes",[]):
            nid=_id(n["tenant_id"],n["canonical_id"]);mapping[(n["tenant_id"],n["canonical_id"])]=nid;self.add_node(node_id=nid,**n)
        for e in canonical.get("edges",[]):
            fid=mapping[(e["tenant_id"],e["from_canonical_id"])];tid=mapping[(e["tenant_id"],e["to_canonical_id"])];eid=_id(e["tenant_id"],e["from_canonical_id"],e["to_canonical_id"],e["relation"],e["source_id"])
            self.add_edge(e["tenant_id"],fid,tid,e["relation"],e["status"],e.get("confidence"),source_type=e["source_type"],source_id=e["source_id"],source_hash=e["source_hash"],source_version=e["source_version"],captured_at=e["captured_at"],created_at=e["created_at"],metadata=e.get("metadata"),edge_id=eid)
    def normalized_projection(self):
        with self._lock:nr=self.db.execute("SELECT node_id FROM nodes ORDER BY tenant_id,canonical_id").fetchall();er=self.db.execute("SELECT edge_id FROM edges ORDER BY tenant_id,edge_id").fetchall()
        return {"nodes":[self.get_node(r["node_id"]) for r in nr],"edges":[self.get_edge(r["edge_id"]) for r in er]}

class DiscoveryRequest(BaseModel):
    input_nodes:list[str]=Field(min_length=1)
    hypothesis:str
    proposed_relation:str
    confidence:float=Field(ge=0,le=1)
    proposed_assertion:str
    reason:str

def create_app(store:GraphStore,authorize:Callable[[str,str],bool])->FastAPI:
    app=FastAPI(title="OLA Evidence Graph",version="0.1")
    def guard(t,r):
        if not authorize(t,r):raise HTTPException(403,"forbidden")
    def hdr(t,r):guard(t,r)
    @app.get("/api/v1/graph/nodes/{node_id}")
    def get_node(node_id:str,x_tenant_id:str=Header(...),x_role:str=Header("graph_reader")):
        hdr(x_tenant_id,x_role)
        try:return store.get_node(node_id,tenant_id=x_tenant_id)
        except (GraphInvariantError,TenantBoundaryError):raise HTTPException(404,"not found")
    @app.get("/api/v1/graph/nodes/{node_id}/neighbors")
    def get_neighbors(node_id:str,direction="out",relation:str|None=None,status:list[str]|None=None,node_type:str|None=None,x_tenant_id:str=Header(...),x_role:str=Header("graph_reader")):
        hdr(x_tenant_id,x_role)
        try:return {"nodes":store.neighbors(node_id,direction=direction,relation=relation,statuses=set(status) if status else None,node_type=node_type,tenant_id=x_tenant_id)}
        except TenantBoundaryError:raise HTTPException(404,"not found")
    @app.get("/api/v1/graph/path")
    def get_path(from_node_id:str,to_node_id:str,max_depth:int=8,status:list[str]|None=None,relation:list[str]|None=None,x_tenant_id:str=Header(...),x_role:str=Header("graph_reader")):
        hdr(x_tenant_id,x_role);return {"nodes":store.path(from_node_id,to_node_id,max_depth=max_depth,allowed_statuses=set(status) if status else None,allowed_relations=set(relation) if relation else None,tenant_id=x_tenant_id)}
    @app.get("/api/v1/graph/subgraph/{node_id}")
    def get_subgraph(node_id:str,max_depth:int=1,status:list[str]|None=None,x_tenant_id:str=Header(...),x_role:str=Header("graph_reader")):
        hdr(x_tenant_id,x_role);return store.subgraph(node_id,max_depth=max_depth,allowed_statuses=set(status) if status else None,tenant_id=x_tenant_id)
    @app.get("/api/v1/graph/evidence/{evidence_id}/lineage")
    def get_lineage(evidence_id:str,max_depth:int=32,x_tenant_id:str=Header(...),x_role:str=Header("graph_reader")):
        hdr(x_tenant_id,x_role);return store.evidence_lineage(evidence_id,max_depth=max_depth,tenant_id=x_tenant_id)
    @app.post("/api/v1/graph/discovery")
    def discovery(body:DiscoveryRequest,x_tenant_id:str=Header(...),x_role:str=Header("graph_discovery")):
        hdr(x_tenant_id,x_role);return store.create_discovery(x_tenant_id,body.input_nodes,body.hypothesis,body.proposed_relation,body.confidence,body.proposed_assertion,body.reason)
    return app
