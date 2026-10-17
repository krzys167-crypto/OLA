"""Independent DAG verifier: no calls to NINA planner, scheduler, or executor.

Certifies integrity/consistency of *captured* local events, not an external
attestation that requests were truly handled by the named LLM provider.
"""
import hashlib
import json


def _hash(value):
    material = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(material.encode()).hexdigest()


def _result(status, reason, **kw):
    return {"status": status, "reason": reason, **kw}


def verify_dag_records(records, *, tenant_id, run_id, expected_commit=None,
                       require_overlap=False, expected_provider=None):
    if not records:
        return _result("UNKNOWN", "no tenant evidence")
    try:
        prev = "0" * 64
        for seq, row in enumerate(records):
            if row["tenant_id"] != tenant_id or row["seq"] != seq or row["prev_hash"] != prev:
                return _result("BLOCK", "tenant chain sequence or predecessor mismatch")
            raw = row["payload_json"]
            digest = hashlib.sha256(f"{tenant_id}|{seq}|{prev}|{raw}".encode()).hexdigest()
            if row["record_hash"] != digest:
                return _result("BLOCK", "tenant chain hash mismatch")
            prev = digest
        relevant = []
        for row in records:
            payload = json.loads(row["payload_json"])
            if payload.get("run_id") == run_id and row["record_type"] != "human.workflow_approval":
                if payload.get("event") != row["record_type"]:
                    return _result("BLOCK", "event type mismatch")
                relevant.append(payload)
        if not relevant:
            return _result("UNKNOWN", "run evidence missing")
        plan_event = relevant[0]
        if plan_event.get("event") != "workflow.planned":
            return _result("BLOCK", "missing plan")
        plan = plan_event.get("nodes")
        if not isinstance(plan, list) or not 1 <= len(plan) <= 16 or _hash(plan) != plan_event.get("plan_digest"):
            return _result("BLOCK", "invalid plan digest or size")
        nodes = {}
        for node in plan:
            if not isinstance(node, dict) or set(node) != {"id", "tool", "task", "needs"}:
                return _result("BLOCK", "malformed DAG node")
            nid, needs = node["id"], node["needs"]
            if not isinstance(nid, str) or nid in nodes or not isinstance(needs, list):
                return _result("BLOCK", "duplicate node or invalid dependencies")
            if not isinstance(node["tool"], str) or not isinstance(node["task"], str):
                return _result("BLOCK", "malformed DAG tool/task")
            if any(not isinstance(dep, str) for dep in needs) or len(set(needs)) != len(needs):
                return _result("BLOCK", "invalid dependency list")
            nodes[nid] = node
        if any(dep not in nodes or dep == nid for nid, node in nodes.items() for dep in node["needs"]):
            return _result("BLOCK", "unresolvable dependencies")
        starts, finishes, response_ids = {}, {}, set()
        terminal = None
        for index, event in enumerate(relevant):
            if event.get("requester_id") != plan_event.get("requester_id"):
                return _result("BLOCK", "requester mismatch")
            if event.get("planner") != plan_event.get("planner"):
                return _result("BLOCK", "planner provenance mismatch")
            if event.get("commit") != plan_event.get("commit"):
                return _result("BLOCK", "run commit mismatch")
            if expected_commit and event.get("commit") != expected_commit:
                return _result("BLOCK", "expected commit mismatch")
            if index == 0:
                continue
            if terminal is not None:
                return _result("BLOCK", "event after terminal state")
            kind, nid = event.get("event"), event.get("node_id")
            if kind == "task.started":
                if nid not in nodes or nid in starts:
                    return _result("BLOCK", "unknown or duplicate task start")
                if any(dep not in finishes for dep in nodes[nid]["needs"]):
                    return _result("BLOCK", "dependency not completed before start")
                deps = {dep: finishes[dep]["output"] for dep in nodes[nid]["needs"]}
                if event.get("input_digest") != _hash({"task": nodes[nid]["task"], "deps": deps}):
                    return _result("BLOCK", "input digest mismatch")
                starts[nid] = event
            elif kind == "task.completed":
                if nid not in starts or nid in finishes:
                    return _result("BLOCK", "completion without unique start")
                if _hash(event.get("output")) != event.get("output_digest"):
                    return _result("BLOCK", "output digest mismatch")
                begun, ended = event.get("worker_started_ns"), event.get("worker_finished_ns")
                if (not isinstance(begun, int) or isinstance(begun, bool)
                        or not isinstance(ended, int) or isinstance(ended, bool)
                        or begun >= ended):
                    return _result("BLOCK", "missing or invalid measured worker interval")
                if nodes[nid]["tool"] == "llm_agent":
                    output = event.get("output")
                    if (not isinstance(output, dict) or not all(
                            isinstance(output.get(key), str) and bool(output[key])
                            for key in ("output", "provider", "model", "response_id"))):
                        return _result("BLOCK", "LLM provenance missing")
                    if expected_provider and output["provider"] != expected_provider:
                        return _result("BLOCK", "LLM provider mismatch")
                    if output["response_id"] in response_ids:
                        return _result("BLOCK", "duplicate LLM response ID")
                    response_ids.add(output["response_id"])
                finishes[nid] = event
            elif kind in ("workflow.completed", "workflow.failed"):
                if index != len(relevant) - 1:
                    return _result("BLOCK", "early terminal state")
                terminal = event
            else:
                return _result("BLOCK", "unexpected event")
        if terminal is None or terminal["event"] != "workflow.completed":
            return _result("BLOCK", "workflow did not complete")
        if (set(starts) != set(nodes) or set(finishes) != set(nodes)
                or terminal.get("status") != "COMPLETED_UNVERIFIED"
                or terminal.get("completed") != sorted(nodes)
                or terminal.get("failed") != {} or terminal.get("skipped") != []):
            return _result("BLOCK", "terminal summary mismatch or incomplete nodes")
        overlap = 0
        llm_ids = [nid for nid, node in nodes.items() if node["tool"] == "llm_agent"]
        for index, a in enumerate(llm_ids):
            for b in llm_ids[index+1:]:
                if a in nodes[b]["needs"] or b in nodes[a]["needs"]:
                    continue
                left, right = finishes[a], finishes[b]
                overlap = max(overlap, min(left["worker_finished_ns"], right["worker_finished_ns"])
                              - max(left["worker_started_ns"], right["worker_started_ns"]))
        if require_overlap and overlap <= 0:
            return _result("BLOCK", "real LLM execution intervals did not overlap", overlap_ns=overlap)
        report_digest = _hash({"tenant_id": tenant_id, "run_id": run_id, "chain_tip": prev,
                               "plan_digest": plan_event["plan_digest"], "completed": sorted(finishes),
                               "overlap_ns": overlap})
        return _result("VERIFIED", "captured DAG events and full tenant chain consistent",
                       verified_nodes=len(finishes), evidence_count=len(relevant),
                       chain_tip=prev, plan_digest=plan_event["plan_digest"],
                       overlap_ns=overlap, report_digest=report_digest,
                       trust_scope="LOCAL_HASH_CHAIN_AND_CAPTURED_RUNTIME_EVENTS")
    except (TypeError, KeyError, ValueError, IndexError, AttributeError, OverflowError):
        return _result("BLOCK", "malformed evidence")
