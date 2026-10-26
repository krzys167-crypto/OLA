import json

from app.hashchain import canonical_json, compute_record_hash, compute_record_hash_v2, sealed_payload_json, EVIDENCE_META_KEY
from app.igor_workflow import verify_dag_records
from app.workflow_engine import WorkflowEngine, validate_plan


def proof():
    events = []
    nodes = validate_plan({"nodes": [
        {"id": "alpha", "tool": "llm_agent", "task": "one", "needs": []},
        {"id": "beta", "tool": "llm_agent", "task": "two", "needs": []},
        {"id": "join", "tool": "safe_expression", "task": "2+2", "needs": ["alpha", "beta"]},
    ]}, allowed_tools={"llm_agent", "safe_expression"})
    def execute(node, deps):
        if node.tool == "llm_agent":
            return {"output": node.id, "provider": "ollama", "model": "qwen", "response_id": node.id}
        return "4"
    WorkflowEngine(max_workers=2).run(nodes, execute,
        lambda event: events.append({**event, "requester_id": "person1",
                                     "planner": {"response_id": "p1"}, "commit": "expected"}),
        run_id="run1")
    return rehash(events)


def rehash(events):
    records = []
    prev = "0" * 64
    for seq, event in enumerate(events):
        event = dict(event)
        event.pop(EVIDENCE_META_KEY, None)
        producer = "tenant_api" if event["event"] == "customer.proof" else "ola_runtime"
        raw = sealed_payload_json(event["event"], event, producer=producer)
        current = compute_record_hash_v2("tenant", seq, prev, event["event"], producer, raw)
        records.append({"tenant_id": "tenant", "seq": seq, "prev_hash": prev,
                        "record_hash": current, "record_type": event["event"], "payload_json": raw})
        prev = current
    return records


def check(records, **kwargs):
    return verify_dag_records(records, tenant_id="tenant", run_id="run1",
                              expected_commit="expected", **kwargs)


def test_standalone_verifier_recomputes_full_trace():
    report = check(proof())
    assert report["status"] == "VERIFIED", report
    assert report["verified_nodes"] == 3
    assert report["report_digest"]


def test_tamper_breaks_chain_even_when_execution_claims_success():
    evidence = proof()
    evidence[2]["payload_json"] = "{}"
    assert check(evidence)["status"] == "BLOCK"


def test_missing_terminal_is_blocked():
    evidence = proof()[:-1]
    assert check(evidence)["status"] == "BLOCK"


def test_fake_timing_rejected_even_after_rehash():
    events = [json.loads(row["payload_json"]) for row in proof()]
    for event in events:
        if event["event"] == "task.completed":
            event["worker_finished_ns"] = event["worker_started_ns"]
    assert check(rehash(events))["status"] == "BLOCK"


def test_wrong_commit_and_missing_run_block():
    assert verify_dag_records(proof(), tenant_id="tenant", run_id="run1",
                              expected_commit="wrong")["status"] == "BLOCK"
    assert verify_dag_records(proof(), tenant_id="tenant", run_id="other")["status"] == "UNKNOWN"


def test_missing_node_or_duplicate_response_rejected():
    events = [json.loads(row["payload_json"]) for row in proof()]
    values = [e for e in events if e["event"] == "task.completed" and isinstance(e["output"], dict)]
    values[1]["output"]["response_id"] = values[0]["output"]["response_id"]
    from app.workflow_engine import _digest
    values[1]["output_digest"] = _digest(values[1]["output"])
    assert check(rehash(events))["status"] == "BLOCK"

def test_customer_evidence_with_matching_run_id_does_not_poison_dag_verification():
    # The full tenant chain includes customer evidence, but only trusted
    # workflow/task record types belong to the NINA execution trace.
    events = [json.loads(row["payload_json"]) for row in proof()]
    events.insert(-1, {"event": "customer.proof", "run_id": "run1",
                       "note": "unrelated user evidence"})
    report = check(rehash(events))
    assert report["status"] == "VERIFIED", report
    assert report["evidence_count"] == len(events) - 1


def test_unexpected_internal_workflow_event_remains_blocked():
    events = [json.loads(row["payload_json"]) for row in proof()]
    events.insert(-1, {"event": "workflow.unexpected", "run_id": "run1",
                       "requester_id": "person1", "planner": {"response_id": "p1"},
                       "commit": "expected"})
    assert check(rehash(events))["status"] == "BLOCK"


def test_v1_forged_customer_trace_never_promotes_to_trusted_workflow():
    legacy = []
    prev = "0" * 64
    for seq, row in enumerate(proof()):
        payload = json.loads(row["payload_json"])
        payload.pop(EVIDENCE_META_KEY)
        raw = canonical_json(payload)
        digest = compute_record_hash("tenant", seq, prev, raw)
        legacy.append({**row, "seq": seq, "prev_hash": prev,
                       "record_hash": digest, "payload_json": raw})
        prev = digest
    assert check(legacy)["status"] == "BLOCK"


def test_v2_type_tamper_is_detected_even_when_hash_is_unchanged():
    from app.hashchain import verify_chain
    forged = proof()
    forged[0]["record_type"] = "customer.proof"
    assert verify_chain(forged) == (False, "record type or producer binding mismatch")
    assert check(forged)["status"] == "BLOCK"
