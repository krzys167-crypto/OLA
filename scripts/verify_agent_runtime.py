import argparse
import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ROLES = ["codeact", "react", "agentic_rag", "mcp_tool_use", "self_reflection", "multi_agent"]
EXPECTED_CAPABILITIES = {
    "codeact": "executed_safe_expression",
    "react": "reason_act_observe",
    "agentic_rag": "retrieved_prior_evidence",
    "mcp_tool_use": "invoked_tool",
    "self_reflection": "checked_previous_output",
    "multi_agent": "aggregated_agent_outputs",
}
EXPECTED_INVOCATION = {
    "provider": "local",
    "model": "deterministic-runtime-v1",
    "invocation_type": "local_deterministic_model",
}
from app.igor_evidence_verifier import (
    evidence_version,
    trusted_record,
    verify_chain as verify_evidence_chain,
)


def verify_hash_chain(rows):
    records = [{
        "tenant_id": row[0],
        "seq": row[1],
        "record_type": row[2],
        "payload_json": row[3],
        "prev_hash": row[4],
        "record_hash": row[5],
    } for row in rows]
    return verify_evidence_chain(records)


def fail(reason, **extra):
    return {"status": "BLOCK", "reason": reason, **extra}


def verify(tenant_id, run_id, expected_commit, expected_task=None, expected_result=None, db_path=None, expected_provider="local", expected_model="deterministic-runtime-v1", expected_invocation_type="local_deterministic_model"):
    db_path = db_path or os.getenv("OLA_EG_DB_PATH", "/data/ola.db")
    expected_invocation = {
        "provider": expected_provider,
        "model": expected_model,
        "invocation_type": expected_invocation_type,
    }

    if (not isinstance(expected_commit, str) or len(expected_commit) != 40
            or any(character not in "0123456789abcdef" for character in expected_commit)):
        return fail("expected commit must be a full 40-character lowercase SHA-1")
    db = sqlite3.connect(db_path)
    rows = db.execute(
        "SELECT tenant_id, seq, record_type, payload_json, prev_hash, record_hash "
        "FROM evidence_records WHERE tenant_id=? ORDER BY seq",
        (tenant_id,),
    ).fetchall()
    db.close()

    # Integrity must be established over the complete evidence store before
    # filtering by run_id; otherwise tampering can hide the corrupted record
    # from the hash-chain check.
    chain_ok, chain_reason = verify_hash_chain(rows)
    if not chain_ok:
        return fail(chain_reason)

    run_rows = []
    for row in rows:
        try:
            payload = json.loads(row[3])
        except json.JSONDecodeError:
            continue
        if payload.get("run_id") == run_id and row[2].startswith("agent."):
            run_rows.append(row)

    expected_types = [f"agent.{role}" for role in ROLES]
    if [row[2] for row in run_rows] != expected_types:
        return fail("six-agent evidence missing or out of order")

    capabilities = {}
    instance_ids = set()
    context_digests = set()
    invocations = {}
    payloads = []
    for row in run_rows:
        payload = json.loads(row[3])
        payloads.append(payload)
        record = {
            "tenant_id": row[0], "seq": row[1], "record_type": row[2],
            "payload_json": row[3], "prev_hash": row[4], "record_hash": row[5],
        }
        if evidence_version(record) not in (2, 3, 4) or not trusted_record(record):
            return fail("legacy or unbound agent evidence")
        agent = payload.get("agent")
        required = {
            "capability", "tool", "tool_output", "result", "status",
            "agent_instance_id", "execution_boundary", "context_digest",
            "invocation_type", "model", "provider", "task_digest",
            "input_digest", "model_output_digest", "model_output_role",
            "action_result_source",
        }
        if not required.issubset(payload):
            return fail(f"execution evidence incomplete for {agent}")
        if payload.get("commit") != expected_commit:
            return fail(f"runtime commit provenance mismatch for {agent}")
        if payload.get("status") != "RECORDED":
            return fail(f"agent evidence was not producer-recorded for {agent}")
        if (payload.get("model_output_role") != "advisory_only"
                or payload.get("action_result_source") != "registered_capability"):
            return fail(f"model/action provenance is ambiguous for {agent}")
        for digest_key in ("context_digest", "task_digest", "input_digest", "model_output_digest"):
            digest_value = payload.get(digest_key)
            if (not isinstance(digest_value, str) or len(digest_value) != 64
                    or any(character not in "0123456789abcdef" for character in digest_value)):
                return fail(f"invalid {digest_key} for {agent}")
        if agent == "self_reflection" and payload.get("tool_output") != "PASS":
            return fail("self-reflection did not pass")
        if payload.get("capability") != EXPECTED_CAPABILITIES.get(agent):
            return fail(f"unexpected capability for {agent}")
        if payload.get("execution_boundary") != "in_process":
            return fail(f"unexpected agent execution boundary for {agent}")
        invocation = {
            "provider": payload["provider"],
            "model": payload["model"],
            "invocation_type": payload["invocation_type"],
        }
        if expected_invocation_type == "real_llm" and not payload.get("response_id"):
            return fail(f"missing real LLM response id for {agent}")
        if invocation != expected_invocation:
            return fail(f"unexpected invocation metadata for {agent}")
        instance_ids.add(payload["agent_instance_id"])
        context_digests.add(payload["context_digest"])
        invocations[agent] = invocation
        capabilities[agent] = payload["capability"]

    if len(instance_ids) != len(ROLES):
        return fail("agent instance identities are not unique")
    if len(context_digests) != len(ROLES):
        return fail("agent contexts are not unique")

    if expected_task is not None:
        expected_task_digest = hashlib.sha256(expected_task.encode("utf-8")).hexdigest()
        for payload in payloads:
            # New evidence stores a commitment, not plaintext task content.
            if payload.get("task_digest") is not None:
                if payload.get("task_digest") != expected_task_digest:
                    return fail("task digest mismatch in execution evidence")
            elif payload.get("task") != expected_task:
                return fail("task mismatch in legacy execution evidence")

    final_result = payloads[-1].get("final_result")
    if expected_result is not None and final_result != expected_result:
        return fail(f"final result mismatch: expected {expected_result!r}, got {final_result!r}")

    codeact_result = payloads[0].get("tool_output")
    if expected_result is not None and codeact_result != expected_result:
        return fail(f"codeact result mismatch: expected {expected_result!r}, got {codeact_result!r}")
    if final_result != codeact_result:
        return fail("final result does not match CodeAct execution result")

    return {
        "status": "VERIFIED",
        "run_id": run_id,
        "commit": expected_commit,
        "task": expected_task,
        "final_result": final_result,
        "agents": ROLES,
        "capabilities": capabilities,
        "agent_instance_count": len(instance_ids),
        "unique_context_count": len(context_digests),
        "execution_boundary": "in_process",
        "verifier_boundary": "separate_process",
        "invocations": invocations,
        "evidence_count": len(run_rows),
        "verification_scope": [
            "runtime_source_commit_binding",
            "agent_role_order_and_record_structure",
            "capability_labels_and_invocation_metadata",
            "unique_agent_instance_and_context_labels",
            "tenant_evidence_hash_chain_integrity",
            "external_expected_result_match" if expected_result is not None else "no_external_expected_result_supplied",
        ],
        "not_established": [
            "isolated_or_independent_agent_processes",
            "semantic_correctness_of_registered_capabilities",
            "model_generated_action_results",
        ],
        "reason": "separate-process verifier checked source binding, record structure, invocation metadata and evidence integrity; it does not isolate agent execution or prove capability semantics",
    }


def _emit_runtime_diagnostic(result):
    message = json.dumps(result, sort_keys=True)
    print(message)
    try:
        with open("/proc/1/fd/1", "w", encoding="utf-8") as stream:
            stream.write(f"AGENT_VERIFIER_RESULT={message}\n")
            stream.flush()
    except OSError:
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--expected-commit", default=os.getenv("GITHUB_SHA", "UNKNOWN"))
    parser.add_argument("--expected-task")
    parser.add_argument("--expected-result")
    parser.add_argument("--db-path", default=os.getenv("OLA_EG_DB_PATH", "/data/ola.db"))
    parser.add_argument("--expected-provider", default="local")
    parser.add_argument("--expected-model", default="deterministic-runtime-v1")
    parser.add_argument("--expected-invocation-type", default="local_deterministic_model")
    args = parser.parse_args()
    result = verify(
        args.tenant_id,
        args.run_id,
        args.expected_commit,
        args.expected_task,
        args.expected_result,
        args.db_path,
        args.expected_provider,
        args.expected_model,
        args.expected_invocation_type,
    )
    _emit_runtime_diagnostic(result)
    sys.exit(0 if result["status"] == "VERIFIED" else 1)


if __name__ == "__main__":
    main()
