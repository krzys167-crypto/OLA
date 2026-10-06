import argparse
import hashlib
from datetime import datetime
import json
import os
import sqlite3
import sys
import re

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
GENESIS_HASH = "0" * 64


def compute_record_hash(tenant_id, seq, prev_hash, payload_json, record_type=None):
    """v1 (no type) or v2 (type-bound, 'ola.chain/2'); same rule as app/hashchain.py."""
    material = (f"{tenant_id}|{seq}|{prev_hash}|{payload_json}" if record_type is None else
                f"ola.chain/2|{tenant_id}|{seq}|{prev_hash}|{len(record_type)}:{record_type}|{payload_json}")
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def verify_hash_chain(rows):
    expected_prev = GENESIS_HASH
    seen_v2 = False
    for expected_seq, row in enumerate(rows):
        tenant_id, seq, record_type, payload_json, prev_hash, record_hash = row
        if seq != expected_seq or prev_hash != expected_prev:
            return False, "sequence or predecessor mismatch"
        if record_hash == compute_record_hash(tenant_id, seq, prev_hash, payload_json, record_type):
            seen_v2 = True
        elif seen_v2 or record_hash != compute_record_hash(tenant_id, seq, prev_hash, payload_json):
            return False, "record hash mismatch"
        expected_prev = record_hash
    return True, "ok"


def fail(reason, **extra):
    return {"status": "BLOCK", "reason": reason, **extra}


def verify(tenant_id, run_id, expected_commit, expected_task=None, expected_result=None, db_path=None, expected_provider="local", expected_model="deterministic-runtime-v1", expected_invocation_type="local_deterministic_model", expected_nonce=None):
    # A blank or "UNKNOWN" expected commit would "agree" with a record written without commit provenance
    # (OLA_SOURCE_COMMIT unset -> "UNKNOWN") and report source_commit_verified: True. That is no provenance.
    if not isinstance(expected_commit, str) or expected_commit.strip().upper() in {"", "UNKNOWN"}:
        return fail("expected commit is blank or UNKNOWN: there is no source provenance to verify")
    db_path = db_path or os.getenv("OLA_EG_DB_PATH", "/data/ola.db")
    expected_invocation = {
        "provider": expected_provider,
        "model": expected_model,
        "invocation_type": expected_invocation_type,
    }
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
    starts = []
    ends = []
    for row in run_rows:
        payload = json.loads(row[3])
        payloads.append(payload)
        agent = payload.get("agent")
        required = {
            "capability", "tool", "tool_output", "result", "status",
            "agent_instance_id", "execution_boundary", "source_commit", "context_digest",
            "invocation_type", "model", "provider", "started_at", "ended_at",
        }
        if not required.issubset(payload):
            return fail(f"execution evidence incomplete for {agent}")
        if payload.get("status") != "VERIFIED":
            return fail(f"execution not verified for {agent}")
        if payload.get("capability") != EXPECTED_CAPABILITIES.get(agent):
            return fail(f"unexpected capability for {agent}")
        if payload.get("execution_boundary") != "independent":
            return fail(f"non-independent execution boundary for {agent}")
        if payload.get("source_commit") != expected_commit:
            return fail(f"source commit mismatch for {agent}: expected {expected_commit!r}, got {payload.get('source_commit')!r}")
        nonce = str(payload.get("replay_nonce", ""))
        if expected_invocation_type == "real_llm" and not re.fullmatch(r"[0-9a-f]{64}", nonce):
            return fail(f"replay nonce missing or malformed for {agent}")
        if expected_nonce is not None and nonce != expected_nonce:
            return fail(f"replay nonce mismatch for {agent}: expected {expected_nonce!r}, got {nonce!r}")
        if payload["invocation_type"] == "real_llm" and not (payload.get("response_id") or payload.get("response_digest")):
            return fail(f"missing real LLM response identity for {agent}")
        invocation = {
            "provider": payload["provider"],
            "model": payload["model"],
            "invocation_type": payload["invocation_type"],
        }
        if expected_invocation_type == "real_llm" and not (
            payload.get("response_id") or payload.get("response_digest")
        ):
            return fail(f"missing real LLM response identity for {agent}")
        if invocation != expected_invocation:
            return fail(f"unexpected invocation metadata for {agent}")
        instance_ids.add(payload["agent_instance_id"])
        context_digests.add(payload["context_digest"])
        try:
            started_at = datetime.fromisoformat(str(payload["started_at"]).replace("Z", "+00:00"))
            ended_at = datetime.fromisoformat(str(payload["ended_at"]).replace("Z", "+00:00"))
        except ValueError:
            return fail(f"invalid execution timestamps for {agent}")
        if not started_at < ended_at:
            return fail(f"non-positive execution duration for {agent}")
        starts.append(started_at)
        ends.append(ended_at)
        invocations[agent] = invocation
        capabilities[agent] = payload["capability"]

    if starts != sorted(starts) or ends != sorted(ends):
        return fail("agent execution timestamps are not monotonic")
    if len(instance_ids) != len(ROLES):
        return fail("agent instance identities are not unique")
    source_commits = {payload.get("source_commit") for payload in payloads}
    if source_commits != {expected_commit}:
        return fail(f"source commit set mismatch: expected {expected_commit!r}, got {sorted(source_commits)!r}")
    replay_nonces = {payload.get("replay_nonce") for payload in payloads}
    if len(replay_nonces) != 1:
        return fail(f"replay nonce set is inconsistent: {sorted(replay_nonces)!r}")
    if expected_nonce is not None and replay_nonces != {expected_nonce}:
        return fail(f"replay nonce set mismatch: expected {expected_nonce!r}, got {sorted(replay_nonces)!r}")
    if len(context_digests) != len(ROLES):
        return fail("agent contexts are not unique")

    if expected_task is not None and any(payload.get("task") != expected_task for payload in payloads):
        return fail("task mismatch in execution evidence")

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
        "source_commit_verified": True,
        "task": expected_task,
        "final_result": final_result,
        "agents": ROLES,
        "capabilities": capabilities,
        "independent_instance_count": len(instance_ids),
        "independent_context_count": len(context_digests),
        "invocations": invocations,
        "evidence_count": len(run_rows),
        "replay_nonce": next(iter(replay_nonces)),
        "reason": "standalone verifier recomputed roles, capabilities, invocation metadata, result, identities, contexts, replay nonce and hash chain without importing runtime verification code",
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
    parser.add_argument("--expected-nonce")
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
        args.expected_nonce,
    )
    _emit_runtime_diagnostic(result)
    sys.exit(0 if result["status"] == "VERIFIED" else 1)


if __name__ == "__main__":
    main()
