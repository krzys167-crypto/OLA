        if payload["execution_boundary"] != "independent":
            return {"status": "BLOCK", "reason": "agent execution boundary is not independent", "evidence_count": len(run_rows)}
        if payload["invocation_type"] == "real_llm" and not (payload.get("response_id") or payload.get("response_digest")):
            return {"status": "BLOCK", "reason": "real LLM response identity missing", "evidence_count": len(run_rows)}
        instance_ids.add(payload["agent_instance_id"])
        context_digests.add(payload["context_digest"])
    if len(instance_ids) != len(AGENT_ROLES) or len(context_digests) != len(AGENT_ROLES):
        return {"status": "BLOCK", "reason": "agent instances or contexts are not unique", "evidence_count": len(run_rows)}
    source_commits = {json.loads(row.payload_json).get("source_commit") for row in run_rows}
    if len(source_commits) != 1 or None in source_commits:
        return {"status": "BLOCK", "reason": "source commit binding is missing or inconsistent", "evidence_count": len(run_rows)}
    chain = [{"tenant_id": row.tenant_id, "seq": row.seq, "prev_hash": row.prev_hash, "record_hash": row.record_hash, "payload_json": row.payload_json} for row in rows]
    chain_ok, reason = verify_chain(chain)
    if not chain_ok:
        return {"status": "BLOCK", "reason": reason, "evidence_count": len(run_rows)}
    return {"status": "VERIFIED", "reason": "independent agent identities, contexts, execution evidence and hash-chain verification passed", "evidence_count": len(run_rows)}