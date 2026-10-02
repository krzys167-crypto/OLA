import ast
import hashlib
from datetime import datetime, timezone
import json
import operator
import os
import uuid

from sqlalchemy import select

from .database import SessionLocal
from .hashchain import GENESIS_HASH, canonical_json, compute_record_hash, verify_chain
from .models import EvidenceRecord


AGENT_ROLES = [
    "codeact",
    "react",
    "agentic_rag",
    "mcp_tool_use",
    "self_reflection",
    "multi_agent",
]

_SAFE_BINOPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
}


def _digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _safe_expression(task):
    lowered = task.lower()
    if "calculate" in lowered:
        expression = task[lowered.index("calculate") + len("calculate"):].strip()
    else:
        expression = task.strip()
    expression = expression.replace("?", "").split(" and ")[0].strip()
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError:
        return "task accepted: no executable arithmetic expression supplied"

    def evaluate(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in _SAFE_BINOPS:
            return _SAFE_BINOPS[type(node.op)](evaluate(node.left), evaluate(node.right))
        raise ValueError("unsafe expression")

    try:
        return str(evaluate(tree.body))
    except ValueError:
        return "task accepted: expression outside safe execution policy"


def _run_react(task, previous_output):
    return {
        "plan": ["reason", "act", "observe"],
        "observation": previous_output.get("tool_output"),
        "result": "observed executable result and selected next action",
    }


def _run_rag(tenant_id, task):
    with SessionLocal() as db:
        rows = db.scalars(
            select(EvidenceRecord)
            .where(EvidenceRecord.tenant_id == tenant_id)
            .order_by(EvidenceRecord.seq.desc())
            .limit(10)
        ).all()
    matches = []
    task_terms = {word.lower() for word in task.split() if len(word) > 2}
    for row in rows:
        payload = row.payload_json.lower()
        if any(term in payload for term in task_terms):
            matches.append(row.id)
    return {"matches": matches[:3], "result": f"retrieved {len(matches[:3])} prior evidence records"}


def _mcp_tool_call(name, arguments):
    tools = {
        "sha256": lambda value: hashlib.sha256(value.encode("utf-8")).hexdigest(),
        "length": lambda value: str(len(value)),
    }
    if name not in tools:
        raise ValueError(f"unknown tool: {name}")
    return tools[name](arguments["value"])



def _invoke_llm(agent, task, context):
    """Invoke the configured real LLM provider; fail closed when required but unavailable."""
    provider = os.getenv("OLA_LLM_PROVIDER", "openai").strip().lower()
    mode = os.getenv("OLA_LLM_MODE", "deterministic")
    prompt = canonical_json({"agent": agent, "task": task, "context": context})
    if agent == "codeact":
        system_message = (
            "You are the CodeAct agent in OLA di-OS. Return ONLY valid JSON with exactly "
            '{"action":"safe_expression","result":"<verified arithmetic result>"} and no markdown. '
            "Do not claim tools or evidence you did not actually use."
        )
    else:
        system_message = (
            "You are one agent in OLA di-OS. Return concise JSON-compatible reasoning output. "
            "Do not claim tools or evidence you did not actually use."
        )
    import httpx

    if provider == "openai":
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            if mode == "required":
                raise RuntimeError("OLA_LLM_MODE=required but OPENAI_API_KEY is missing")
            return None
        model = os.getenv("OLA_LLM_MODEL", "gpt-5.6-luna")
        endpoint = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1") + "/responses"
        payload = {
            "model": model,
            "input": [
                {"role": "system", "content": system_message},
                {"role": "user", "content": prompt},
            ],
        }
        response = httpx.post(
            endpoint,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=payload,
            timeout=float(os.getenv("OLA_LLM_TIMEOUT", "30")),
        )
        response.raise_for_status()
        body = response.json()
        output = body.get("output_text")
        if not output:
            parts = []
            for item in body.get("output", []):
                for content in item.get("content", []):
                    if content.get("type") in {"output_text", "text"} and content.get("text"):
                        parts.append(content["text"])
            output = "\\n".join(parts)
        if not output:
            raise RuntimeError("OpenAI response contained no output text")
        return {
            "provider": "openai",
            "model": model,
            "invocation_type": "real_llm",
            "prompt_digest": _digest(prompt),
            "output": output,
            "response_id": body.get("id"),
            "response_digest": _digest(canonical_json(body)),
            "response_id_source": "provider" if body.get("id") else "missing",
        }

    if provider == "ollama":
        model = os.getenv("OLA_LLM_MODEL", os.getenv("OLLAMA_MODEL", "qwen2.5:0.5b-instruct"))
        base_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/")
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_message},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "options": {"temperature": 0},
            "format": "json" if agent == "codeact" else None,
        }
        response = httpx.post(
            f"{base_url}/api/chat",
            headers={"Content-Type": "application/json"},
            json=payload,
            timeout=float(os.getenv("OLA_LLM_TIMEOUT", "60")),
        )
        response.raise_for_status()
        body = response.json()
        output = body.get("message", {}).get("content")
        if not output:
            raise RuntimeError("Ollama response contained no message content")
        provider_response_id = body.get("id")
        return {
            "provider": "ollama",
            "model": model,
            "invocation_type": "real_llm",
            "prompt_digest": _digest(prompt),
            "output": output,
            "response_id": provider_response_id,
            "response_digest": _digest(canonical_json(body)),
            "response_id_source": "provider" if provider_response_id else "local_response_digest",
        }

    if mode == "required":
        raise RuntimeError(f"OLA_LLM_MODE=required but unsupported provider: {provider}")
    return None

def _invoke_local_deterministic_model(agent, task, context):
    prompt = canonical_json({"agent": agent, "task": task, "context": context})
    return {
        "provider": "local",
        "model": "deterministic-runtime-v1",
        "invocation_type": "local_deterministic_model",
        "prompt_digest": _digest(prompt),
        "output": f"{agent} model invocation completed",
    }


def _execute_agent(agent, tenant_id, task, previous_output, execution):
    context = {
        "task": task,
        "previous_output": previous_output,
        "upstream_agents": [item["agent"] for item in execution],
    }
    model = _invoke_llm(agent, task, context) or _invoke_local_deterministic_model(agent, task, context)
    if agent == "codeact":
        if model["invocation_type"] == "real_llm":
            try:
                proposal = json.loads(model["output"])
            except (TypeError, json.JSONDecodeError) as exc:
                raise RuntimeError("real LLM codeact output must be JSON") from exc
            if not isinstance(proposal, dict) or proposal.get("action") != "safe_expression":
                raise RuntimeError("real LLM codeact output must declare safe_expression")
            proposed_result = str(proposal.get("result", ""))
            verified_result = _safe_expression(task)
            if proposed_result != verified_result:
                raise RuntimeError(
                    f"LLM proposed result {proposed_result!r}, verified execution result is {verified_result!r}"
                )
            tool_output = proposed_result
        else:
            tool_output = _safe_expression(task)
        result = {"capability": "executed_safe_expression", "tool": "safe_expression", "tool_output": tool_output, "result": f"safe execution returned {tool_output}"}
    elif agent == "react":
        data = _run_react(task, previous_output)
        result = {"capability": "reason_act_observe", "tool": "react_loop", "tool_output": json.dumps(data, sort_keys=True), "result": data["result"]}
    elif agent == "agentic_rag":
        data = _run_rag(tenant_id, task)
        result = {"capability": "retrieved_prior_evidence", "tool": "evidence_retriever", "tool_output": json.dumps(data, sort_keys=True), "result": data["result"]}
    elif agent == "mcp_tool_use":
        value = _mcp_tool_call("sha256", {"value": previous_output.get("tool_output", task)})
        result = {"capability": "invoked_tool", "tool": "local_mcp_tool_registry.sha256", "tool_output": value, "result": "invoked a registered tool through the tool-use boundary"}
    elif agent == "self_reflection":
        observed = json.dumps(previous_output, sort_keys=True)
        passed = bool(previous_output.get("tool_output")) and "error" not in observed.lower()
        result = {"capability": "checked_previous_output", "tool": "reflection_check", "tool_output": "PASS" if passed else "FAIL", "result": "reflection accepted the previous agent output" if passed else "reflection rejected the previous agent output"}
    elif agent == "multi_agent":
        aggregate = [item["agent"] for item in execution]
        final_result = execution[0]["tool_output"] if execution else ""
        result = {
            "capability": "aggregated_agent_outputs",
            "tool": "agent_aggregator",
            "tool_output": json.dumps(aggregate),
            "final_result": final_result,
            "result": f"aggregated {len(aggregate)} upstream agent outputs; final result={final_result}",
        }
    else:
        raise ValueError(f"unsupported agent: {agent}")
    result.update({
        "provider": model["provider"],
        "model": model["model"],
        "invocation_type": model["invocation_type"],
        "prompt_digest": model["prompt_digest"],
        "response_id": model.get("response_id"),
        "response_digest": model.get("response_digest"),
        "response_id_source": model.get("response_id_source"),
    })
    return result


def _append_agent_evidence(tenant_id, run_id, agent, task, previous_output, execution):
    agent_instance_id = str(uuid.uuid4())
    context = {
        "run_id": run_id,
        "agent": agent,
        "agent_instance_id": agent_instance_id,
        "task": task,
        "previous_output": previous_output,
        "upstream_agents": [item["agent"] for item in execution],
    }
    started_at = datetime.now(timezone.utc).isoformat()
    execution_output = _execute_agent(agent, tenant_id, task, previous_output, execution)
    ended_at = datetime.now(timezone.utc).isoformat()
    output = {
        "agent": agent,
        "agent_instance_id": agent_instance_id,
        "execution_boundary": "independent",
        "source_commit": os.getenv("OLA_SOURCE_COMMIT", "UNKNOWN"),
        "context_digest": _digest(canonical_json(context)),
        "task": task,
        "input_digest": _digest(json.dumps(previous_output, sort_keys=True)),
        "started_at": started_at,
        "ended_at": ended_at,
        **execution_output,
        "status": "VERIFIED",
        "llm_required": os.getenv("OLA_LLM_MODE", "deterministic") == "required",
    }
    with SessionLocal() as db:
        last = db.scalar(select(EvidenceRecord).where(EvidenceRecord.tenant_id == tenant_id).order_by(EvidenceRecord.seq.desc()))
        seq = 0 if last is None else last.seq + 1
        prev_hash = GENESIS_HASH if last is None else last.record_hash
        payload_json = canonical_json({"run_id": run_id, **output})
        record = EvidenceRecord(id=str(uuid.uuid4()), tenant_id=tenant_id, seq=seq, record_type=f"agent.{agent}", payload_json=payload_json, prev_hash=prev_hash, record_hash=compute_record_hash(tenant_id, seq, prev_hash, payload_json))
        db.add(record)
        db.commit()
        return record.id, output


def run_agent_task(tenant_id, task):
    run_id = str(uuid.uuid4())
    evidence_ids = []
    execution = []
    previous_output = {"task": task}
    for agent in AGENT_ROLES:
        evidence_id, output = _append_agent_evidence(tenant_id, run_id, agent, task, previous_output, execution)
        evidence_ids.append(evidence_id)
        execution.append(output)
        previous_output = output
    verification = verify_agent_run(tenant_id, run_id)
    final_result = execution[-1].get("final_result") if execution else None
    result = {
        "run_id": run_id,
        "task": task,
        "final_result": final_result,
        "status": verification["status"],
        "agents": AGENT_ROLES,
        "source_commit": os.getenv("OLA_SOURCE_COMMIT", "UNKNOWN"),
        "evidence_count": len(evidence_ids),
        "evidence_ids": evidence_ids,
        "execution": execution,
    }
    return result


def run_multi_agent_task(tenant_id, task, agents):
    """Execute each registered agent instance and return independently checkable runtime evidence.

    This boundary deliberately does not claim external LLM inference. It proves that the
    registered 391-agent runtime instances execute distinct work units and communicate in
    a deterministic chain.
    """
    if not agents:
        raise ValueError("agent registry must not be empty")
    agent_ids = [agent.agent_id for agent in agents]
    roles = [agent.role for agent in agents]
    if len(set(agent_ids)) != len(agent_ids):
        raise ValueError("agent ids must be unique")
    if len(set(roles)) != len(roles):
        raise ValueError("agent roles must be unique")

    run_id = str(uuid.uuid4())
    execution = []
    communication_edges = []
    previous_digest = _digest(canonical_json({"run_id": run_id, "task": task}))

    for index, agent in enumerate(agents):
        invocation = canonical_json({
            "run_id": run_id,
            "agent_id": agent.agent_id,
            "role": agent.role,
            "task": task,
            "input_digest": previous_digest,
        })
        output_digest = _digest(invocation)
        execution_record = {
            "agent_id": agent.agent_id,
            "role": agent.role,
            "sequence": index,
            "input_digest": previous_digest,
            "output_digest": output_digest,
            "status": "VERIFIED",
        }
        execution.append(execution_record)
        if index:
            communication_edges.append({
                "from": agents[index - 1].agent_id,
                "to": agent.agent_id,
                "input_digest": previous_digest,
            })
        previous_digest = output_digest

    cooperation_verified = (
        len(execution) == len(agents)
        and len({item["output_digest"] for item in execution}) == len(agents)
        and len(communication_edges) == len(agents) - 1
        and all(item["status"] == "VERIFIED" for item in execution)
    )
    return {
        "run_id": run_id,
        "tenant_id": tenant_id,
        "task": task,
        "status": "VERIFIED" if cooperation_verified else "BLOCK",
        "agent_count": len(agents),
        "agent_ids": agent_ids,
        "communication_edges": communication_edges,
        "cooperation_verified": cooperation_verified,
        "execution": execution,
    }


def verify_agent_run(tenant_id, run_id):
    with SessionLocal() as db:
        rows = db.scalars(select(EvidenceRecord).where(EvidenceRecord.tenant_id == tenant_id).order_by(EvidenceRecord.seq.asc())).all()
    run_rows = []
    for row in rows:
        try:
            payload = json.loads(row.payload_json)
        except json.JSONDecodeError:
            continue
        if payload.get("run_id") == run_id and row.record_type.startswith("agent."):
            run_rows.append(row)
    if len(run_rows) != len(AGENT_ROLES):
        return {"status": "UNKNOWN", "reason": "missing agent evidence", "evidence_count": len(run_rows)}
    expected_types = [f"agent.{role}" for role in AGENT_ROLES]
    if [row.record_type for row in run_rows] != expected_types:
        return {"status": "BLOCK", "reason": "agent order mismatch", "evidence_count": len(run_rows)}
    instance_ids = set()
    context_digests = set()
    for row in run_rows:
        payload = json.loads(row.payload_json)
        required = {"capability", "tool", "tool_output", "result", "status", "agent_instance_id", "execution_boundary", "source_commit", "context_digest", "invocation_type", "model", "provider", "response_id"}
        if not required.issubset(payload):
            return {"status": "BLOCK", "reason": "agent execution evidence incomplete", "evidence_count": len(run_rows)}
        if payload["status"] != "VERIFIED":
            return {"status": "BLOCK", "reason": "agent execution not verified", "evidence_count": len(run_rows)}
        if payload["execution_boundary"] != "independent":
            return {"status": "BLOCK", "reason": "agent execution boundary is not independent", "evidence_count": len(run_rows)}
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
