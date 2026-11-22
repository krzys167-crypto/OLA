import ast
import hashlib
import ipaddress
import json
import operator
import os
import tempfile
import uuid
from urllib.parse import urlsplit

from sqlalchemy import select

from .database import SessionLocal, append_evidence_atomic, engine
from .hashchain import canonical_json
from .igor_evidence_verifier import verify_chain, trusted_record
from .models import EvidenceRecord
from .runtime_provenance import runtime_source_commit
from .capability_broker import (
    ExecutionRequest, PostgresReplayLedger, SQLiteReplayLedger,
    VoucherIssuer, VoucherVerifier,
)


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


def _validate_ollama_base_url(base_url):
    try:
        parsed = urlsplit(base_url)
        host = (parsed.hostname or "").rstrip(".").lower()
        parsed.port
    except ValueError:
        raise RuntimeError("OLLAMA_BASE_URL is not an approved Ollama endpoint") from None
    if (not host or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.scheme not in {"http", "https"}):
        raise RuntimeError("OLLAMA_BASE_URL is not an approved Ollama endpoint")
    try:
        is_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loopback = host == "localhost"
    allowed_hosts = {
        item.strip().lower().rstrip(".")
        for item in os.getenv("OLA_OLLAMA_ALLOWED_HOSTS", "").split(",")
        if item.strip()
    }
    if parsed.scheme == "http" and not is_loopback:
        raise RuntimeError("OLLAMA_BASE_URL requires loopback HTTP or an allowlisted HTTPS host")
    if parsed.scheme == "https" and not is_loopback and host not in allowed_hosts:
        raise RuntimeError("OLLAMA_BASE_URL requires loopback HTTP or an allowlisted HTTPS host")
    return base_url


MAX_AGENT_TASK_CHARS = 4096
MAX_EXPRESSION_NODES = 128
MAX_EXPRESSION_DEPTH = 24
MAX_LITERAL_ABS = 10**12


def _safe_expression(task):
    if not isinstance(task, str) or len(task) > MAX_AGENT_TASK_CHARS:
        return "execution blocked: task exceeds safe input limit"
    lowered = task.lower()
    if "calculate" in lowered:
        expression = task[lowered.index("calculate") + len("calculate"):].strip()
    else:
        expression = task.strip()
    expression = expression.replace("?", "").split(" and ")[0].strip()
    try:
        tree = ast.parse(expression, mode="eval")
    except (SyntaxError, ValueError, MemoryError):
        return "task accepted: no executable arithmetic expression supplied"
    if len(list(ast.walk(tree))) > MAX_EXPRESSION_NODES:
        return "task accepted: expression exceeds safe complexity limit"

    def evaluate(node, depth=0):
        if depth > MAX_EXPRESSION_DEPTH:
            raise ValueError("expression nesting limit exceeded")
        if isinstance(node, ast.Constant) and type(node.value) in (int, float):
            if abs(node.value) > MAX_LITERAL_ABS:
                raise ValueError("numeric literal exceeds safe range")
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in _SAFE_BINOPS:
            return _SAFE_BINOPS[type(node.op)](evaluate(node.left, depth + 1), evaluate(node.right, depth + 1))
        raise ValueError("unsafe expression")

    try:
        value = evaluate(tree.body)
        if isinstance(value, (int, float)) and abs(value) > MAX_LITERAL_ABS:
            return "task accepted: result exceeds safe numeric range"
        return str(value)
    except (ValueError, ArithmeticError, RecursionError, OverflowError):
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
    mode = os.getenv("OLA_LLM_MODE", "deterministic").strip().lower()
    if mode == "deterministic":
        return None
    if mode != "required":
        raise RuntimeError("OLA_LLM_MODE must be deterministic or required")
    prompt = canonical_json({"agent": agent, "task": task, "context": context})
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
        model = os.getenv("OLA_LLM_MODEL", "").strip()
        if not model:
            raise RuntimeError("OLA_LLM_MODEL must be explicitly configured when LLM mode is required")
        base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        parsed_url = urlsplit(base_url)
        allowed_hosts = {host.strip().lower() for host in os.getenv("OLA_LLM_ALLOWED_HOSTS", "api.openai.com").split(",") if host.strip()}
        if (parsed_url.scheme != "https" or not parsed_url.hostname
                or parsed_url.hostname.lower() not in allowed_hosts
                or parsed_url.username or parsed_url.password or parsed_url.query or parsed_url.fragment):
            raise RuntimeError("OPENAI_BASE_URL is not an approved HTTPS LLM endpoint")
        endpoint = base_url + "/responses"
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
            timeout=min(15.0, max(1.0, float(os.getenv("OLA_LLM_TIMEOUT", "15")))),
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
            output = "\n".join(parts)
        if not output:
            raise RuntimeError("OpenAI response contained no output text")
        return {
            "provider": "openai",
            "model": model,
            "invocation_type": "real_llm",
            "prompt_digest": _digest(prompt),
            "output": output,
            "response_id": body.get("id"),
        }

    if provider == "ollama":
        model = os.getenv("OLA_LLM_MODEL", os.getenv("OLLAMA_MODEL", "qwen2.5:0.5b-instruct"))
        base_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").strip().rstrip("/")
        base_url = _validate_ollama_base_url(base_url)
        options = {"temperature": 0}
        token_budget = os.getenv("OLA_OLLAMA_NUM_PREDICT")
        if token_budget is not None:
            if not token_budget.isascii() or not token_budget.isdecimal() or not 1 <= int(token_budget) <= 512:
                raise ValueError("OLA_OLLAMA_NUM_PREDICT must be an integer from 1 to 512")
            options["num_predict"] = int(token_budget)
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_message},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "options": options,
        }
        if agent == "nina_dag_planner":
            # A JSON DAG needs more room than short worker answers. Ollama's
            # structured JSON mode keeps the plan machine-readable; validation
            # of allowed tools, dependencies and sizes still happens separately.
            allowed = context.get("allowed_tools", [])
            if (not isinstance(allowed, list) or not allowed
                    or not all(isinstance(tool, str) and tool for tool in allowed)):
                raise ValueError("planner requires explicit allowlisted capabilities")
            payload["format"] = {
                "type": "object",
                "properties": {
                    "nodes": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 16,
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "string", "minLength": 1, "maxLength": 40},
                                "tool": {"type": "string", "enum": allowed},
                                "task": {"type": "string", "minLength": 1, "maxLength": 1000},
                                "needs": {"type": "array", "items": {"type": "string"}},
                            },
                            "required": ["id", "tool", "task", "needs"],
                            "additionalProperties": False,
                        },
                    },
                },
                "required": ["nodes"],
                "additionalProperties": False,
            }
            if context.get("independent_only") is True:
                # Independent goal: model still chooses task count/IDs/content,
                # but cannot hallucinate dependencies on nonexistent DAG nodes.
                nodes_schema = payload["format"]["properties"]["nodes"]
                nodes_schema["minItems"] = 2
                nodes_schema["maxItems"] = 4
                nodes_schema["items"]["properties"]["needs"]["maxItems"] = 0
            options["num_predict"] = max(options.get("num_predict", 0), 256)
        response = httpx.post(
            f"{base_url}/api/chat",
            headers={"Content-Type": "application/json"},
            json=payload,
            timeout=min(15.0, max(1.0, float(os.getenv("OLA_LLM_TIMEOUT", "15")))),
        )
        response.raise_for_status()
        body = response.json()
        output = body.get("message", {}).get("content")
        if not output:
            raise RuntimeError("Ollama response contained no message content")
        response_id = body.get("id") or f"ollama:{_digest(canonical_json(body))}"
        return {
            "provider": "ollama",
            "model": model,
            "invocation_type": "real_llm",
            "prompt_digest": _digest(prompt),
            "output": output,
            "response_id": response_id,
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
        "model_output_digest": _digest(model.get("output", "")),
        "model_output_role": "advisory_only",
        "action_result_source": "registered_capability",
    })
    return result


def _runtime_source_commit():
    # The embedded build metadata is authoritative. In strict container mode,
    # OLA_RUNTIME_COMMIT is deliberately ignored to prevent caller spoofing.
    # Legacy non-strict test environments may provide OLA_RUNTIME_COMMIT, but
    # agent evidence must still bind to a syntactically valid full Git SHA.
    commit = runtime_source_commit()
    if (
        not isinstance(commit, str)
        or len(commit) != 40
        or any(char not in "0123456789abcdef" for char in commit)
    ):
        return None
    return commit


def _append_agent_evidence(tenant_id, run_id, agent, task, previous_output, execution):
    agent_instance_id = str(uuid.uuid4())
    context = {
        "run_id": run_id,
        "agent": agent,
        "agent_instance_id": agent_instance_id,
        "task_digest": _digest(task),
        "previous_output_digest": _digest(canonical_json(previous_output)),
        "upstream_agents": [item["agent"] for item in execution],
    }
    output = {
        "agent": agent,
        "agent_instance_id": agent_instance_id,
        "execution_boundary": "in_process",
        "commit": _runtime_source_commit() or "UNKNOWN",
        "context_digest": _digest(canonical_json(context)),
        "task_digest": _digest(task),
        "input_digest": _digest(canonical_json(previous_output)),
        **_execute_agent(agent, tenant_id, task, previous_output, execution),
        "status": "RECORDED",
        "llm_required": os.getenv("OLA_LLM_MODE", "deterministic") == "required",
    }
    saved = append_evidence_atomic(tenant_id, f"agent.{agent}", {"run_id": run_id, **output})
    return saved["id"], output


def _run_evidence_rows(tenant_id, run_id):
    with SessionLocal() as db:
        rows = db.scalars(
            select(EvidenceRecord)
            .where(EvidenceRecord.tenant_id == tenant_id)
            .order_by(EvidenceRecord.seq.asc())
        ).all()
    selected = []
    for row in rows:
        try:
            payload = json.loads(row.payload_json)
        except (TypeError, ValueError):
            continue
        if payload.get("run_id") == run_id:
            selected.append((row, payload))
    return rows, selected


def finalize_agent_run(tenant_id, run_id):
    """Idempotently append the terminal lifecycle record, then verify the closed run."""
    if not isinstance(run_id, str) or not run_id:
        return {"status": "BLOCK", "reason": "run_id is required"}

    _, selected = _run_evidence_rows(tenant_id, run_id)
    starts = [(row, payload) for row, payload in selected
              if row.record_type == "execution.run.start"]
    ends = [(row, payload) for row, payload in selected
            if row.record_type == "execution.run.end"]
    errors = [(row, payload) for row, payload in selected
              if row.record_type == "execution.run.error"]
    agent_rows = [(row, payload) for row, payload in selected
                  if row.record_type.startswith("agent.")]

    if len(starts) != 1:
        return {"status": "BLOCK", "reason": "run must have exactly one durable start record"}
    if len(ends) > 1:
        return {"status": "BLOCK", "reason": "run has duplicate terminal records"}
    if ends:
        terminal = ends[0][1]
        if terminal.get("status") == "COMPLETED":
            return verify_agent_run(tenant_id, run_id)
        if terminal.get("status") == "FAILED":
            return {"status": "FAILED", "reason": "run has a durable failed terminal record"}
        return {"status": "BLOCK", "reason": "run terminal status is invalid"}

    failed = bool(errors)
    completed_count = len(agent_rows)
    if not failed and completed_count != len(AGENT_ROLES):
        return {
            "status": "FINALIZATION_PENDING",
            "reason": "run is incomplete and has no durable error record",
            "run_id": run_id,
            "completed_agent_count": completed_count,
        }

    terminal_status = "FAILED" if failed else "COMPLETED"
    try:
        append_evidence_atomic(
            tenant_id,
            "execution.run.end",
            {
                "run_id": run_id,
                "status": terminal_status,
                "completed_agent_count": completed_count,
            },
            deduplicate=True,
        )
    except Exception as exc:
        return {
            "status": "FINALIZATION_PENDING",
            "reason": f"terminal evidence append unavailable: {type(exc).__name__}",
            "run_id": run_id,
            "completed_agent_count": completed_count,
        }

    if failed:
        return {"status": "FAILED", "reason": "agent execution failed",
                "run_id": run_id, "completed_agent_count": completed_count}
    return verify_agent_run(tenant_id, run_id)


def run_agent_task(tenant_id, task, principal_id=None):
    blocked = {
        "run_id": None, "task": None, "final_result": None, "status": "BLOCK",
        "agents": AGENT_ROLES, "evidence_count": 0, "evidence_ids": [], "execution": [],
    }
    if not isinstance(task, str) or not task.strip() or len(task) > MAX_AGENT_TASK_CHARS:
        blocked["reason"] = "task must be a non-empty string no longer than 4096 characters"
        return blocked
    if principal_id is None and os.getenv("OLA_ENVIRONMENT") == "test":
        principal_id = "test-runtime-principal"
    if not isinstance(principal_id, str) or not principal_id.strip():
        blocked["reason"] = "authenticated principal is required"
        return blocked
    source_commit = _runtime_source_commit()
    if source_commit is None:
        blocked["reason"] = "runtime source commit missing or invalid"
        return blocked

    raw_key = os.getenv("OLA_CAPABILITY_VOUCHER_KEY_HEX")
    if not isinstance(raw_key, str) or not raw_key:
        blocked["reason"] = "capability voucher key is unavailable"
        return blocked
    try:
        secret = bytes.fromhex(raw_key)
    except (ValueError, TypeError):
        blocked["reason"] = "capability voucher key encoding is invalid"
        return blocked
    if len(secret) < 32:
        blocked["reason"] = "capability voucher key must contain at least 32 bytes"
        return blocked

    allowed_capabilities = {f"agent.execute:{role}" for role in AGENT_ROLES}
    test_scope = None
    try:
        if engine.dialect.name == "postgresql":
            replay_ledger = PostgresReplayLedger()
        elif engine.dialect.name == "sqlite" and os.getenv("OLA_ENVIRONMENT") == "test":
            # SQLite replay is confined to explicit pytest mode and a temporary,
            # run-scoped file. It is never a runtime/multi-host fallback.
            test_scope = tempfile.TemporaryDirectory(prefix="ola-capability-replay-test-")
            replay_ledger = SQLiteReplayLedger(
                os.path.join(test_scope.name, "replay.sqlite3")
            )
        else:
            blocked["reason"] = "shared durable replay ledger is unavailable"
            return blocked
        issuer = VoucherIssuer(secret, allowed_capabilities)
        verifier = VoucherVerifier(
            secret, allowed_capabilities, replay_ledger=replay_ledger,
        )
    except Exception as exc:
        if test_scope is not None:
            test_scope.cleanup()
        blocked["reason"] = f"capability enforcement unavailable: {type(exc).__name__}"
        return blocked

    run_id = str(uuid.uuid4())
    evidence_ids = []
    execution = []
    previous_output = {"task_digest": _digest(task)}
    try:
        append_evidence_atomic(tenant_id, "execution.run.start", {
            "run_id": run_id, "task_digest": _digest(task),
            "source_commit": source_commit, "principal_id": principal_id,
        })
        try:
            for agent in AGENT_ROLES:
                capability = f"agent.execute:{agent}"
                arguments = {
                    "agent_role": agent,
                    "task_digest": _digest(task),
                    "input_digest": _digest(canonical_json(previous_output)),
                    "upstream_agents": [item["agent"] for item in execution],
                }
                request = ExecutionRequest(
                    run_id=run_id, tenant_id=tenant_id, principal_id=principal_id,
                    capability=capability, arguments=arguments,
                    policy_version="agent-runtime-capability-v1",
                )
                voucher = issuer.issue(request)
                # Consume the one-use voucher before appending authorization
                # evidence or invoking the registered capability.
                verifier.verify_and_consume(voucher, request)
                append_evidence_atomic(
                    tenant_id, "execution.capability.authorized", {
                        "run_id": run_id, "tenant_id": tenant_id,
                        "principal_id": principal_id, "capability": capability,
                        "voucher_id": voucher.voucher_id,
                        "arguments_digest": voucher.arguments_digest,
                        "policy_version": voucher.policy_version,
                        "source_commit": source_commit,
                        "decision": "ALLOW",
                    }, producer_id="ola_runtime",
                )
                evidence_id, output = _append_agent_evidence(
                    tenant_id, run_id, agent, task, previous_output, execution
                )
                evidence_ids.append(evidence_id)
                execution.append(output)
                previous_output = output
        except Exception as exc:
            # Store only the exception class; messages may contain prompts,
            # secrets or PII. No capability is invoked after authorization fails.
            try:
                append_evidence_atomic(
                    tenant_id, "execution.run.error", {
                        "run_id": run_id, "error_type": type(exc).__name__,
                        "completed_agent_count": len(evidence_ids),
                    }, deduplicate=True,
                )
            except Exception:
                return {
                    "run_id": run_id, "task": None, "final_result": None,
                    "status": "FINALIZATION_PENDING",
                    "reason": "failure evidence could not be persisted",
                    "agents": AGENT_ROLES, "evidence_count": len(evidence_ids),
                    "evidence_ids": evidence_ids, "execution": execution,
                }
            finalization = finalize_agent_run(tenant_id, run_id)
            return {
                "run_id": run_id, "task": None, "final_result": None,
                "status": finalization["status"],
                "reason": finalization.get("reason", f"agent execution failed: {type(exc).__name__}"),
                "agents": AGENT_ROLES, "evidence_count": len(evidence_ids),
                "evidence_ids": evidence_ids, "execution": execution,
                "verification_scope": finalization.get("verification_scope", []),
                "not_established": finalization.get("not_established", []),
            }

        finalization = finalize_agent_run(tenant_id, run_id)
        final_result = execution[-1].get("final_result") if execution else None
        return {
            "run_id": run_id, "task": task if finalization["status"] == "VERIFIED" else None,
            "final_result": final_result if finalization["status"] == "VERIFIED" else None,
            "status": finalization["status"], "reason": finalization.get("reason"),
            "agents": AGENT_ROLES, "evidence_count": len(evidence_ids),
            "evidence_ids": evidence_ids, "execution": execution,
            "verification_scope": finalization.get("verification_scope", []),
            "not_established": finalization.get("not_established", []),
        }
    finally:
        if test_scope is not None:
            test_scope.cleanup()


def run_multi_agent_task(tenant_id, task, agents):
    """Build a deterministic digest-chain simulation for a supplied agent registry.

    This function does not start agent processes, invoke an LLM, execute capabilities,
    persist evidence, or prove inter-agent communication. Its output is SIMULATED only.
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
    digest_edges = []
    previous_digest = _digest(canonical_json({"run_id": run_id, "task": task}))

    for index, agent in enumerate(agents):
        invocation = canonical_json({
            "run_id": run_id,
            "agent_id": agent.agent_id,
            "role": agent.role,
            "task_digest": _digest(task),
            "input_digest": previous_digest,
        })
        output_digest = _digest(invocation)
        execution.append({
            "agent_id": agent.agent_id,
            "role": agent.role,
            "sequence": index,
            "input_digest": previous_digest,
            "output_digest": output_digest,
            "status": "SIMULATED",
        })
        if index:
            digest_edges.append({
                "from": agents[index - 1].agent_id,
                "to": agent.agent_id,
                "input_digest": previous_digest,
                "edge_type": "synthetic_digest_link",
            })
        previous_digest = output_digest

    digest_chain_valid = (
        len(execution) == len(agents)
        and len({item["output_digest"] for item in execution}) == len(agents)
        and len(digest_edges) == len(agents) - 1
        and all(item["status"] == "SIMULATED" for item in execution)
    )
    return {
        "run_id": run_id,
        "tenant_id": tenant_id,
        "task_digest": _digest(task),
        "status": "SIMULATED",
        "execution_mode": "digest_only_simulation",
        "claim_boundary": "No agent processes, LLM calls, capability executions, evidence persistence, or real inter-agent communication are established.",
        "agent_count": len(agents),
        "agent_ids": agent_ids,
        "digest_edges": digest_edges,
        "cooperation_verified": False,
        "deterministic_chain_valid": digest_chain_valid,
        "not_established": [
            "agent_process_execution",
            "llm_invocation",
            "capability_execution",
            "inter_agent_communication",
            "independently_verified_agent_evidence",
        ],
        "execution": execution,
    }


def verify_agent_run(tenant_id, run_id):
    expected_commit = _runtime_source_commit()
    if expected_commit is None:
        return {"status": "BLOCK", "reason": "runtime source commit missing or invalid"}

    rows, selected = _run_evidence_rows(tenant_id, run_id)
    start_rows = [(row, payload) for row, payload in selected
                  if row.record_type == "execution.run.start"]
    end_rows = [(row, payload) for row, payload in selected
                if row.record_type == "execution.run.end"]
    run_rows = [row for row, _ in selected if row.record_type.startswith("agent.")]

    if len(start_rows) != 1 or len(end_rows) != 1:
        return {
            "status": "UNKNOWN",
            "reason": "complete run lifecycle evidence is required",
            "evidence_count": len(run_rows),
        }
    start_row, _ = start_rows[0]
    end_row, end_payload = end_rows[0]
    if end_payload.get("status") != "COMPLETED":
        return {"status": "BLOCK", "reason": "run terminal record is not COMPLETED",
                "evidence_count": len(run_rows)}
    if end_payload.get("completed_agent_count") != len(AGENT_ROLES):
        return {"status": "BLOCK", "reason": "terminal agent count mismatch",
                "evidence_count": len(run_rows)}
    if not (start_row.seq < end_row.seq):
        return {"status": "BLOCK", "reason": "run lifecycle order is invalid",
                "evidence_count": len(run_rows)}
    if any(row.seq >= end_row.seq for row in run_rows):
        return {"status": "BLOCK", "reason": "agent evidence appears after terminal record",
                "evidence_count": len(run_rows)}
    if len(run_rows) != len(AGENT_ROLES):
        return {"status": "UNKNOWN", "reason": "missing agent evidence",
                "evidence_count": len(run_rows)}
    expected_types = [f"agent.{role}" for role in AGENT_ROLES]
    if [row.record_type for row in run_rows] != expected_types:
        return {"status": "BLOCK", "reason": "agent order mismatch",
                "evidence_count": len(run_rows)}

    instance_ids = set()
    context_digests = set()
    for row in run_rows:
        payload = json.loads(row.payload_json)
        required = {
            "capability", "tool", "tool_output", "result", "status",
            "agent_instance_id", "execution_boundary", "context_digest",
            "invocation_type", "model", "provider", "response_id", "commit",
            "task_digest", "input_digest", "model_output_digest",
            "model_output_role", "action_result_source",
        }
        if not required.issubset(payload):
            return {"status": "BLOCK", "reason": "agent execution evidence incomplete",
                    "evidence_count": len(run_rows)}
        for digest_key in ("context_digest", "task_digest", "input_digest", "model_output_digest"):
            digest_value = payload.get(digest_key)
            if (not isinstance(digest_value, str) or len(digest_value) != 64
                    or any(char not in "0123456789abcdef" for char in digest_value)):
                return {"status": "BLOCK",
                        "reason": f"invalid {digest_key} for {payload.get('agent')}",
                        "evidence_count": len(run_rows)}
        if payload.get("commit") != expected_commit:
            return {"status": "BLOCK", "reason": "runtime commit provenance mismatch",
                    "evidence_count": len(run_rows)}
        if payload["status"] != "RECORDED":
            return {"status": "BLOCK", "reason": "agent evidence was not producer-recorded",
                    "evidence_count": len(run_rows)}
        if (payload.get("model_output_role") != "advisory_only"
                or payload.get("action_result_source") != "registered_capability"):
            return {"status": "BLOCK", "reason": "model/action provenance is ambiguous",
                    "evidence_count": len(run_rows)}
        if payload.get("agent") == "self_reflection" and payload.get("tool_output") != "PASS":
            return {"status": "BLOCK", "reason": "self-reflection did not pass",
                    "evidence_count": len(run_rows)}
        if payload["execution_boundary"] != "in_process":
            return {"status": "BLOCK", "reason": "unexpected agent execution boundary",
                    "evidence_count": len(run_rows)}
        instance_ids.add(payload["agent_instance_id"])
        context_digests.add(payload["context_digest"])
    if len(instance_ids) != len(AGENT_ROLES) or len(context_digests) != len(AGENT_ROLES):
        return {"status": "BLOCK", "reason": "agent instances or contexts are not unique",
                "evidence_count": len(run_rows)}

    chain = [{
        "tenant_id": row.tenant_id, "seq": row.seq, "prev_hash": row.prev_hash,
        "record_hash": row.record_hash, "record_type": row.record_type,
        "payload_json": row.payload_json,
    } for row in rows]
    chain_ok, reason = verify_chain(chain)
    if chain_ok and not all(
        trusted_record({"record_type": row.record_type, "payload_json": row.payload_json})
        for row in run_rows
    ):
        return {"status": "BLOCK", "reason": "legacy or untrusted agent evidence",
                "evidence_count": len(run_rows)}
    if not chain_ok:
        return {"status": "BLOCK", "reason": reason, "evidence_count": len(run_rows)}
    return {
        "status": "VERIFIED",
        "reason": "closed run lifecycle, source binding, recorded agent structure, unique instance labels and tenant evidence hash-chain integrity passed; process isolation and capability semantics were not verified",
        "commit": expected_commit,
        "evidence_count": len(run_rows),
        "execution_boundary": "in_process",
        "verification_scope": [
            "closed_run_lifecycle",
            "runtime_source_commit_binding",
            "agent_role_order_and_record_structure",
            "unique_agent_instance_and_context_labels",
            "tenant_evidence_hash_chain_integrity",
        ],
        "not_established": [
            "isolated_or_independent_agent_processes",
            "semantic_correctness_of_registered_capabilities",
            "model_generated_action_results",
        ],
    }
