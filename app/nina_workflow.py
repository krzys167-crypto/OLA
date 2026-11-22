"""Feature-gated autonomous workflow planning for the existing NINA runtime.

No implicit deterministic fallback: planning requires a real configured LLM.
All executable capabilities are already allowlisted by NINA.
"""
import hashlib
import json
import os
import tempfile
import uuid

from .database import engine
from .hashchain import canonical_json
from .capability_broker import (
    ExecutionRequest, PostgresReplayLedger, SQLiteReplayLedger,
    VoucherIssuer, VoucherVerifier,
)

from .workflow_engine import WorkflowEngine, WorkflowPlanError, validate_plan


def model_plan(goal, tools, *, independent_only=False):
    from .agent_runtime import _invoke_llm

    if not isinstance(goal, str) or not goal.strip() or len(goal) > 2000:
        raise WorkflowPlanError("invalid goal")
    contract = (
        'Respond with ONLY JSON: {"nodes":[{"id":"short_unique_id",'
        '"tool":"one_allowed_tool","task":"bounded instruction",'
        '"needs":[]}]}. Generate 1 to 16 useful nodes. '
        'Use dependencies only when needed and parallel independent work. '
        'Every needs entry MUST match an actual id of another node in the '
        'same plan; for independent nodes use needs:[]. '
        'No code fences, no prose. Never request tools outside allowed_tools.'
    )
    if independent_only:
        contract += (
            " The user needs independent work only: create TWO to FOUR "
            "independent llm_agent nodes with needs:[] for every node. "
            "Choose the node identities and the substantive tasks yourself. "
            "Do not create imaginary dependencies or extra joins."
        )
    rejection = None
    for attempt in range(1, 4):
        context = {"contract": contract, "allowed_tools": list(tools)}
        if independent_only:
            context["independent_only"] = True
        if rejection:
            # Only the deterministic validator's error, not previous model text.
            # This requests correction from the model; Python never repairs an
            # invalid DAG, silently drops dependencies, or runs fallback steps.
            context["revision"] = (
                f"Previous plan rejected: {rejection}. Generate a new plan with "
                "all needs referencing defined node ids (or [] for independent "
                "work), exact required fields, and only allowlisted tools."
            )
        try:
            response = _invoke_llm("nina_dag_planner", goal, context)
        except Exception as exc:
            raise WorkflowPlanError(f"planner failed: {type(exc).__name__}") from exc
        if (not response or response.get("invocation_type") != "real_llm"
                or not response.get("response_id") or not response.get("output")):
            raise WorkflowPlanError("real LLM planning and response provenance required")
        try:
            data = json.loads(response["output"])
        except (ValueError, TypeError):
            rejection = "planner output is not strict JSON"
            continue
        try:
            nodes = validate_plan(data, allowed_tools=set(tools))
            if independent_only and (not 2 <= len(nodes) <= 4
                                     or any(node.needs or node.tool != "llm_agent"
                                            for node in nodes)):
                raise WorkflowPlanError("independent plan must have 2-4 root LLM nodes")
        except WorkflowPlanError as exc:
            rejection = str(exc)
            continue
        return nodes, {
            "provider": response["provider"], "model": response["model"],
            "response_id": response["response_id"],
            "prompt_digest": response.get("prompt_digest"),
            "attempts": attempt,
        }
    raise WorkflowPlanError(f"planner output invalid after 3 attempts: {rejection}")


def execute_registered_node(node, deps):
    if node.tool == "safe_expression":
        from .agent_runtime import _safe_expression
        return _safe_expression(node.task)
    if node.tool == "local_mcp_tool_registry.sha256":
        from .agent_runtime import _mcp_tool_call
        value = json.dumps(deps, sort_keys=True) if deps else node.task
        return _mcp_tool_call("sha256", {"value": value})
    if node.tool == "llm_agent":
        from .agent_runtime import _invoke_llm
        response = _invoke_llm(node.id, node.task, {"upstream_results": deps})
        if (not response or response.get("invocation_type") != "real_llm"
                or not response.get("response_id") or not response.get("output")):
            raise WorkflowPlanError("real subagent execution and response provenance required")
        return {"output": response["output"], "provider": response["provider"],
                "model": response["model"], "response_id": response["response_id"]}
    raise WorkflowPlanError("tool not permitted by workflow executor")


def run_nina_workflow(*, tenant_id, requester_id, goal, allowed_tools, append,
                      planner=model_plan, executor=execute_registered_node,
                      fetch_records=None, require_overlap=False, expected_provider=None):
    # Preflight the execution boundary before planner calls or DAG effects.
    if not isinstance(requester_id, str) or not requester_id.strip():
        raise WorkflowPlanError("authenticated workflow principal required")
    raw_key = os.getenv("OLA_CAPABILITY_VOUCHER_KEY_HEX")
    if not isinstance(raw_key, str) or not raw_key:
        raise WorkflowPlanError("capability voucher key unavailable")
    try:
        secret = bytes.fromhex(raw_key)
    except (ValueError, TypeError):
        raise WorkflowPlanError("capability voucher key encoding invalid") from None
    if len(secret) < 32:
        raise WorkflowPlanError("capability voucher key must contain at least 32 bytes")
    allowed_capabilities = {f"workflow.execute:{tool}" for tool in allowed_tools}
    test_scope = None
    try:
        if engine.dialect.name == "postgresql":
            replay_ledger = PostgresReplayLedger()
        elif engine.dialect.name == "sqlite" and os.getenv("OLA_ENVIRONMENT") == "test":
            # Local replay file is confined to explicit test mode.
            test_scope = tempfile.TemporaryDirectory(prefix="ola-nina-replay-test-")
            replay_ledger = SQLiteReplayLedger(
                os.path.join(test_scope.name, "replay.sqlite3")
            )
        else:
            raise WorkflowPlanError("shared durable replay ledger unavailable")
        issuer = VoucherIssuer(secret, allowed_capabilities)
        verifier = VoucherVerifier(secret, allowed_capabilities, replay_ledger=replay_ledger)
    except WorkflowPlanError:
        if test_scope is not None:
            test_scope.cleanup()
        raise
    except Exception as exc:
        if test_scope is not None:
            test_scope.cleanup()
        raise WorkflowPlanError(f"capability enforcement unavailable: {type(exc).__name__}") from None

    run_id = str(uuid.uuid4())
    try:
        nodes, provenance = planner(goal, tuple(allowed_tools))
        nodes = validate_plan({"nodes": [
            {"id": n.id, "tool": n.tool, "task": n.task, "needs": list(n.needs)}
            for n in nodes]}, allowed_tools=set(allowed_tools))
        evidence_ids = []

        def record(event):
            payload = {**event, "requester_id": requester_id, "planner": provenance,
                       "commit": os.getenv("OLA_RUNTIME_COMMIT", "UNKNOWN")}
            saved = append(tenant_id, event["event"], payload)
            if not isinstance(saved, dict) or not saved.get("id"):
                raise RuntimeError("evidence write was not confirmed")
            evidence_ids.append(saved["id"])

        def execute_authorized_node(node, deps):
            capability = f"workflow.execute:{node.tool}"
            arguments = {
                "node_id": node.id, "tool": node.tool,
                "task_digest": hashlib.sha256(node.task.encode("utf-8")).hexdigest(),
                "dependency_digest": hashlib.sha256(
                    canonical_json(deps).encode("utf-8")
                ).hexdigest(),
            }
            request = ExecutionRequest(
                run_id=run_id, tenant_id=tenant_id, principal_id=requester_id,
                capability=capability, arguments=arguments,
                policy_version="nina-workflow-capability-v1",
            )
            voucher = issuer.issue(request)
            verifier.verify_and_consume(voucher, request)
            record({
                "event": "execution.capability.authorized",
                "run_id": run_id, "node_id": node.id, "capability": capability,
                "voucher_id": voucher.voucher_id,
                "arguments_digest": voucher.arguments_digest,
                "policy_version": voucher.policy_version,
                "decision": "ALLOW",
            })
            return executor(node, deps)

        result = WorkflowEngine(max_workers=4).run(
            nodes, execute_authorized_node, record, run_id=run_id
        )
        from .igor_workflow import verify_dag_records
        igor = {"status": "UNKNOWN", "reason": "independent evidence reader not configured"}
        if fetch_records is not None:
            igor = verify_dag_records(
                fetch_records(tenant_id), tenant_id=tenant_id, run_id=result["run_id"],
                expected_commit=os.getenv("OLA_RUNTIME_COMMIT") or None,
                require_overlap=require_overlap, expected_provider=expected_provider,
            )
        final_status = result["status"] if igor["status"] in ("VERIFIED", "UNKNOWN") else "BLOCK"
        return {**result, "status": final_status, "tenant_id": tenant_id, "planner": provenance,
                "evidence_ids": evidence_ids, "igor": igor, "human_gate": "NOT_APPROVED",
                "verified": False}
    finally:
        if test_scope is not None:
            test_scope.cleanup()
