from dataclasses import dataclass
import uuid

from .agent_runtime import run_agent_task


REGISTERED_TOOLS = ("safe_expression", "local_mcp_tool_registry.sha256", "llm_agent")


@dataclass(frozen=True)
class NinaTask:
    task_id: str
    tenant_id: str
    task: str
    requested_tools: tuple[str, ...]
    principal_id: str | None = None

    @classmethod
    def create(cls, tenant_id: str, task: str, requested_tools: list[str] | tuple[str, ...],
               principal_id: str | None = None):
        if not isinstance(task, str) or not task.strip():
            raise ValueError("task is required")
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            raise ValueError("tenant_id is required")
        if principal_id is not None and (
            not isinstance(principal_id, str) or not principal_id.strip()
        ):
            raise ValueError("principal_id must be nonempty when provided")
        return cls(
            task_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            task=task.strip(),
            requested_tools=tuple(requested_tools),
            principal_id=principal_id,
        )


@dataclass(frozen=True)
class NinaDecision:
    status: str
    reason: str
    allowed_tools: tuple[str, ...]


class NinaOrchestrator:
    """Bounded orchestration facade over the existing OLA runtime.

    NINA decides which registered capabilities may be requested. It does not
    manufacture verification and it does not bypass the OLA execution gate.
    """

    def __init__(self, registered_tools: tuple[str, ...] = REGISTERED_TOOLS):
        self._registered_tools = tuple(registered_tools)

    def plan(self, task: NinaTask) -> NinaDecision:
        unknown = tuple(tool for tool in task.requested_tools if tool not in self._registered_tools)
        if unknown:
            return NinaDecision(
                status="BLOCK",
                reason=f"unknown tool: {', '.join(unknown)}",
                allowed_tools=(),
            )
        return NinaDecision(
            status="ALLOW",
            reason="all requested tools are registered",
            allowed_tools=task.requested_tools,
        )

    def execute(self, task: NinaTask):
        decision = self.plan(task)
        if decision.status != "ALLOW":
            return {
                "task_id": task.task_id,
                "decision": decision,
                "status": "BLOCK",
                "reason": decision.reason,
            }
        runtime = run_agent_task(task.tenant_id, task.task, task.principal_id)
        status = runtime.get("status", "UNKNOWN")
        # The legacy six-agent executor can fall back to a deterministic model.
        # That trace may be internally consistent, but is not evidence that an
        # explicitly requested LLM capability actually ran.
        if "llm_agent" in task.requested_tools:
            events = runtime.get("execution")
            if (not isinstance(events, list) or not events
                    or any(not isinstance(event, dict)
                           or event.get("invocation_type") != "real_llm"
                           or not isinstance(event.get("response_id"), str)
                           or not event["response_id"]
                           for event in events)):
                status = "BLOCK"
        return {
            "task_id": task.task_id,
            "decision": decision,
            "status": status,
            "runtime": runtime,
        }
