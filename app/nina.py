from dataclasses import dataclass
import uuid

from .agent_runtime import run_agent_task


REGISTERED_TOOLS = ("safe_expression", "local_mcp_tool_registry.sha256")


@dataclass(frozen=True)
class NinaTask:
    task_id: str
    tenant_id: str
    task: str
    requested_tools: tuple[str, ...]

    @classmethod
    def create(cls, tenant_id: str, task: str, requested_tools: list[str] | tuple[str, ...]):
        if not isinstance(task, str) or not task.strip():
            raise ValueError("task is required")
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            raise ValueError("tenant_id is required")
        if not isinstance(requested_tools, (list, tuple)):
            raise ValueError("requested_tools must be a list")
        return cls(
            task_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            task=task.strip(),
            requested_tools=tuple(requested_tools),
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
        # a tool name that is not a string is never registered (and must not break the message below)
        unknown = tuple(tool for tool in task.requested_tools if tool not in self._registered_tools)
        if unknown:
            return NinaDecision(
                status="BLOCK",
                reason=f"unknown tool: {', '.join(tool if isinstance(tool, str) else repr(tool) for tool in unknown)}",
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
        runtime = run_agent_task(task.tenant_id, task.task)
        return {
            "task_id": task.task_id,
            "decision": decision,
            "status": runtime.get("status", "UNKNOWN"),
            "runtime": runtime,
        }
