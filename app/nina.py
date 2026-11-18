from dataclasses import dataclass
import uuid

from .agent_runtime import run_agent_task


# Generic tools are executed by run_agent_task. Dedicated capabilities have their
# own bounded dispatcher and must never fall through to the generic agent runtime.
REGISTERED_TOOLS = ("safe_expression", "local_mcp_tool_registry.sha256")
REGISTERED_CAPABILITIES = ("blogger.read_metadata",)


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
        if any(not isinstance(tool, str) or not tool.strip() for tool in requested_tools):
            raise ValueError("requested_tools entries must be non-empty strings")
        if len(set(requested_tools)) != len(requested_tools):
            raise ValueError("requested_tools must not contain duplicates")
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
    """Bounded orchestration facade over OLA's generic and dedicated capabilities.

    A dedicated capability is registered centrally but can only be invoked by
    its dedicated dispatcher; it is never executed by the generic agent runtime.
    """

    def __init__(self, registered_tools: tuple[str, ...] | None = None):
        self._registered_tools = tuple(
            REGISTERED_TOOLS + REGISTERED_CAPABILITIES
            if registered_tools is None else registered_tools
        )

    def plan(self, task: NinaTask) -> NinaDecision:
        unknown = tuple(tool for tool in task.requested_tools if tool not in self._registered_tools)
        if unknown:
            return NinaDecision(
                status="BLOCK",
                reason=f"unknown tool: {', '.join(repr(tool) for tool in unknown)}",
                allowed_tools=(),
            )
        return NinaDecision(
            status="ALLOW",
            reason="all requested tools are centrally registered",
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
        dedicated = tuple(tool for tool in decision.allowed_tools if tool in REGISTERED_CAPABILITIES)
        if dedicated:
            return {
                "task_id": task.task_id,
                "decision": decision,
                "status": "DISPATCH_REQUIRED",
                "reason": "dedicated capabilities must use their registered bounded dispatcher",
                "capabilities": dedicated,
            }
        runtime = run_agent_task(task.tenant_id, task.task)
        return {
            "task_id": task.task_id,
            "decision": decision,
            "status": runtime.get("status", "UNKNOWN"),
            "runtime": runtime,
        }
