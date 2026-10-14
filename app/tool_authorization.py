"""Per-run tool scope, checked immediately before registered tool dispatch.

In-process enforcement only: not a sandbox or a durable one-time permit.
"""
from dataclasses import dataclass

REGISTERED_TOOLS = ("safe_expression", "local_mcp_tool_registry.sha256")


class ToolAuthorizationError(ValueError):
    pass


@dataclass(frozen=True)
class ToolScope:
    tenant_id: str
    task: str
    allowed: frozenset[str]

    @classmethod
    def create(cls, tenant_id, task, allowed):
        if not isinstance(allowed, (list, tuple, frozenset)) or any(
            not isinstance(tool, str) or tool not in REGISTERED_TOOLS for tool in allowed
        ):
            raise ToolAuthorizationError("invalid tool scope")
        return cls(tenant_id, task, frozenset(allowed))

    def require(self, tool, tenant_id, task):
        if tenant_id != self.tenant_id or task != self.task or tool not in self.allowed:
            raise ToolAuthorizationError("tool outside authorized scope")

    def preflight(self):
        # This fixed pipeline requires BOTH tools. Do not silently widen a request.
        if self.allowed != frozenset(REGISTERED_TOOLS):
            raise ToolAuthorizationError("fixed pipeline requires both registered tools")
