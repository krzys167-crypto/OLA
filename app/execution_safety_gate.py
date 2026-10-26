from dataclasses import dataclass
from typing import Any, Callable, FrozenSet, Optional


@dataclass(frozen=True)
class ExecutionDecision:
    status: str
    policy: str = "deny-by-default"
    side_effect_count: int = 0
    required_approval: Optional[str] = None
    result: Any = None


class ExecutionSafetyGate:
    """Fail-closed execution gate: unknown actions never execute."""

    def __init__(self, allowed_actions: Optional[set[str]] = None):
        self._allowed_actions: FrozenSet[str] = frozenset(allowed_actions or set())

    def execute(
        self,
        *,
        agent_id: str,
        action: str,
        effect: Callable[[], Any],
        risk: str = "LOW",
        human_approved: bool = False,
    ) -> ExecutionDecision:
        # agent_id is part of the execution contract even though this minimal
        # gate does not yet maintain an agent registry.
        _ = agent_id

        # A caller-controlled boolean is NOT an authenticated, action-bound
        # Human Gate approval. Deny high-risk execution until a trusted
        # approval verifier is integrated at this execution boundary.
        if not isinstance(risk, str) or risk.upper() not in {"LOW", "MEDIUM", "HIGH"}:
            return ExecutionDecision(status="BLOCK")
        if risk.upper() == "HIGH":
            return ExecutionDecision(
                status="REVIEW",
                required_approval="HUMAN_OWNER",
            )

        if action not in self._allowed_actions:
            return ExecutionDecision(status="BLOCK")

        result = effect()
        return ExecutionDecision(
            status="ALLOW",
            side_effect_count=1,
            result=result,
        )
