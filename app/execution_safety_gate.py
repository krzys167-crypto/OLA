from dataclasses import dataclass
from typing import Any, Callable, FrozenSet, Optional


_RISKS = frozenset({"LOW", "MEDIUM", "HIGH"})


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
        if allowed_actions is None:
            allowed_actions = set()
        # a bare string would silently become a set of single characters ("read" -> {"r","e","a","d"})
        if isinstance(allowed_actions, (str, bytes)) or not all(type(a) is str for a in allowed_actions):
            raise TypeError("allowed_actions must be a collection of str")
        self._allowed_actions: FrozenSet[str] = frozenset(allowed_actions)

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

        # Unknown input never executes: a risk label outside the known set (typo, None, zero-width character)
        # is a BLOCK, not an implicit "not HIGH".
        if type(risk) is not str or risk.upper() not in _RISKS:
            return ExecutionDecision(status="BLOCK")

        # High-risk actions require explicit human-owner approval (the JSON/Python boolean True, nothing truthy)
        # before any allow-list check can result in execution.
        if risk.upper() == "HIGH" and human_approved is not True:
            return ExecutionDecision(
                status="REVIEW",
                required_approval="HUMAN_OWNER",
            )

        if type(action) is not str or action not in self._allowed_actions:
            return ExecutionDecision(status="BLOCK")

        result = effect()
        return ExecutionDecision(
            status="ALLOW",
            side_effect_count=1,
            result=result,
        )
