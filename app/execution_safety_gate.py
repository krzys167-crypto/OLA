from dataclasses import dataclass
from typing import Any, Callable, Collection, FrozenSet, Mapping, Optional


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

    def __init__(
        self,
        allowed_actions: Optional[set[str]] = None,
        agent_actions: Optional[Mapping[str, Collection[str]]] = None,
    ):
        if allowed_actions is None:
            allowed_actions = set()
        # a bare string would silently become a set of single characters ("read" -> {"r","e","a","d"})
        if isinstance(allowed_actions, (str, bytes)) or not all(type(a) is str for a in allowed_actions):
            raise TypeError("allowed_actions must be a collection of str")
        self._allowed_actions: FrozenSet[str] = frozenset(allowed_actions)

        # Optional per-agent narrowing. Without it, any non-empty agent_id may run any globally allowed action.
        # With it, an agent runs only the actions listed for it (and only if they are also globally allowed);
        # an agent that is not listed runs nothing.
        self._agent_actions: Optional[dict[str, FrozenSet[str]]] = None
        if agent_actions is not None:
            if not isinstance(agent_actions, Mapping):
                raise TypeError("agent_actions must be a mapping of agent_id -> collection of str")
            narrowed: dict[str, FrozenSet[str]] = {}
            for agent, actions in agent_actions.items():
                if type(agent) is not str or not agent:
                    raise TypeError("agent_actions keys must be non-empty str")
                if isinstance(actions, (str, bytes)) or not all(type(a) is str for a in actions):
                    raise TypeError("agent_actions values must be collections of str")
                narrowed[agent] = frozenset(actions)
            self._agent_actions = narrowed

    def execute(
        self,
        *,
        agent_id: str,
        action: str,
        effect: Callable[[], Any],
        risk: str = "LOW",
        human_approved: bool = False,
    ) -> ExecutionDecision:
        # Identity first: an anonymous or malformed agent_id never executes and is not routed to a human either.
        if type(agent_id) is not str or not agent_id.strip():
            return ExecutionDecision(status="BLOCK")
        if self._agent_actions is not None and agent_id not in self._agent_actions:
            return ExecutionDecision(status="BLOCK")

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
        if self._agent_actions is not None and action not in self._agent_actions[agent_id]:
            return ExecutionDecision(status="BLOCK")

        result = effect()
        return ExecutionDecision(
            status="ALLOW",
            side_effect_count=1,
            result=result,
        )
