from dataclasses import dataclass


@dataclass(frozen=True)
class ReviewDecision:
    approved: bool
    actor: str
    reason: str


@dataclass(frozen=True)
class GateResult:
    status: str
    reason: str


class HumanGate:
    @staticmethod
    def evaluate(candidate_status: str, decision: ReviewDecision) -> GateResult:
        if not isinstance(decision.actor, str) or not decision.actor.strip():
            return GateResult("BLOCK", "review actor is required")
        # only a real boolean True approves: "false", "no", 1 or [] are truthy/falsy accidents, not decisions
        if decision.approved is not True:
            reason = decision.reason if isinstance(decision.reason, str) else ""
            return GateResult("BLOCK", reason or "review rejected")
        if candidate_status != "VERIFIED":
            return GateResult("BLOCK", f"cannot promote {candidate_status} to VERIFIED")
        return GateResult("VERIFIED", "human review confirmed verified candidate")
