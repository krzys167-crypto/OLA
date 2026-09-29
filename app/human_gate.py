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
        if candidate_status == "BLOCK":
            return GateResult("BLOCK", "candidate is BLOCK")
        if not decision.approved:
            return GateResult("REVIEW", decision.reason or "human approval required before promotion")
        if not decision.actor.strip():
            return GateResult("BLOCK", "review actor is required")
        if candidate_status != "VERIFIED":
            return GateResult("BLOCK", f"cannot promote {candidate_status} to VERIFIED")
        return GateResult("VERIFIED", "human review confirmed verified candidate")
