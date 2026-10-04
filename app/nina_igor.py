from .human_gate import HumanGate, ReviewDecision


STATUS_VALUES = frozenset({
    "UNKNOWN",
    "NOT_RUN",
    "VERIFIED",
    "REVIEW",
    "BLOCK",
})

STATUS_FIELDS = (
    "RUNTIME",
    "EVIDENCE",
    "REPLAY_INTEGRITY",
    "POLICY",
    "HUMAN_GATE",
)

_STATUS_PRECEDENCE = {
    "BLOCK": 4,
    "UNKNOWN": 3,
    "NOT_RUN": 2,
    "REVIEW": 1,
    "VERIFIED": 0,
}


class NinaIgorChain:
    """Terminal decision boundary: NINA proposes, IGOR verifies, human confirms."""

    @staticmethod
    def derive_status(statuses: dict[str, str]) -> str:
        if set(statuses) != set(STATUS_FIELDS):
            return "BLOCK"
        values = tuple(statuses[field] for field in STATUS_FIELDS)
        if any(not isinstance(value, str) or value not in STATUS_VALUES for value in values):
            return "BLOCK"
        if all(value == "VERIFIED" for value in values):
            return "VERIFIED"
        return max(values, key=lambda value: _STATUS_PRECEDENCE[value])

    @staticmethod
    def finalize(nina_status: str, igor_status: str, review: ReviewDecision):
        if nina_status != "VERIFIED":
            return {"status": "BLOCK", "reason": f"nina status is {nina_status}"}
        if igor_status == "UNKNOWN":
            return {"status": "BLOCK", "reason": "igor verification is UNKNOWN"}
        if igor_status != "VERIFIED":
            return {"status": "BLOCK", "reason": f"igor verification is {igor_status}"}
        gate = HumanGate.evaluate(igor_status, review)
        return {"status": gate.status, "reason": gate.reason}
