from app.human_gate import HumanGate, ReviewDecision
from app.nina_igor import NinaIgorChain


def test_chain_blocks_when_igor_is_unknown():
    chain = NinaIgorChain()
    result = chain.finalize(
        nina_status="VERIFIED",
        igor_status="UNKNOWN",
        review=ReviewDecision(True, "reviewer-1", "reviewed"),
    )
    assert result["status"] == "BLOCK"
    assert result["reason"] == "igor verification is UNKNOWN"


def test_chain_requires_igor_before_human_gate():
    chain = NinaIgorChain()
    result = chain.finalize(
        nina_status="VERIFIED",
        igor_status="VERIFIED",
        review=ReviewDecision(True, "reviewer-1", "reviewed"),
    )
    assert result["status"] == "VERIFIED"


def test_chain_rejects_human_review():
    chain = NinaIgorChain()
    result = chain.finalize(
        nina_status="VERIFIED",
        igor_status="VERIFIED",
        review=ReviewDecision(False, "reviewer-1", "unsafe"),
    )
    assert result["status"] == "BLOCK"


STATUS_FIELDS = (
    "RUNTIME",
    "EVIDENCE",
    "REPLAY_INTEGRITY",
    "POLICY",
    "HUMAN_GATE",
    "EXECUTION_ALLOWED",
)

NON_VERIFIED_STATUSES = ("NOT_RUN", "REVIEW", "UNKNOWN")


def test_derive_status_is_verified_only_when_every_field_is_verified():
    status = {field: "VERIFIED" for field in STATUS_FIELDS}
    assert NinaIgorChain.derive_status(status) == "VERIFIED"


def test_derive_status_rejects_unknown_status_value():
    status = {field: "VERIFIED" for field in STATUS_FIELDS}
    status["POLICY"] = "NOT_A_STATUS"
    assert NinaIgorChain.derive_status(status) == "BLOCK"


def test_derive_status_is_fail_closed_for_every_non_verified_field():
    for field in STATUS_FIELDS:
        for value in NON_VERIFIED_STATUSES:
            status = {name: "VERIFIED" for name in STATUS_FIELDS}
            status[field] = value
            assert NinaIgorChain.derive_status(status) != "VERIFIED", (
                f"{field}={value} incorrectly derived VERIFIED"
            )
