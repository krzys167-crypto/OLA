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


def test_chain_requires_human_review():
    chain = NinaIgorChain()
    result = chain.finalize(
        nina_status="VERIFIED",
        igor_status="VERIFIED",
        review=ReviewDecision(False, "reviewer-1", "awaiting approval"),
    )
    assert result["status"] == "REVIEW"


def test_human_gate_candidate_block_wins_before_approval_state():
    result = HumanGate.evaluate(
        "BLOCK",
        ReviewDecision(False, "reviewer-1", "awaiting approval"),
    )
    assert result.status == "BLOCK"


STATUS_FIELDS = (
    "RUNTIME",
    "EVIDENCE",
    "REPLAY_INTEGRITY",
    "POLICY",
)

NON_VERIFIED_STATUSES = ("NOT_RUN", "REVIEW", "UNKNOWN")


def test_derive_status_is_verified_only_when_every_input_field_is_verified():
    status = {field: "VERIFIED" for field in STATUS_FIELDS}
    assert NinaIgorChain.derive_status(status) == "VERIFIED"


def test_derive_status_rejects_execution_allowed_as_an_input():
    status = {field: "VERIFIED" for field in STATUS_FIELDS}
    status["EXECUTION_ALLOWED"] = "VERIFIED"
    assert NinaIgorChain.derive_status(status) == "BLOCK"


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


def test_derive_status_rejects_missing_field():
    status = {field: "VERIFIED" for field in STATUS_FIELDS}
    del status["EVIDENCE"]
    assert NinaIgorChain.derive_status(status) == "BLOCK"
