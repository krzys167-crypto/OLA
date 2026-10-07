from app.decision_fabric import DecisionFabric, DecisionPolicy


class FakeProvider:
    name = "fake"

    def __init__(self, body):
        self.body = body

    def evaluate(self, *, state, questions, model):
        return {"body": self.body, "request_id": "req-test-1"}


QUESTIONS = {
    "route": {
        "type": "choice",
        "instructions": "Which route?",
        "criteria": {"audit": "Evidence audit", "block": "Unsafe"},
    },
    "risk": {
        "type": "score",
        "instructions": "How risky is this?",
        "criteria": ["low", "medium", "high"],
    },
    "needs_human": {
        "type": "noul",
        "instructions": "Does this require human review?",
    },
}


def test_current_typed_contract_and_hashes():
    provider = FakeProvider({
        "model": "jev-1.13.0",
        "answers": {
            "route": {"type": "choice", "choice": "audit", "probabilities": {"audit": 0.92, "block": 0.08}, "confidence": 0.92},
            "risk": {"type": "score", "score": 0.9, "legend": {"0": "low", "1": "medium", "2": "high"}, "probabilities": {"0": 0.9, "1": 0.08, "2": 0.02}, "confidence": 0.91},
            "needs_human": {"type": "noul", "noul": 0.91},
        },
        "usage": {"input_tokens": 120, "output_tokens": 12},
    })
    result = DecisionFabric(provider=provider).evaluate(state={"task": "audit evidence"}, questions=QUESTIONS)
    assert result.status == "READY"
    assert result.model == "jev-1.13.0"
    assert result.request_sha256 and result.response_sha256
    assert result.request_id == "req-test-1"
    assert result.usage == {"input_tokens": 120, "output_tokens": 12}
    assert DecisionFabric(provider=provider).classify(result) == {"route": "ACCEPT", "risk": "ACCEPT", "needs_human": "YES"}


def test_noul_has_no_confidence_field():
    policy = DecisionPolicy()
    assert policy.classify({"type": "noul", "noul": 0.50}) == "REVIEW"
    assert policy.classify({"type": "noul", "noul": 0.79}) == "REVIEW"
    assert policy.classify({"type": "noul", "noul": 0.20}) == "NO"


def test_missing_provider_blocks_without_fallback():
    class Broken:
        name = "broken"
        def evaluate(self, **kwargs):
            raise RuntimeError("missing credential")
    result = DecisionFabric(provider=Broken()).evaluate(
        state={"task": "x"}, questions={"ok": {"type": "noul", "instructions": "Is it safe?"}}
    )
    assert result.status == "BLOCK"
    assert "failure" in result.reason
    assert DecisionFabric(provider=Broken()).classify(result) == {}


def test_mismatched_answers_block():
    provider = FakeProvider({"model": "jev-1.13.0", "answers": {"other": {"type": "noul", "noul": 1.0}}})
    result = DecisionFabric(provider=provider).evaluate(
        state={}, questions={"expected": {"type": "noul", "instructions": "Is it valid?"}}
    )
    assert result.status == "BLOCK"
    assert "failure" in result.reason


def test_score_criteria_must_be_ordered_sequence():
    result = DecisionFabric(provider=FakeProvider({})).evaluate(
        state={}, questions={"risk": {"type": "score", "instructions": "Risk?", "criteria": {"low": "low", "high": "high"}}}
    )
    assert result.status == "BLOCK"


def test_malformed_answer_blocks():
    provider = FakeProvider({"model": "jev-1.13.0", "answers": {
        "route": {"type": "choice", "choice": "audit", "probabilities": {"audit": 1.0}, "confidence": 1.0}
    }})
    result = DecisionFabric(provider=provider).evaluate(
        state={}, questions={"route": {"type": "choice", "instructions": "Route?", "criteria": {"audit": None, "block": None}}}
    )
    assert result.status == "BLOCK"


def test_noul_requires_instruction_or_outcome_criteria():
    provider = FakeProvider({"model": "jev-1.13.0", "answers": {"ok": {"type": "noul", "noul": 0.9}}})
    result = DecisionFabric(provider=provider).evaluate(state={}, questions={"ok": {"type": "noul"}})
    assert result.status == "BLOCK"


def test_noul_can_use_true_false_criteria_without_instruction():
    provider = FakeProvider({"model": "jev-1.13.0", "answers": {"ok": {"type": "noul", "noul": 0.9}}})
    result = DecisionFabric(provider=provider).evaluate(
        state={},
        questions={"ok": {"type": "noul", "criteria": {"true": "yes", "false": "no"}}},
    )
    assert result.status == "READY"


def test_state_null_blocks_before_provider():
    provider = FakeProvider({})
    result = DecisionFabric(provider=provider).evaluate(
        state=None, questions={"ok": {"type": "noul", "instructions": "Is it valid?"}}
    )
    assert result.status == "BLOCK"


def test_score_probability_keys_and_legend_are_exact():
    provider = FakeProvider({"model": "jev-1.13.0", "answers": {
        "risk": {
            "type": "score", "score": 1.5, "confidence": 0.9,
            "probabilities": {"0": 0.1, "2": 0.9},
            "legend": {"0": "low", "1": "medium", "2": "high"},
        }
    }})
    result = DecisionFabric(provider=provider).evaluate(
        state={}, questions={"risk": {"type": "score", "instructions": "Risk?", "criteria": ["low", "medium", "high"]}}
    )
    assert result.status == "BLOCK"
