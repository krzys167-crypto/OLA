"""Sixth review, ola_pipeline library: the judge is held to Nina's standard, evaluations follow from the judge's
raw reply, one definition of "the same model", bounded policy and scores, a checked iteration chain, secret
scanning that is neither blind nor quadratic, one numeric typing rule, a parsed loopback test, and a failed
finalize that still verifies.

Sessions are either forged through the real vault (forge_session) or produced by the pipeline against a fake Ollama
that presents itself as a live runtime (`fake.version = "0.99.0"`: logic only, the proof kind is OLLAMA_OBSERVED).
"""
import ast
import json
import shutil
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path

import pytest

from fake_ollama import FakeOllama
from forge_session import DIG, IGOR_DIG, env as forge_env, reply, session
from pipeline_helpers import igor_json
from ola_pipeline import Pipeline, Policy, providers, verify, verify_session
from ola_pipeline import igor as igor_mod
from ola_pipeline.config import ProviderConfig
from ola_pipeline.errors import ConfigError, ProviderTimeout, ProviderUnavailable
from ola_pipeline.igor import Igor, parse_judge
from ola_pipeline.redact import contains_secret, scrub
from ola_pipeline.vault import EvidenceVault
from ola_pipeline.verify import same_model

REPO = Path(__file__).resolve().parents[2]
TASK = "State the capital of France in one sentence."
NINA_DIGEST = "a1b2c3d4" * 8


def cli(*args):
    return subprocess.run([sys.executable, "-m", "ola_pipeline", *args], capture_output=True, text=True, cwd=str(REPO))


def unlock(path):
    import os
    for p in [path, *Path(path).rglob("*")]:
        os.chmod(p, 0o755 if Path(p).is_dir() else 0o644)


def reasons(rep):
    return " | ".join(rep["recomputed"]["reasons"])


def live(fake):
    fake.version = "0.99.0"          # not a declared test double -> OLLAMA_OBSERVED (protocol/logic only)


def run_live(fake, make_cfg, judge, *, nina="Paris is the capital of France.", policy=None, igor="igor-test"):
    live(fake)
    fake.script("nina-test", nina)
    fake.script(igor, judge)
    r = Pipeline(make_cfg(policy=policy or Policy(), igor_model=igor)).run(TASK)
    return r, verify_session(r.session_dir)


# ======================================================================================================== 1
# The judge's and the canary's generations pass the same runtime-proof / provenance checks as Nina's.
@pytest.mark.parametrize("proof, text", [({"kind": "TEST_DOUBLE"}, "TEST_DOUBLE"), ({"kind": "MOCK"}, "unrecognised"),
                                         ({"note": "no kind"}, "unrecognised")],
                         ids=["test-double", "unknown-kind", "no-kind"])
def test_a_judge_generation_must_pass_the_same_proof_checks_as_nina(tmp_path, proof, text):
    v, _ = session(tmp_path, igors=[{"proof": proof}])
    r = verify_session(v.dir)
    assert r["overall"] != "VERIFIED" and r["recomputed"]["state"] == "BLOCKED", r["recomputed"]
    assert r["recomputed"]["igor_status"] == "UNAVAILABLE" and text in reasons(r), reasons(r)


def test_a_judge_from_an_unknown_provider_is_refused(tmp_path):
    v, _ = session(tmp_path, igors=[{"provider": "mock"}])
    r = verify_session(v.dir)
    assert r["overall"] != "VERIFIED" and "unknown provider" in reasons(r), reasons(r)


def test_judge_provenance_is_checked_like_ninas():
    e = {"provider": "ollama-local", "model": "m", "model_digest": None}
    problem = verify._generation_problem("OLLAMA_OBSERVED", e, {}, "Igor judge")
    assert problem and problem.startswith("Igor judge: provenance incomplete") and "run_id" in problem
    full = {k: "x" for k in verify.REQUIRED_PROVENANCE}
    full.update(provider="ollama-local", model="m", model_digest=None, parent_run_id=None)
    assert verify._generation_problem("OLLAMA_OBSERVED", full, {}, "w") is None
    assert verify._generation_problem("TEST_DOUBLE", full, {}, "w")
    assert verify._generation_problem("TEST_DOUBLE", full, {"allow_test_double": True}, "w") is None


def test_a_judge_test_double_needs_the_explicit_opt_in_and_never_counts_as_live(tmp_path):
    v, _ = session(tmp_path, policy=Policy(allow_test_double=True), igors=[{"proof": {"kind": "TEST_DOUBLE"}}])
    r = verify_session(v.dir)
    rc = r["recomputed"]
    assert rc["state"] == "PASS" and rc["igor_status"] == "PASS_UNATTESTED" and rc["evidence_class"] == "TEST_DOUBLE"
    assert r["overall"] == "PARTIAL" and r["failures"] == []


@pytest.mark.parametrize("proof, text", [({"kind": "TEST_DOUBLE"}, "TEST_DOUBLE"), ({"kind": "MOCK"}, "unrecognised")],
                         ids=["test-double", "unknown-kind"])
def test_a_canary_generation_must_pass_the_same_proof_checks(tmp_path, proof, text):
    v, _ = session(tmp_path, canaries=[{"proof": proof}])
    r = verify_session(v.dir)
    assert r["overall"] != "VERIFIED" and r["recomputed"]["igor_status"] == "UNCALIBRATED", r["recomputed"]
    assert text in reasons(r), reasons(r)


def test_a_canary_test_double_with_the_opt_in_is_never_live(tmp_path):
    v, _ = session(tmp_path, policy=Policy(allow_test_double=True), canaries=[{"proof": {"kind": "TEST_DOUBLE"}}])
    r = verify_session(v.dir)
    assert r["recomputed"]["igor_status"] == "PASS_UNATTESTED" and r["overall"] == "PARTIAL"


@pytest.fixture
def live_nina():
    f = FakeOllama().start()
    f.version = "0.99.0"
    f.add_model("nina-test", digest=NINA_DIGEST)
    f.script("nina-test", "Paris is the capital of France.")
    yield f
    f.stop()


def test_end_to_end_a_judge_on_a_declared_test_double_cannot_pass_a_live_nina(fake, live_nina, make_cfg):
    fake.script("igor-test", igor_json("PASS", 92))                     # `fake` declares itself a test double
    r = Pipeline(make_cfg(nina_url=live_nina.url, policy=Policy())).run(TASK)
    assert r.final["gate_state"] == "BLOCKED" and r.final["igor_status"] == "UNAVAILABLE", r.final
    assert any("TEST_DOUBLE" in x for x in r.final["gate_reasons"]), r.final["gate_reasons"]
    rep = verify_session(r.session_dir)
    assert rep["failures"] == [] and rep["overall"] == "CONSISTENT", rep


def test_end_to_end_with_the_opt_in_a_double_judge_is_attested_as_such(fake, live_nina, make_cfg):
    fake.script("igor-test", igor_json("PASS", 92))
    r = Pipeline(make_cfg(nina_url=live_nina.url, policy=Policy(allow_test_double=True))).run(TASK)
    assert r.final["gate_state"] == "PASS" and r.final["igor_status"] == "PASS_UNATTESTED", r.final
    assert r.final["evidence_class"] == "TEST_DOUBLE"
    rep = verify_session(r.session_dir)
    assert rep["failures"] == [] and rep["overall"] == "PARTIAL", rep


# ======================================================================================================== 2
# Each stored evaluation is tied to the judge's RAW reply, parsed by the pipeline's own parse_judge.
def test_the_verifier_and_the_pipeline_share_one_parser():
    assert igor_mod.parse_judge is verify.parse_judge and parse_judge is verify.parse_judge


@pytest.mark.parametrize("kw, text", [
    ({"reply": reply("BLOCK", 5)}, "less strict"),
    ({"reply": reply("REVIEW", 92)}, "less strict"),
    ({"reply": reply("PASS", 80)}, "quality_score does not match"),
    ({"reply": reply("PASS", 92, ["fix it"])}, "required_corrections do not match"),
    ({"reply": b'{"decision": "BLOCK", "quality_score": 5, "decision": "PASS", "findings": [], '
               b'"required_corrections": [], "reason": "x"}'}, "duplicate key"),
    ({"reply": b"```json\n" + reply() + b"\n```"}, "not valid JSON"),
    ({"reply": b"I think it is fine."}, "not valid JSON"),
    ({"reply": b'{"decision": "PASS", "quality_score": "92", "findings": [], "required_corrections": [], '
               b'"reason": "x"}'}, "quality_score must be an integer"),
], ids=["raw-block", "raw-review", "other-score", "raw-has-corrections", "duplicate-keys", "fenced", "prose", "str-score"])
def test_an_evaluation_that_does_not_follow_from_the_judges_raw_reply_never_verifies(tmp_path, kw, text):
    v, _ = session(tmp_path, igors=[kw])
    r = verify_session(v.dir)
    assert r["overall"] != "VERIFIED" and r["recomputed"]["state"] == "BLOCKED", r["recomputed"]
    assert text in reasons(r), reasons(r)


@pytest.mark.parametrize("kw", [
    {"reply": reply("PASS", 100)}, {"reply": reply("BLOCK", 6)}, {"reply": b"```json\n" + reply("BLOCK", 5) + b"\n```"},
    {"reply": b'{"decision": "BLOCK", "quality_score": 5, "quality_score": 5, "findings": [], '
              b'"required_corrections": [], "reason": "x"}'},
], ids=["raw-pass", "other-score", "fenced", "duplicate-keys"])
def test_a_canary_evaluation_that_does_not_match_its_raw_reply_is_not_calibration(tmp_path, kw):
    v, _ = session(tmp_path, canaries=[kw])
    r = verify_session(v.dir)
    assert r["overall"] != "VERIFIED" and r["recomputed"]["igor_status"] == "UNCALIBRATED", r["recomputed"]
    assert "raw reply" in reasons(r), reasons(r)


def test_an_evaluation_stricter_than_the_raw_reply_is_not_an_inconsistency(tmp_path):
    # the pipeline turns PASS-with-open-corrections into REVIEW and may append a correction of its own
    v, _ = session(tmp_path, igors=[{"decision": "REVIEW", "score": 92, "corrections": ["fix it", "and this"],
                                     "reply": reply("PASS", 92, ["fix it"])}])
    r = verify_session(v.dir)
    assert r["failures"] == [] and r["recomputed"]["state"] == "REVIEW_REQUIRED" and "raw reply" not in reasons(r)


def test_a_session_whose_older_parser_refused_a_float_score_stays_a_consistent_block(tmp_path):
    # evaluation says INVALID_OUTPUT/BLOCK, the raw reply (float score) parses today: stricter, never flagged
    v, _ = session(tmp_path, igors=[{"decision": "BLOCK", "score": 0, "js": "INVALID_OUTPUT",
                                     "reply": reply("PASS", 92.0)}])
    r = verify_session(v.dir)
    assert r["failures"] == [] and r["overall"] == "CONSISTENT" and r["recomputed"]["state"] == "BLOCKED"


# --- messy replies from a live-looking model: accepted ones verify, refused ones are a consistent block
ACCEPTED = {
    "whitespace-extra-keys-unicode": "\n\n  " + json.dumps(
        {"decision": "PASS", "quality_score": 92, "findings": ["Paris ✓ 🇫🇷"], "required_corrections": [],
         "reason": "correct — väl", "confidence": 0.9}, ensure_ascii=False) + "  \n",
    "escaped-unicode": json.dumps({"decision": "PASS", "quality_score": 92, "findings": ["🇫🇷"],
                                   "required_corrections": [], "reason": "ok"}, ensure_ascii=True),
    "float-score": '{"decision": "PASS", "quality_score": 92.0, "findings": [], "required_corrections": [], "reason": "ok"}',
    "exponent-score": '{"decision": "PASS", "quality_score": 9.2e1, "findings": [], "required_corrections": [], "reason": "ok"}',
    "score-at-the-minimum": igor_json("PASS", 70),
    "score-100": igor_json("PASS", 100),
}


@pytest.mark.parametrize("judge", list(ACCEPTED.values()), ids=list(ACCEPTED))
def test_messy_but_accepted_judge_replies_verify_and_are_not_a_false_fail(fake, make_cfg, judge):
    r, rep = run_live(fake, make_cfg, judge)
    assert r.final["gate_state"] == "PASS", r.final["gate_reasons"]
    assert rep["failures"] == [] and rep["overall"] == "VERIFIED", rep


def test_a_reasoning_model_with_a_separate_thinking_field_verifies(fake, make_cfg):
    r, rep = run_live(fake, make_cfg, {"content": igor_json("PASS", 92), "thinking": "Weigh the answer. " * 120},
                      nina={"content": "Paris is the capital of France.", "thinking": "The user asks. " * 200})
    assert r.final["gate_state"] == "PASS", r.final["gate_reasons"]
    assert rep["failures"] == [] and rep["overall"] == "VERIFIED", rep


REFUSED = {
    "fenced": "```json\n" + igor_json("PASS", 92) + "\n```",
    "prose-around-json": "Here is my verdict:\n" + igor_json("PASS", 92) + "\nHope this helps!",
    "qwen3-inline-thinking": "<think>\nThe answer is Paris, so it is fine.\n</think>\n" + igor_json("PASS", 92),
    "duplicate-keys": '{"decision": "BLOCK", "quality_score": 5, "decision": "PASS", "findings": [], '
                      '"required_corrections": [], "reason": "x"}',
    "not-json": "PASS, looks fine",
    "string-score": '{"decision": "PASS", "quality_score": "92", "findings": [], "required_corrections": [], "reason": "x"}',
    "fractional-score": '{"decision": "PASS", "quality_score": 92.5, "findings": [], "required_corrections": [], "reason": "x"}',
    "score-101": igor_json("PASS", 101),
    "bool-score": '{"decision": "PASS", "quality_score": true, "findings": [], "required_corrections": [], "reason": "x"}',
    "nan-score": '{"decision": "PASS", "quality_score": NaN, "findings": [], "required_corrections": [], "reason": "x"}',
}


@pytest.mark.parametrize("judge", list(REFUSED.values()), ids=list(REFUSED))
def test_replies_the_pipeline_refuses_are_a_consistent_block_not_a_failed_session(fake, make_cfg, judge):
    r, rep = run_live(fake, make_cfg, judge)
    assert r.final["gate_state"] == "BLOCKED" and r.final["igor_status"] == "UNAVAILABLE", r.final
    assert rep["failures"] == [] and rep["overall"] == "CONSISTENT", rep


def test_pass_with_open_corrections_is_review_and_the_whole_iteration_chain_verifies(fake, make_cfg):
    r, rep = run_live(fake, make_cfg, igor_json("PASS", 92, corrections=["add the population"]))
    assert r.final["gate_state"] == "REVIEW_REQUIRED" and r.final["iterations"] == 3, r.final
    assert rep["failures"] == [] and rep["overall"] == "CONSISTENT", rep


def test_a_low_score_pass_is_downgraded_and_verifies_consistently(fake, make_cfg):
    r, rep = run_live(fake, make_cfg, igor_json("PASS", 50))
    assert r.final["gate_state"] == "REVIEW_REQUIRED", r.final
    assert rep["failures"] == [] and rep["overall"] == "CONSISTENT", rep


def test_a_judge_that_passes_on_the_second_iteration_verifies(fake, make_cfg):
    live(fake)
    fake.script("nina-test", "Lyon is the capital of France.", "Paris is the capital of France.")
    fake.script("igor-test", igor_json("REVIEW", 40, corrections=["name the right city"]), igor_json("PASS", 92))
    r = Pipeline(make_cfg(policy=Policy())).run(TASK)
    rep = verify_session(r.session_dir)
    assert r.final["gate_state"] == "PASS" and r.final["iterations"] == 2, r.final
    assert rep["failures"] == [] and rep["overall"] == "VERIFIED", rep


# ======================================================================================================== 3
# One same_model(), used at stage time and in the verifier's recomputation.
SAME = [
    (("ollama-local", "llama3", "http://localhost:11434"), ("ollama-local", "llama3:latest", "http://127.0.0.1:11434/")),
    (("ollama-local", "Llama3 ", "http://LOCALHOST:11434"), ("OLLAMA-LOCAL", "llama3", "http://[::1]:11434")),
    (("ollama-cloud", "m", "https://ollama.com"), ("ollama-cloud", "m", "https://ollama.com:443/")),
    (("ollama-local", "m", "http://h"), ("ollama-local", "m", "http://h:80")),
    (("ollama-local", "m", "http://[::ffff:127.0.0.1]:11434"), ("ollama-local", "m", "http://localhost:11434")),
    (("openai", "gpt-x", "https://api.openai.com"), ("openai", " GPT-X", "https://api.openai.com/")),
    (("ollama-local", "m:LATEST", "http://localhost:11434"), ("ollama-local", "m", "http://localhost:11434")),
]
DIFFERENT = [
    (("ollama-local", "llama3:8b", "http://localhost:11434"), ("ollama-local", "llama3", "http://localhost:11434")),
    (("ollama-local", "m", "http://localhost:11434"), ("ollama-local", "m", "http://localhost:11435")),
    (("ollama-local", "m", "http://localhost:11434"), ("ollama-local", "m", "http://otherhost:11434")),
    (("ollama-local", "m", "http://h"), ("ollama-local", "m", "https://h")),
    (("ollama-local", "m", "http://h/a"), ("ollama-local", "m", "http://h/b")),
    (("ollama-local", "a", "http://h"), ("ollama-local", "b", "http://h")),
    (("ollama-local", "m", "http://127.0.0.2:11434"), ("ollama-local", "m", "http://127.0.0.1:11434")),
    (("ollama-local", "m", "http://h"), ("ollama-cloud", "m", "http://h")),
]


def _ident(cfg, digest=None):
    return {"provider": cfg.provider, "model": cfg.model, "endpoint": cfg.public_endpoint(), "model_digest": digest}


@pytest.mark.parametrize("a, b, expected", [(a, b, True) for a, b in SAME] + [(a, b, False) for a, b in DIFFERENT])
def test_stage_time_and_verifier_use_the_same_same_model(a, b, expected):
    nina, judge = ProviderConfig(a[0], a[1], base_url=a[2]), ProviderConfig(b[0], b[1], base_url=b[2])
    label = Igor(judge, nina, Policy(), ()).independence_label()
    assert (label == "SAME_MODEL_SEPARATE_CONTEXT") is expected
    assert same_model(_ident(nina), _ident(judge)) is expected and same_model(_ident(judge), _ident(nina)) is expected


def test_equal_non_empty_digests_are_one_model_whatever_the_names():
    a = {"provider": "ollama-local", "model": "a", "endpoint": "http://x", "model_digest": "ab" * 32}
    b = {"provider": "ollama-cloud", "model": "b", "endpoint": "https://y", "model_digest": "AB" * 32}
    assert same_model(a, b)
    assert not same_model({**a, "model_digest": None}, {**b, "model_digest": None})
    assert not same_model({**a, "model_digest": ""}, {**b, "model_digest": ""})
    assert not same_model(a, {**b, "model_digest": "cd" * 32})
    # what must differ is unchanged: equal provider/model/endpoint stay the same model even with unequal digests
    assert same_model(a, {**a, "model_digest": "cd" * 32})
    assert Igor(ProviderConfig("p", "b", base_url="http://y"), ProviderConfig("p", "a", base_url="http://x"),
                Policy(), ()).independence_label("ab" * 32, "ab" * 32) == "SAME_MODEL_SEPARATE_CONTEXT"


def test_a_judge_that_is_nina_under_another_spelling_is_not_independent(tmp_path):
    kw = {"model": "NINA-M ", "endpoint": "HTTP://x/"}
    v, _ = session(tmp_path, igors=[kw], canaries=[kw])
    r = verify_session(v.dir)
    assert r["overall"] != "VERIFIED" and r["recomputed"]["igor_status"] == "NOT_INDEPENDENT", r["recomputed"]


def test_a_judge_with_nina_s_digest_is_not_independent(tmp_path):
    kw = {"digest": DIG}
    v, _ = session(tmp_path, igors=[kw], canaries=[kw])
    r = verify_session(v.dir)
    assert r["overall"] != "VERIFIED" and r["recomputed"]["igor_status"] == "NOT_INDEPENDENT", r["recomputed"]


def test_end_to_end_two_names_for_the_same_weights_are_not_independent(fake, make_cfg):
    fake.add_model("alias-test", digest=NINA_DIGEST)                       # Nina's digest under another name
    r, rep = run_live(fake, make_cfg, igor_json("PASS", 92), igor="alias-test")
    facts = verify.inspect_session(r.session_dir)
    assert facts.igor_eval["meta"]["independence"] == "SAME_MODEL_SEPARATE_CONTEXT"      # stage-time label
    assert r.final["igor_status"] == "NOT_INDEPENDENT" and r.final["gate_state"] == "REVIEW_REQUIRED", r.final
    assert rep["failures"] == [] and rep["overall"] == "CONSISTENT", rep               # same decision on replay


def test_end_to_end_a_different_model_with_its_own_digest_stays_independent(fake, make_cfg):
    r, rep = run_live(fake, make_cfg, igor_json("PASS", 92))
    assert verify.inspect_session(r.session_dir).igor_eval["meta"]["independence"] == "DIFFERENT_MODEL"
    assert r.final["gate_state"] == "PASS" and rep["overall"] == "VERIFIED", rep


# ======================================================================================================== 4
# Bounds: max_iterations and scores; a weak policy never reaches the top tier.
BAD_MAX = {"bool": True, "float": 3.0, "str": "3", "none": None, "zero": 0, "negative": -1, "four": 4, "huge": 10 ** 9}


@pytest.mark.parametrize("bad", list(BAD_MAX.values()), ids=list(BAD_MAX))
def test_max_iterations_must_be_an_int_within_1_to_3(tmp_path, bad):
    v, _ = session(tmp_path, policy={**asdict(Policy()), "max_iterations": bad})
    r = verify_session(v.dir)
    assert r["overall"] != "VERIFIED" and r["recomputed"]["state"] == "BLOCKED" and "max_iterations" in reasons(r)


def test_an_absent_max_iterations_is_a_failure(tmp_path):
    pol = asdict(Policy())
    del pol["max_iterations"]
    v, _ = session(tmp_path, policy=pol)
    r = verify_session(v.dir)
    assert r["overall"] != "VERIFIED" and "max_iterations" in reasons(r)


def test_loosening_max_iterations_after_the_fact_is_failed(tmp_path):
    v, final = session(tmp_path)
    unlock(v.dir)
    final["policy"]["max_iterations"] = 99
    final["anti_replay"]["binding"] = verify.compute_final_binding(final)
    (v.dir / "final.json").write_text(json.dumps(final))
    r = verify_session(v.dir)
    assert r["overall"] == "FAILED" and any("gate_state" in f for f in r["failures"]), r["failures"]


@pytest.mark.parametrize("score", [101, 1000, -1, -5], ids=["101", "1000", "-1", "-5"])
def test_a_judge_score_outside_0_to_100_never_verifies(tmp_path, score):
    v, _ = session(tmp_path, policy=Policy(min_quality_score=0), igors=[{"score": score}])
    r = verify_session(v.dir)
    assert r["overall"] != "VERIFIED" and r["recomputed"]["state"] == "BLOCKED", r["recomputed"]


@pytest.mark.parametrize("score", [True, False, "92", None, 92.5], ids=["true", "false", "str", "none", "fraction"])
def test_a_judge_score_that_is_not_an_integer_never_verifies(tmp_path, score):
    v, _ = session(tmp_path, policy=Policy(min_quality_score=0), igors=[{"score": score}])
    r = verify_session(v.dir)
    assert r["overall"] != "VERIFIED" and r["recomputed"]["state"] == "BLOCKED", r["recomputed"]


@pytest.mark.parametrize("min_q, top", [(70, True), (71, True), (100, True), (69, False), (50, False), (0, False)])
def test_a_weak_policy_is_capped_below_the_top_tier_with_a_reason(tmp_path, min_q, top):
    v, _ = session(tmp_path, policy=Policy(min_quality_score=min_q), igors=[{"score": 100}])
    r = verify_session(v.dir)
    assert r["recomputed"]["state"] == "PASS" and r["failures"] == [], r
    if top:
        assert r["overall"] == "VERIFIED" and r["caps"] == []
    else:
        assert r["overall"] == "CONSISTENT" and r["outcome"] == "PASS", r["overall"]
        assert r["caps"] and "min_quality_score" in r["caps"][0] and "capped" in r["caps"][0]
        assert any("capped" in w for w in r["warnings"])


def test_a_capped_weak_policy_session_exits_with_the_consistent_code(tmp_path):
    v, _ = session(tmp_path, policy=Policy(min_quality_score=10), igors=[{"score": 100}])
    p = cli("verify", str(v.dir))
    assert p.returncode == 2 and "capped" in p.stdout, (p.returncode, p.stdout)


def test_relaxed_flags_that_are_not_thresholds_warn_but_are_not_capped(tmp_path):
    v, _ = session(tmp_path, policy=Policy(require_model_digest=False, require_igor_calibration=False), canaries=[])
    r = verify_session(v.dir)
    assert r["overall"] == "VERIFIED" and r["caps"] == [] and any("weaker than the defaults" in w for w in r["warnings"])


def test_the_default_thresholds_are_unchanged():
    assert Policy().min_quality_score == verify.DEFAULT_MIN_QUALITY_SCORE == 70
    assert Policy().max_iterations == 3 and Policy().require_model_digest and Policy().require_igor_calibration
    assert not Policy().allow_test_double and not Policy().allow_same_model_igor


# ======================================================================================================== 5
# The iteration chain, and the gate_state each envelope recorded.
def test_an_honest_three_iteration_chain_verifies(tmp_path):
    v, _ = session(tmp_path, nina_n=3)
    r = verify_session(v.dir)
    assert r["overall"] == "VERIFIED" and r["failures"] == [], r["failures"]


@pytest.mark.parametrize("kw, text", [
    ({"chain": False}, "without a non-PASS Igor verdict"),
    ({"chain": "no-refs"}, "correction refs"),
    ({"chain": "wrong-refs"}, "correction refs"),
    ({"earlier": {"decision": "PASS", "score": 95}}, "without a non-PASS Igor verdict"),
], ids=["no-verdict", "no-correction-refs", "wrong-correction-refs", "ran-on-after-a-pass"])
def test_a_broken_iteration_chain_is_failed(tmp_path, kw, text):
    v, _ = session(tmp_path, nina_n=2, **kw)
    r = verify_session(v.dir)
    assert r["overall"] == "FAILED" and any(text in f for f in r["failures"]), r["failures"]


def test_a_session_written_before_correction_refs_existed_verifies_via_its_input_artifact(tmp_path):
    v, _ = session(tmp_path, nina_n=2, chain="input-only")
    r = verify_session(v.dir)
    assert r["overall"] == "VERIFIED" and r["failures"] == [], r["failures"]


@pytest.mark.parametrize("kw", [
    dict(igors=[{"decision": "BLOCK", "score": 5, "gate": "PASS"}]),
    dict(igors=[{"gate": "BLOCKED"}]),
    dict(igors=[{"decision": "REVIEW", "score": 60, "corrections": ["x"], "gate": "PASS"}]),
    dict(canaries=[{"gate": "CANARY_ACCEPTED"}]),
    dict(canaries=[{"js": "INVALID_OUTPUT", "gate": "CANARY_REJECTED"}]),
    dict(nina_gate="PASS"),
], ids=["block-labelled-pass", "pass-labelled-blocked", "review-labelled-pass", "rejected-canary-labelled-accepted",
        "unavailable-canary-labelled-rejected", "nina-labelled-pass"])
def test_an_envelope_whose_gate_state_is_not_the_derived_one_is_failed(tmp_path, kw):
    v, _ = session(tmp_path, **kw)
    r = verify_session(v.dir)
    assert r["overall"] == "FAILED" and any("gate_state" in f and "derived" in f for f in r["failures"]), r["failures"]


# ======================================================================================================== 6
# Secrets: boundary, placeholders, still detected in context, linear.
REAL = {
    "sk-proj": ("sk-proj-" + "aB3dE5fG7hJ9kL1mN3pQ5rS7", "aB3dE5fG7hJ9kL1mN3pQ5rS7"),
    "sk-ant": ("sk-ant-api03-" + "A1b2C3d4E5f6G7h8I9j0K1l2", "A1b2C3d4E5f6G7h8I9j0K1l2"),
    "stripe-sk": ("sk_live_" + "51HxYz9aBcDeFgHiJk", "51HxYz9aBcDeFgHiJk"),
    "stripe-rk": ("rk_live_" + "51HxYz9aBcDeFgHiJk", "51HxYz9aBcDeFgHiJk"),
    "jwt": ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r", "dBjftJeZ4CVPmB92K27uhbUJU1p1r"),
    "dsn": ("postgres://admin:hunter2@db.internal:5432/app", "hunter2"),
    "dsn-odd-scheme": ("1+postgres://admin:hunter2@db.internal/app", "hunter2"),
}
CONTEXTS = ["", "key=", "KEY = ", "key: ", " ", "'", '"', "`", "(", "[", "{", ",", "Bearer ", "bearer ",
            "Authorization: Bearer ", "\n", "\\n", "x\\t", "%3D", "?token=", "<", "="]


@pytest.mark.parametrize("name", list(REAL))
@pytest.mark.parametrize("ctx", CONTEXTS, ids=repr)
def test_real_looking_keys_are_still_detected_after_any_delimiter(name, ctx):
    secret, core = REAL[name]
    text = f"here is {ctx}{secret} and more text"
    assert contains_secret(text), text
    assert core not in scrub(text)


@pytest.mark.parametrize("text", [
    "See https://example.com/blog/risk-based-approach-to-operational-resilience-under-dora for details.",
    "Attach docs/risk-register-template-2026-v2.xlsx to the ticket.",
    "Use the branch name feature/task-management-and-planning-tool-redesign.",
    "Enable disk-encryption-at-rest-and-in-transit for all volumes.",
    "def risk_live_monitoring(feed):\n    return feed",
    "Set DATABASE_URL=postgresql://user:password@localhost:5432/mydb in .env",
    "DATABASE_URL=postgresql://user:<password>@localhost/db", "mysql://root:${DB_PASSWORD}@db/x",
    "redis://default:****@h:6379", "mongodb://app:{{ mongo_password }}@h/db", "amqp://guest:PASSWORD@h//",
], ids=["risk-based-url", "risk-register", "task-management", "disk-encryption", "risk_live", "dsn-password",
        "dsn-angle", "dsn-shell", "dsn-stars", "dsn-jinja", "dsn-upper"])
def test_ordinary_prose_and_placeholder_dsns_are_not_flagged(text):
    assert not contains_secret(text), text


@pytest.mark.parametrize("text", [
    "postgres://user:password123@h/db", "postgres://user:Password1@h", "postgres://user:passwordx@h",
    "mysql://root:<pw>x@h", "redis://default:xx@h", "postgres://user:hunter2@h", "ssh+git://u:s3cr3t@h",
], ids=["password123", "Password1", "passwordx", "partial-template", "two-x", "hunter2", "ssh-git"])
def test_a_real_secret_cannot_hide_behind_a_placeholder_shape(text):
    assert contains_secret(text), text


N = 200_000
ADVERSARIAL = {
    "alnum": "a" * N, "sk-repeated": "sk-" * (N // 3), "eyJ-repeated": "eyJ" * (N // 3), "eyJ-dashes": "eyJ-" * (N // 4),
    "eyJ-segments": "eyJaaaaaaaa." * (N // 12), "scheme-repeated": "a://" * (N // 4), "url-long-host": "http://" + "a" * N,
    "colons": "a://b" + ":" * N, "template-repeated": "a://b:<" * (N // 7), "template-long": "x://u:<" + "a" * N,
    "dashes": "-" * N, "digits-dashes": "1-" * (N // 2), "plus-letters": "a+" * (N // 2), "bearer-repeated": "bearer " * (N // 7),
    "basic-spaces": "authorization:" + " " * N, "begin-repeated": "-----BEGIN " + "A " * (N // 2),
    "percent-escapes": "%3D" * (N // 3), "backslash-n": "\\n" * (N // 2), "ask-long": "ask-" + "b" * N,
    "risk-live-long": "risk_live_" + "b" * N, "ghp-long": "ghp_" + "a" * N, "kebab-prose": "risk-based-approach " * (N // 19),
}


@pytest.mark.parametrize("name", list(ADVERSARIAL))
def test_every_secret_scan_is_linear_on_200k_characters(name):
    text = ADVERSARIAL[name]
    t0 = time.perf_counter()
    contains_secret(text)
    t1 = time.perf_counter()
    scrub(text)
    t2 = time.perf_counter()
    assert t1 - t0 < 0.5 and t2 - t1 < 0.5, (name, t1 - t0, t2 - t1)


# ======================================================================================================== 7
# One numeric rule for judge scores (pipeline parser and verifier) and for Policy fields.
def _reply_with(score_literal):
    return ('{"decision": "PASS", "quality_score": %s, "findings": [], "required_corrections": [], "reason": "r"}'
            % score_literal)


@pytest.mark.parametrize("literal, expected", [("92", 92), ("92.0", 92), ("9.2e1", 92), ("0", 0), ("0.0", 0), ("-0.0", 0),
                                               ("100", 100), ("100.0", 100)])
def test_parse_judge_accepts_integral_scores_as_ints(literal, expected):
    got, why = parse_judge(_reply_with(literal))
    assert why == "" and got["quality_score"] == expected and type(got["quality_score"]) is int


@pytest.mark.parametrize("literal", ["92.5", "true", "false", '"92"', "null", "NaN", "Infinity", "-Infinity", "101", "-1",
                                     "100.5", "1e999", "[]", "{}"])
def test_parse_judge_still_rejects_everything_else(literal):
    got, why = parse_judge(_reply_with(literal))
    assert got is None and why == "quality_score must be an integer 0..100"


def test_the_verifier_reads_an_integral_float_score_like_the_pipeline_does(tmp_path):
    v, _ = session(tmp_path, igors=[{"score": 92.0}])
    r = verify_session(v.dir)
    assert r["overall"] == "VERIFIED" and r["failures"] == [], r


def test_a_canary_pass_with_an_integral_float_score_is_a_pass(tmp_path):
    v, _ = session(tmp_path, canaries=[{"decision": "PASS", "score": 100.0}])
    r = verify_session(v.dir)
    assert r["overall"] != "VERIFIED" and r["recomputed"]["igor_status"] == "UNCALIBRATED"
    assert "PASSed a known-wrong answer" in reasons(r)


def test_policy_coerces_integral_floats_and_refuses_the_rest_with_a_config_error():
    p = Policy(max_iterations=3.0, min_quality_score=70.0)
    assert (p.max_iterations, p.min_quality_score) == (3, 70)
    assert type(p.max_iterations) is int and type(asdict(p)["min_quality_score"]) is int
    for bad in (2.5, "3", True, None, float("nan"), float("inf"), [3]):
        with pytest.raises(ConfigError):
            Policy(max_iterations=bad)
        with pytest.raises(ConfigError):
            Policy(min_quality_score=bad)
    for out_of_range in (0, 4, -1):
        with pytest.raises(ConfigError):
            Policy(max_iterations=out_of_range).validate()
    with pytest.raises(ConfigError):
        Policy(min_quality_score=101).validate()


def test_a_pipeline_run_with_float_policy_values_records_ints(fake, make_cfg):
    r, rep = run_live(fake, make_cfg, igor_json("PASS", 92), policy=Policy(max_iterations=3.0, min_quality_score=70.0))
    assert r.final["policy"]["max_iterations"] == 3 and type(r.final["policy"]["max_iterations"]) is int
    assert type(r.final["policy"]["min_quality_score"]) is int and rep["overall"] == "VERIFIED", rep


# ======================================================================================================== 8
# URL guard.
@pytest.mark.parametrize("host, loopback", [
    ("localhost", True), ("LOCALHOST", True), ("localhost.", True), ("127.0.0.1", True), ("127.0.0.2", True),
    ("127.255.255.254", True), ("::1", True), ("0:0:0:0:0:0:0:1", True), ("::ffff:127.0.0.1", True),
    ("example.com", False), ("10.0.0.1", False), ("192.168.1.5", False), ("0.0.0.0", False), ("128.0.0.1", False),
    ("host.docker.internal", False), ("localhost.evil.test", False), ("127.0.0.1.evil.test", False), ("", False),
    ("::ffff:10.0.0.1", False), ("::", False),
])
def test_loopback_is_parsed_not_string_matched(host, loopback):
    assert providers._is_loopback(host) is loopback


@pytest.mark.parametrize("url", ["http://10.0.0.1:11434/x", "http://192.168.1.5/x", "http://host.docker.internal:11434/x",
                                 "http://[::ffff:10.1.2.3]/x", "http://127.0.0.1.evil.test/x", "http://[2001:db8::1]:11434/x"])
def test_credentials_never_travel_over_cleartext_http_to_a_non_loopback_host(url):
    with pytest.raises(ConfigError, match="plain http"):
        providers._http("GET", url, None, {"Authorization": "Bearer abc"}, 1)


@pytest.mark.parametrize("url", ["http://127.0.0.2:1/x", "http://[::1]:1/x", "http://LOCALHOST:1/x",
                                 "http://[::ffff:127.0.0.1]:1/x"])
def test_loopback_hosts_may_carry_credentials_over_http(url):
    with pytest.raises((ProviderUnavailable, ProviderTimeout)):           # the guard let it through; nobody listens
        providers._http("GET", url, None, {"Authorization": "Bearer abc"}, 2)


@pytest.mark.parametrize("base, expected", [
    ("http://[::1]:11434/", "http://[::1]:11434"),
    ("http://[::1]", "http://[::1]"),
    ("http://user:pw@[2001:db8::1]:8080/api?x=1#f", "http://[2001:db8::1]:8080/api"),
    ("http://localhost:11434", "http://localhost:11434"),
    ("https://ollama.com", "https://ollama.com"),
    ("http://host.docker.internal:11434/", "http://host.docker.internal:11434"),
])
def test_public_endpoint_keeps_the_brackets_of_an_ipv6_literal(base, expected):
    assert ProviderConfig("ollama-local", "m", base_url=base).public_endpoint() == expected


def test_an_ipv6_literal_endpoint_is_used_and_recorded_with_its_brackets(monkeypatch):
    seen = []

    def fake_http(method, url, body, headers, timeout, secrets=()):
        seen.append(url)
        if url.endswith("/api/version"):
            return {"version": "0.5.0"}
        if url.endswith("/api/tags"):
            return {"models": [{"name": "m1", "model": "m1", "digest": "d" * 64}]}
        return {"message": {"content": "hi"}, "done": True, "model": "m1"}
    monkeypatch.setattr(providers, "_http", fake_http)
    gen = providers.build_provider(ProviderConfig("ollama-local", "m1", base_url="http://[::1]:11434")).execute(
        [{"role": "user", "content": "x"}])
    assert seen[0] == "http://[::1]:11434/api/version" and gen.runtime_proof["endpoint"] == "http://[::1]:11434"


# ======================================================================================================== 9
# A failed finalize still verifies; CLI report and task handling.
def test_a_judge_whose_evaluation_cannot_be_stored_is_a_consistent_block(fake, make_cfg, monkeypatch):
    live(fake)
    fake.script("igor-test", igor_json("PASS", 92))
    orig = EvidenceVault.put_artifact

    def put(self, data):
        if b'"meta":{' in data:                      # the Igor evaluation
            raise OSError("disk full")
        return orig(self, data)
    monkeypatch.setattr(EvidenceVault, "put_artifact", put)
    r = Pipeline(make_cfg(policy=Policy())).run(TASK)
    assert r.final["gate_state"] == "BLOCKED", r.final
    rep = verify_session(r.session_dir)
    assert rep["failures"] == [] and rep["overall"] == "CONSISTENT", rep
    facts = verify.inspect_session(r.session_dir)
    refs = facts.igor[0]["refs"]
    assert refs["verifies_run_id"] == facts.nina[0]["run_id"]
    assert refs["verifies_envelope_hash"] == facts.nina[0]["envelope_hash"]
    assert "finalize failed" in facts.igor[0]["detail"]


def test_a_canary_whose_evaluation_cannot_be_stored_is_not_calibration_but_still_verifies(fake, make_cfg, monkeypatch):
    live(fake)
    fake.script("igor-test", igor_json("PASS", 92))
    orig = EvidenceVault.put_artifact

    def put(self, data):
        if b'"expected":"anything but PASS"' in data:        # the canary evaluation
            raise OSError("disk full")
        return orig(self, data)
    monkeypatch.setattr(EvidenceVault, "put_artifact", put)
    r = Pipeline(make_cfg(policy=Policy())).run(TASK)
    assert r.final["gate_state"] == "REVIEW_REQUIRED" and r.final["igor_status"] == "UNCALIBRATED", r.final
    rep = verify_session(r.session_dir)
    assert rep["failures"] == [] and rep["overall"] == "CONSISTENT", rep
    assert verify.inspect_session(r.session_dir).canary[0]["refs"]["verifies_run_id"]


def test_cli_report_survives_envelopes_with_missing_or_odd_fields(tmp_path):
    v, _ = session(tmp_path)
    unlock(v.dir)
    e = sorted((v.dir / "envelopes").glob("*.json"))[0]
    doc = json.loads(e.read_text())
    for k in ("seq", "agent_id", "parent_run_id", "execution_status", "provider", "envelope_hash"):
        doc.pop(k, None)
    doc["refs"] = ["not", "a", "dict"]
    e.write_text(json.dumps(doc))
    p = cli("report", str(v.dir))
    assert p.returncode == 1 and "Traceback" not in p.stderr and "run_id=" in p.stdout, (p.stdout[-300:], p.stderr[-300:])


def test_cli_report_of_a_clean_session_keeps_its_format(tmp_path):
    v, _ = session(tmp_path)
    p = cli("report", str(v.dir))
    assert p.returncode == 0 and "[01] nina" in p.stdout and "verifier       : VERIFIED" in p.stdout, p.stdout[:400]


def test_cli_run_with_an_unencodable_task_is_a_clean_error(tmp_path):
    p = cli("run", "--task", "Paris \udcff is the capital")
    assert p.returncode == 1 and "Traceback" not in p.stderr, p.stderr[-400:]
    out = json.loads(p.stdout)
    assert out["gate_state"] == "BLOCKED" and "UTF-8" in out["error"]


def test_cli_run_with_a_task_file_that_is_not_utf8_or_missing_is_a_clean_error(tmp_path):
    bad = tmp_path / "task.txt"
    bad.write_bytes(b"abc \xff\xfe")
    for path in (bad, tmp_path / "missing.txt"):
        p = cli("run", "--task-file", str(path))
        assert p.returncode == 1 and "Traceback" not in p.stderr, p.stderr[-400:]
        assert json.loads(p.stdout)["gate_state"] == "BLOCKED"


def test_pipeline_run_refuses_a_task_that_cannot_be_stored_before_creating_anything(fake, make_cfg, tmp_path):
    cfg = make_cfg()
    for bad in ("Paris \ud800 is the capital", None, b"bytes"):
        with pytest.raises(ConfigError):
            Pipeline(cfg).run(bad)
    assert not (tmp_path / "vault").exists()


# ======================================================================================================== compat / robustness
def test_an_older_policy_snapshot_without_the_newer_keys_still_verifies(tmp_path):
    pol = asdict(Policy())
    del pol["require_igor_calibration"], pol["allow_same_model_igor"]          # keys added after the first sessions
    v, _ = session(tmp_path, policy=pol)
    r = verify_session(v.dir)
    assert r["overall"] == "VERIFIED" and r["failures"] == [] and r["caps"] == [], r


def test_a_deeply_nested_judge_reply_is_an_invalid_reply_not_an_exception():
    got, why = parse_judge("[" * 200_000)
    assert got is None and why == "judge output is not valid JSON"


def test_an_evaluation_that_is_valid_json_but_not_an_object_is_a_named_failure(tmp_path):
    def extra(v, sid, n):
        forge_env(v, sid, "igor", 1, n["run_id"], out=reply(), model="igor-m", digest=IGOR_DIG, gate="PASS",
                  refs={"verifies_run_id": n["run_id"], "verifies_envelope_hash": n["envelope_hash"],
                        "evaluation_hash": v.put_artifact(b"[1, 2]")})
    v, _ = session(tmp_path, igors=[], canaries=[], extra=extra)
    r = verify_session(v.dir)
    assert r["overall"] == "FAILED" and any("not a JSON object" in f for f in r["failures"]), r["failures"]


# ======================================================================================================== misc
def test_verify_py_is_still_a_standalone_stdlib_only_file(tmp_path):
    tree = ast.parse(Path(verify.__file__).read_text("utf-8"))
    mods = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            mods |= {a.name.split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom):
            assert n.level == 0, "verify.py must not import from the package"
            mods.add((n.module or "").split(".")[0])
    assert mods <= set(sys.stdlib_module_names), mods
    v, _ = session(tmp_path / "s")
    alone = tmp_path / "alone" / "verify.py"
    alone.parent.mkdir()
    shutil.copy(verify.__file__, alone)
    p = subprocess.run([sys.executable, str(alone), str(v.dir)], capture_output=True, text=True, cwd=str(alone.parent))
    assert p.returncode == 0 and "overall=VERIFIED" in p.stdout, (p.stdout, p.stderr)
