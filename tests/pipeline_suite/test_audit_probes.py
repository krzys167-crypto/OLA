"""Regression probes for the two defects the 2026-10-04 audit (F01, F02) found in the STANDALONE package
`ola_nina_ollama_pipeline`, replayed against THIS pipeline (`ola_pipeline`): a different code base, so the audit
result does not transfer either way. Test double only: these prove gate/verifier logic, not a real runtime.

F01  a model result that says "deny" must never end in an allow / PASS.
F02  an envelope whose hashes are forged (sha256 = '0' * 64, or any value that is not the recomputed digest)
     must never verify and must never leave the Gate at PASS.
"""
import json
from pathlib import Path

import pytest

from pipeline_helpers import igor_json
from ola_pipeline import Pipeline, Policy, verify_session

TASK = "State the capital of France in one sentence."
ZERO = "0" * 64


def _run(cfg):
    return Pipeline(cfg).run(TASK)


def _envelope_paths(session_dir):
    return sorted((Path(session_dir) / "envelopes").glob("*.json"))


def _rewrite(path, mutate):
    import os
    os.chmod(path, 0o644)
    d = json.loads(path.read_text())
    mutate(d)
    path.write_text(json.dumps(d))


@pytest.mark.parametrize("field", ["envelope_hash", "input_hash", "output_hash"])
def test_f02_zeroed_digest_in_any_envelope_never_verifies(fake, make_cfg, field):
    fake.script("igor-test", igor_json("PASS"))
    r = _run(make_cfg())
    assert verify_session(r.session_dir)["failures"] == []        # the untouched session is clean
    victims = 0
    for p in _envelope_paths(r.session_dir):
        if field in json.loads(p.read_text()):
            _rewrite(p, lambda d: d.__setitem__(field, ZERO))
            victims += 1
    assert victims, f"no envelope carries {field}"
    rep = verify_session(r.session_dir)
    assert rep["overall"] == "FAILED" and rep["failures"], rep


def test_f02_zeroed_digest_in_final_evidence_never_verifies(fake, make_cfg):
    fake.script("igor-test", igor_json("PASS"))
    r = _run(make_cfg())
    fp = Path(r.session_dir) / "final.json"
    def zero(d):
        d.setdefault("evidence", {})["output_hash"] = ZERO
    _rewrite(fp, zero)
    rep = verify_session(r.session_dir)
    assert rep["overall"] == "FAILED" and rep["failures"], rep


def test_f01_a_judge_that_blocks_never_yields_pass(fake, make_cfg):
    fake.script("igor-test", igor_json("BLOCK", 5, corrections=["unsafe"]))
    r = _run(make_cfg(policy=Policy(allow_test_double=True, max_iterations=1)))
    assert r.final["gate_state"] != "PASS"
    assert verify_session(r.session_dir)["overall"] != "VERIFIED"


def test_f01_a_forged_pass_on_a_blocked_session_is_detected(fake, make_cfg):
    fake.script("igor-test", igor_json("BLOCK", 5, corrections=["unsafe"]))
    r = _run(make_cfg(policy=Policy(allow_test_double=True, max_iterations=1)))
    assert r.final["gate_state"] != "PASS"
    fp = Path(r.session_dir) / "final.json"
    _rewrite(fp, lambda d: d.__setitem__("gate_state", "PASS"))
    rep = verify_session(r.session_dir)
    assert rep["overall"] == "FAILED" and any("gate_state" in x for x in rep["failures"]), rep
