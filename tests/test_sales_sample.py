"""The synthetic sample under docs/sales/sample must stay what it says it is: a TEST_DOUBLE session that verifies as PARTIAL,
that fails when touched, and that carries its SYNTHETIC label in the README and inside the recorded task."""
import json
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ola_pipeline import verify_session  # noqa: E402

SAMPLE = ROOT / "docs" / "sales" / "sample"
SESSION = next(SAMPLE.glob("ses_*"))


def _copy(tmp_path):
    dest = tmp_path / SESSION.name
    shutil.copytree(SESSION, dest)
    for p in [dest, *dest.rglob("*")]:
        os.chmod(p, 0o700 if p.is_dir() else 0o600)     # writable files, as after a git checkout (owner-only)
    return dest


def test_the_sample_verifies_as_partial_and_never_better(tmp_path):
    rep = verify_session(_copy(tmp_path))
    assert rep["failures"] == [], rep["failures"]
    assert rep["overall"] == "PARTIAL"
    assert rep["runtime_kind"] == "TEST_DOUBLE"
    assert rep["authenticity"] == "NONE"


def test_changing_one_word_of_the_produced_text_is_caught(tmp_path):
    dest = _copy(tmp_path)
    produced = dest / "artifacts" / json.loads((dest / "final.json").read_text())["evidence"]["output_hash"]
    assert b"Must stay with a person" in produced.read_bytes()
    produced.write_bytes(produced.read_bytes().replace(b"a person", b"a robot"))
    rep = verify_session(dest)
    assert rep["overall"] == "FAILED"
    assert any("hash" in f for f in rep["failures"])


def test_the_synthetic_label_is_in_the_readme_and_inside_the_recorded_task():
    readme = (SAMPLE / "README.md").read_text()
    assert readme.startswith("# SYNTHETIC SAMPLE")
    assert "SYNTHETIC / TEST EVIDENCE ONLY" in readme and "TEST_DOUBLE" not in readme.split("## What it is")[0]
    assert "PARTIAL" in readme and "overall=VERIFIED" not in readme
    recorded = [p for p in (SESSION / "artifacts").iterdir() if b"SYNTHETIC SAMPLE - not a real customer" in p.read_bytes()]
    assert recorded, "the recorded task must carry the label itself"


def test_the_sample_holds_no_local_path_or_secret_shaped_text():
    for p in SAMPLE.rglob("*"):
        if p.is_file():
            text = p.read_text(errors="replace")
            for needle in ("/tmp/", "/home/", "/root/", "scratchpad", "BEGIN PRIVATE KEY", "sk-"):
                assert needle not in text, (str(p), needle)
