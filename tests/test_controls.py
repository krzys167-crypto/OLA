"""scripts/check_controls.py: the control matrix must be backed by things that exist, and it must be able to say no."""
import importlib.util
import json
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("check_controls", ROOT / "scripts" / "check_controls.py")
cc = importlib.util.module_from_spec(_spec)
sys.modules["check_controls"] = cc
_spec.loader.exec_module(cc)


def real():
    return json.loads((ROOT / "governance" / "controls.json").read_text())["controls"]


def test_every_reference_of_the_real_matrix_exists_and_is_run_by_ci():
    errors, info = cc.check(real())
    assert errors == [], errors
    assert len(info) >= 14 and all(i["status"] == "NOT_RUN" for i in info.values()), "static check never claims a status"


def test_the_markdown_matrix_is_in_sync_with_the_json():
    controls = real()
    _, info = cc.check(controls)
    assert (ROOT / "docs" / "control-evidence-matrix.md").read_text() == cc.to_markdown(controls, info, False)


def test_every_control_states_a_limit():
    assert all(len(c["limits"]) > 20 for c in real()), "a control without a stated limit is a claim"


# ------------------------------------------------------------------ the checker can say no (synthetic repository)
@pytest.fixture
def repo(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "m.py").write_text("def mechanism():\n    return 1\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_a.py").write_text("def test_ok():\n    assert True\n\ndef test_bad():\n    assert False\n")
    (tmp_path / "tests" / "test_b.py").write_text("def test_b():\n    assert True\n")
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "all.yml").write_text(textwrap.dedent("""\
        name: all
        on: push
        jobs:
          unit:
            runs-on: ubuntu-latest
            steps:
              - run: pip install pytest
              - run: python -m pytest -q
          some:
            runs-on: ubuntu-latest
            steps:
              - run: python -m pytest -q tests/test_a.py
          lint:
            runs-on: ubuntu-latest
            steps:
              - run: echo hello
        """))
    return tmp_path


def ctl(**over):
    c = {"id": "T-1", "statement": "s", "limits": "l", "mechanism": [{"file": "app/m.py", "symbol": "mechanism"}],
         "tests": ["tests/test_a.py::test_ok"], "ci": [{"workflow": "all.yml", "job": "unit"}]}
    c.update(over)
    return c


def errs(repo, **over):
    return cc.check([ctl(**over)], repo)[0]


def test_a_sound_control_passes(repo):
    assert errs(repo) == []


@pytest.mark.parametrize("over,needle", [
    ({"tests": ["tests/test_a.py::test_missing"]}, "test not found"),
    ({"tests": ["tests/test_zzz.py::test_ok"]}, "test file missing"),
    ({"tests": []}, "no tests"),
    ({"mechanism": [{"file": "app/nope.py", "symbol": ""}]}, "mechanism file missing"),
    ({"mechanism": [{"file": "app/m.py", "symbol": "ghost"}]}, "symbol 'ghost' not found"),
    ({"ci": [{"workflow": "nope.yml", "job": "unit"}]}, "CI job missing"),
    ({"ci": [{"workflow": "all.yml", "job": "ghost"}]}, "CI job missing"),
    ({"ci": [{"workflow": "all.yml", "job": "lint"}]}, "runs no pytest"),
    ({"ci": []}, "no listed CI job runs"),
    ({"limits": ""}, "limits are required"),
    ({"statement": ""}, "limits are required"),
])
def test_broken_references_are_reported(repo, over, needle):
    assert any(needle in e for e in errs(repo, **over)), errs(repo, **over)


def test_ci_that_names_only_other_test_files_does_not_cover_the_control(repo):
    over = {"tests": ["tests/test_b.py::test_b"], "ci": [{"workflow": "all.yml", "job": "some"}]}
    assert any("no listed CI job runs tests/test_b.py" in e for e in errs(repo, **over))
    over = {"tests": ["tests/test_a.py::test_ok"], "ci": [{"workflow": "all.yml", "job": "some"}]}
    assert errs(repo, **over) == []


def test_duplicate_ids_are_reported(repo):
    errors, _ = cc.check([ctl(), ctl()], repo)
    assert "duplicate control ids" in errors


def test_a_pip_install_line_is_not_a_test_run(repo):
    blocks = cc.workflow_jobs(repo / ".github" / "workflows" / "all.yml")
    assert cc.pytest_scope(blocks["unit"]) == {"*"} and cc.pytest_scope(blocks["lint"]) is None
    assert cc.pytest_scope("      - run: pip install pytest\n") is None
    assert cc.pytest_scope("      # pytest tests/test_a.py\n") is None


def test_only_module_level_test_functions_count(repo):
    (repo / "tests" / "test_n.py").write_text(
        "class Helper:\n    def test_method(self):\n        pass\n\ndef outer():\n    def test_nested():\n        pass\n\n"
        "def test_real():\n    pass\n")
    assert cc.test_functions(repo / "tests" / "test_n.py") == {"test_real"}
    assert any("test not found" in e for e in errs(repo, tests=["tests/test_n.py::test_method"]))
    assert any("test not found" in e for e in errs(repo, tests=["tests/test_n.py::test_nested"]))


def test_a_test_that_pytest_never_ran_is_not_a_pass(repo):
    """The id exists statically, but the module cannot be collected: no result must never read as a pass."""
    (repo / "tests" / "test_c.py").write_text("def test_c():\n    assert True\n\nraise RuntimeError('cannot import')\n")
    controls = [ctl(id="C", tests=["tests/test_c.py::test_c"], ci=[{"workflow": "all.yml", "job": "unit"}])]
    _, info = cc.check(controls, repo)
    assert info["C"]["status"] == "NOT_RUN"
    cc.run_tests(controls, info, repo)
    assert info["C"]["status"] == "FAILING" and info["C"]["results"] == {"tests/test_c.py::test_c": "missing"}


def test_a_parametrized_test_counts_only_when_every_instance_passes(repo):
    (repo / "tests" / "test_p.py").write_text(
        "import pytest\n\n@pytest.mark.parametrize('x', [1, 2, 3])\ndef test_all_good(x):\n    assert x > 0\n\n"
        "@pytest.mark.parametrize('x', [1, 2, 3])\ndef test_one_bad(x):\n    assert x != 2\n\n"
        "@pytest.mark.parametrize('x', [1, 2])\ndef test_skipped(x):\n    pytest.skip('no')\n")
    controls = [ctl(id="P1", tests=["tests/test_p.py::test_all_good"]), ctl(id="P2", tests=["tests/test_p.py::test_one_bad"]),
                ctl(id="P3", tests=["tests/test_p.py::test_skipped"])]
    _, info = cc.check(controls, repo)
    cc.run_tests(controls, info, repo)
    assert {k: v["status"] for k, v in info.items()} == {"P1": "VERIFIED_LOCALLY", "P2": "FAILING", "P3": "FAILING"}, \
        "a skipped test is not a pass"


def test_run_computes_the_status_from_results_and_never_from_the_file(repo):
    controls = [ctl(id="GOOD"), ctl(id="BAD", tests=["tests/test_a.py::test_bad"]),
                ctl(id="MIXED", tests=["tests/test_a.py::test_ok", "tests/test_a.py::test_bad"]),
                ctl(id="BROKEN", tests=["tests/test_a.py::test_ghost"]), ctl(id="B2", tests=["tests/test_b.py::test_b"])]
    _, info = cc.check(controls, repo)
    cc.run_tests(controls, info, repo)
    assert {k: v["status"] for k, v in info.items()} == {
        "GOOD": "VERIFIED_LOCALLY", "BAD": "FAILING", "MIXED": "FAILING", "BROKEN": "BROKEN_REFERENCE", "B2": "VERIFIED_LOCALLY"}
    assert info["MIXED"]["results"] == {"tests/test_a.py::test_ok": "passed", "tests/test_a.py::test_bad": "failed"}
