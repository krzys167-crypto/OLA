"""scripts/ci_annotate_runtime_failure.sh - a red real-LLM runtime step must say WHY as one annotation.

Job logs and artifacts are not always readable from outside the runner, annotations are (REST: check-runs/<id>/annotations).
The real-LLM job failed once on a commit that changed no application code and passed on the rerun; nothing recorded the
reason. These tests pin the helper (no Docker needed: `docker` is a stub on PATH) and the way the workflow uses it.
"""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ci_annotate_runtime_failure.sh"
GENERIC = ROOT / "scripts" / "ci_annotate_failure.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "ollama-real-runtime.yml"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash is required")


def _run(tmp_path, *args, docker_body="exit 0\n"):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    stub = bin_dir / "docker"
    stub.write_text("#!/usr/bin/env bash\n" + docker_body)
    stub.chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}
    return subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, cwd=tmp_path, env=env, timeout=30)


def _annotation_lines(proc):
    return [line for line in proc.stdout.splitlines() if line.startswith("::error")]


def test_the_annotation_carries_the_exit_status_the_container_log_and_the_step_stderr(tmp_path):
    stderr = tmp_path / "step-stderr.txt"
    stderr.write_text("Traceback (most recent call last):\nurllib.error.HTTPError: HTTP Error 500: Internal Server Error\n")
    docker = 'echo "INFO: Uvicorn running"\necho "RuntimeError: LLM proposed result 391.0"\n'
    proc = _run(tmp_path, "7", "real runtime failed", str(stderr), docker_body=docker)
    assert proc.returncode == 0, proc.stderr
    lines = _annotation_lines(proc)
    assert len(lines) == 1, proc.stdout                       # ONE annotation, one workflow-command line
    line = lines[0]
    assert line.startswith("::error title=real runtime failed::"), line
    for expected in ("exit status 7", "RuntimeError: LLM proposed result 391.0", "HTTP Error 500", "OLA container log"):
        assert expected in line, (expected, line)
    assert "%0A" in line and "\n" not in line                 # newlines are escaped, the command stays on one line


def test_percent_signs_and_carriage_returns_are_escaped_for_the_workflow_command(tmp_path):
    stderr = tmp_path / "e.txt"
    stderr.write_bytes(b"100% sure\r\nnext\n")
    proc = _run(tmp_path, "1", "t", str(stderr))
    (line,) = _annotation_lines(proc)
    assert "100%25 sure" in line and "%0D" in line and "\r" not in line, line


def test_a_missing_container_or_stderr_file_still_gives_an_annotation_and_the_helper_never_fails(tmp_path):
    proc = _run(tmp_path, "3", "t", str(tmp_path / "does-not-exist.txt"), docker_body='echo "no such container" >&2\nexit 1\n')
    assert proc.returncode == 0, proc.stderr                  # the step keeps its own exit status, the helper adds a note
    (line,) = _annotation_lines(proc)
    assert "exit status 3" in line and "no such container" in line and "step stderr" not in line, line


def test_an_overlong_log_is_cut_to_what_one_annotation_can_carry(tmp_path):
    stderr = tmp_path / "e.txt"
    stderr.write_text("".join(f"line {i} " + "x" * 600 + "\n" for i in range(200)))
    proc = _run(tmp_path, "1", "t", str(stderr), docker_body="".join(f'echo "container {i} {"y" * 600}"\n' for i in range(60)))
    (line,) = _annotation_lines(proc)
    assert len(line) < 4500, len(line)                        # GitHub truncates a longer message; the tail is what matters
    assert "line 199" in line                                 # the END of the step stderr (the actual exception) survives


def test_the_generic_helper_keeps_the_end_of_a_long_log_not_its_beginning(tmp_path):
    """The assertion and the summary line are the LAST lines of a pytest log; with long lines the first 3.5 kB used to win."""
    log = tmp_path / "pytest.txt"
    log.write_text("".join(f"context line {i} " + "c" * 380 + "\n" for i in range(60)) + "E   AssertionError: the real reason\n"
                   "1 failed in 602.80s\n")
    proc = subprocess.run(["bash", str(GENERIC), str(log), "live bridge test failed"], capture_output=True, text=True, timeout=30)
    (line,) = [x for x in proc.stdout.splitlines() if x.startswith("::error")]
    assert "AssertionError: the real reason" in line and "1 failed in 602.80s" in line, line[-300:]
    assert len(line) < 4000, len(line)


def test_the_workflow_uses_the_helper_and_a_red_step_stays_red():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "scripts/ci_annotate_runtime_failure.sh" in text and SCRIPT.is_file()
    # the gate itself did not change: same assertions, same expected values
    for must_stay in ('assert result["status"]=="VERIFIED"', 'assert result["final_result"]=="391"',
                      'assert len(result["execution"])==6', '--expected-invocation-type "real_llm"'):
        assert must_stay in text, must_stay
    # the diagnostic runs in an EXIT trap that only fires on a non-zero status and never calls `exit 0`
    trap_lines = [line for line in text.splitlines() if line.strip().startswith("trap ")]
    assert len(trap_lines) == 2, trap_lines
    for line in trap_lines:
        assert '-ne 0' in line or '-eq 0' in line, line
        assert "exit 0" not in line, line
