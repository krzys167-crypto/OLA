from pathlib import Path
import textwrap


ROOT = Path(__file__).resolve().parents[1]


def workflow(name: str) -> str:
    return (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")


def trigger_block(source: str, next_section: str) -> str:
    lines = source.splitlines()
    start = lines.index("on:")
    end = lines.index(f"{next_section}:")
    return chr(10).join(lines[start + 1:end])


def test_nina_ollama_workflow_is_reusable_not_a_second_pr_or_main_push_trigger():
    triggers = trigger_block(workflow("nina-igor-ollama.yml"), "permissions")

    assert "  workflow_call:" in triggers
    assert "  workflow_dispatch:" in triggers
    assert "  pull_request:" not in triggers
    push = triggers[triggers.index("  push:"):]
    assert "- feat/evidence-graph-v0.1" in push
    assert "- main" not in push


def test_12h_flow_is_the_single_full_flow_for_pr_and_main_push():
    triggers = trigger_block(workflow("ola-12h-autoflow.yml"), "concurrency")

    assert "  schedule:" in triggers
    assert "  workflow_dispatch:" in triggers
    assert "  pull_request:" in triggers
    assert "  push:" in triggers
    assert "paths:" not in triggers


def test_12h_concurrency_isolates_prs_from_main_evidence_runs():
    source = workflow("ola-12h-autoflow.yml")
    group = next(line for line in source.splitlines() if line.strip().startswith("group:"))

    assert "github.event.pull_request.number" in group
    assert "github.ref" in group
    assert "cancel-in-progress: false" in source


def test_final_gate_verifies_nested_nina_igor_and_aggregator_in_12h_run():
    source = workflow("final-production-gate.yml")
    start = source.index("required_exact = [")
    end = source.index("]", start)
    required = source[start:end]

    assert "OLA 12h Autonomous Evidence Flow" in required
    assert "NINA IGOR Ollama Full Flow" not in required
    assert 'autoflow_run = exact.get("OLA 12h Autonomous Evidence Flow")' in source
    assert "real_ollama_flow / nina-igor-ollama-full-flow" in source
    assert "real_ollama_flow / igor-independent-ollama / igor-ollama" in source
    assert '"OLA 12h Evidence Aggregator": "classify"' in source
    assert 'jobs_by_name.setdefault(job.get("name"), job)' in source


def test_final_gate_embedded_python_is_syntactically_valid():
    source = workflow("final-production-gate.yml")
    marker = "if python - <<'PY'"
    start = source.index(marker)
    newline = chr(10)
    body_start = source.index(newline, start) + 1
    body_end = source.index(newline + "          PY", body_start)
    body = source[body_start:body_end]
    compile(
        textwrap.dedent(body),
        "final-production-gate.yml::<embedded-python>",
        "exec",
    )
