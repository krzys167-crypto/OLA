from pathlib import Path


WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ola-product-gate.yml"


def _step(text: str, name: str) -> str:
    marker = f"      - name: {name}\n"
    start = text.index(marker)
    next_step = text.find("\n      - name: ", start + len(marker))
    if next_step == -1:
        next_step = len(text)
    return text[start:next_step]


def test_required_openai_runtime_receives_fresh_replay_challenge():
    text = WORKFLOW.read_text(encoding="utf-8")

    challenge = _step(text, "Issue fresh anti-replay challenge")
    assert "openssl rand -hex 32" in challenge
    assert 'echo "OLA_REPLAY_NONCE=$OLA_REPLAY_NONCE" >> "$GITHUB_ENV"' in challenge

    start_runtime = _step(text, "Start runtime")
    assert "OLA_LLM_MODE:" in start_runtime and "'required'" in start_runtime
    assert '-e OLA_REPLAY_NONCE="$OLA_REPLAY_NONCE"' in start_runtime
