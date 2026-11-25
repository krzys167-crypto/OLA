"""Security policy for the cryptography dependency floor."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = "50.0.2"


def _pins(path):
    pins = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split("==", 1)
        if len(parts) == 2:
            pins[parts[0].strip().lower().replace("_", "-")] = parts[1].split()[0]
    return pins


def test_cryptography_runtime_pin_and_hash_lock_are_exactly_50_0_2():
    assert _pins(ROOT / "requirements.txt").get("cryptography") == TARGET
    assert _pins(ROOT / "requirements.lock").get("cryptography") == TARGET


def test_project_python_floor_and_container_runtime_are_supported():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'requires-python = ">=3.11"' in pyproject
    assert "python3.13" in (ROOT / "Dockerfile").read_text(encoding="utf-8")


def test_cryptography_lock_entry_contains_sha256_hashes():
    lines = (ROOT / "requirements.lock").read_text(encoding="utf-8").splitlines()
    start = next(i for i, line in enumerate(lines) if line == "cryptography==50.0.2 \\")
    block = []
    for line in lines[start:]:
        block.append(line)
        if line.startswith("    # via"):
            break
    hashes = [line for line in block if "--hash=sha256:" in line]
    assert len(hashes) >= 2
