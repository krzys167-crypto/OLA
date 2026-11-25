"""Security policy for the cryptography dependency floor."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = "50.0.2"


def _pins(path):
    pins = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^([A-Za-z0-9_.-]+)==([^\\s\\;]+)", line)
        if match:
            pins[match.group(1).lower().replace("_", "-")] = match.group(2)
    return pins


def test_cryptography_runtime_pin_and_hash_lock_are_exactly_50_0_2():
    assert _pins(ROOT / "requirements.txt").get("cryptography") == TARGET
    assert _pins(ROOT / "requirements.lock").get("cryptography") == TARGET


def test_project_python_floor_is_supported_by_cryptography_50():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r'requires-python\\s*=\\s*">=3\\.(9|1[0-9])', pyproject)
    assert "python3.13" in (ROOT / "Dockerfile").read_text(encoding="utf-8")


def test_cryptography_lock_entry_contains_sha256_hashes():
    lock = (ROOT / "requirements.lock").read_text(encoding="utf-8")
    match = re.search(
        r"(?ms)^cryptography==50\\.0\\.2\\s*\\\\\\n(.*?)(?=^[A-Za-z0-9_.-]+==|\\Z)",
        lock,
    )
    assert match, "cryptography==50.0.2 entry missing from requirements.lock"
    hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})", match.group(0))
    assert len(hashes) >= 2
