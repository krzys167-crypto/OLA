"""requirements.lock must stay in step with requirements.txt and carry hashes for every package."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _pins(path):
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^([A-Za-z0-9_.-]+)==([^\s\;]+)", line)
        if m:
            out[m.group(1).lower().replace("_", "-")] = m.group(2)
    return out


def test_every_direct_pin_is_in_the_lock_at_the_same_version():
    direct = _pins(ROOT / "requirements.txt")
    locked = _pins(ROOT / "requirements.lock")
    assert direct, "requirements.txt has no exact pins"
    for name, version in direct.items():
        assert locked.get(name) == version, f"{name}: requirements.txt has {version}, lock has {locked.get(name)}"


def test_every_locked_package_has_at_least_one_sha256_hash():
    text = (ROOT / "requirements.lock").read_text(encoding="utf-8")
    blocks = re.split(r"\n(?=[A-Za-z0-9_.-]+==)", text)
    pkgs = [b for b in blocks if re.match(r"[A-Za-z0-9_.-]+==", b)]
    assert len(pkgs) >= 20
    for b in pkgs:
        assert re.search(r"--hash=sha256:[0-9a-f]{64}", b), b.splitlines()[0]


def test_the_dockerfile_installs_only_from_the_hashed_lock():
    d = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "--require-hashes -r requirements.lock" in d
    assert "COPY requirements.txt requirements.lock" in d
    assert not re.search(r"pip install[^\n]*-r requirements\.txt", d)
