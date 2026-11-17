from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_production_image_removes_pytest_and_does_not_copy_test_suite():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "python -m pip uninstall -y pytest" in dockerfile
    assert "COPY tests ./tests" not in dockerfile


def test_test_toolchain_uses_security_fixed_pytest_and_setuptools():
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "pytest==9.0.3" in requirements
    assert "setuptools==84.1.0" in requirements
    assert "pytest>=9.0.3,<10" in pyproject
