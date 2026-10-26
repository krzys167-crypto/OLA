"""Regression checks for the source-pinned workstation installer.

These checks are intentionally static: PowerShell syntax and Docker runtime
still require independent Windows CI before an operational READY claim.
"""
from pathlib import Path
import re

SCRIPT = Path(__file__).resolve().parents[1] / "workstation" / "OLA-Workstation.ps1"


def test_workstation_script_is_single_and_source_pinned():
    text = SCRIPT.read_text(encoding="utf-8")
    assert text.count('Write-Gate "WORKSTATION" "READY"') == 1
    assert text.count("git verify-commit $SourceCommit") == 1
    assert text.count('docker build --tag $Image') == 1
    assert "^[0-9a-fA-F]{40}$" in text
    assert "OLA_SIGNER_FINGERPRINT" in text
    assert re.search(r'\$signatureStatus\s+-ne\s+"G"', text)
    assert "$signer -ine $ExpectedSigner" in text
    assert "git checkout --detach $SourceCommit" in text


def test_workstation_refuses_destructive_or_fixed_demo_secrets():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "Remove-Item -Recurse" not in text
    assert '$rawKey = "ola-workstation-key"' not in text
    assert '127.0.0.1:${Port}:8000' in text
    assert '("ola-source-" + $RunToken)' in text
    assert '("workstation-evidence-" + $RunToken)' in text


def test_workstation_checks_external_command_outcomes():
    text = SCRIPT.read_text(encoding="utf-8")
    for label in ("GIT_CLONE", "GIT_FETCH", "GIT_CHECKOUT", "SOURCE_SIGNATURE",
                  "IMAGE_BUILD", "PYTEST", "APPEND_ONLY_TAMPER"):
        assert f'Write-Gate "{label}" "BLOCKED"' in text
    assert "API_KEY_PEPPER" in text
