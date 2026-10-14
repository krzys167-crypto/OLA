"""Local Executor: explicit host boundary and opt-in browser action contract."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "workstation" / "OLA-Local-Executor.ps1"
HTML = ROOT / "web" / "index.html"


def test_bridge_has_strict_local_network_and_token_boundaries():
    script = RUNNER.read_text(encoding="utf-8")
    assert "http://127.0.0.1:$script:Port/" in script
    assert "$script:Port=18110" in script
    assert "Equal-Token" in script
    assert "Bearer $token" in script
    assert "BAD_ORIGIN" in script and "BAD_HOST" in script
    assert "ACTION_NOT_ALLOWLISTED" in script
    assert "LOCAL_LOG_NOT_INDEPENDENT_VERIFICATION" in script
    assert "production='NOT_VERIFIED'" in script
    for unsafe in ("Invoke-Expression", "ScriptBlock]::Create", "cmd.exe /c", "powershell.exe -Command", "netsh http add", "Start-Process -Verb RunAs"):
        assert unsafe not in script


def test_mutations_require_server_side_nonce_and_are_once_only():
    script = RUNNER.read_text(encoding="utf-8")
    assert "'docker-unpause-ola'=@{" in script
    assert "'docker-start-ola'=@{" in script
    assert "mode='confirm'" in script
    assert "APPROVAL_REQUIRED" in script
    assert "APPROVAL_EXPIRED_OR_INVALID" in script
    assert "$pending=$script:Approval;$script:Approval=@{}" in script
    assert "AddSeconds(30)" in script
    assert "WaitForExit(15000)" in script
    assert "Read-LocalBody" not in script  # Current handler uses bounded Parse-Body.


def test_frontend_executes_only_user_selected_registered_actions():
    html = HTML.read_text(encoding="utf-8")
    for node in ('localToken', 'localAction', 'localConnect', 'localRun',
                 'localDisconnect', 'localResult', 'localState'):
        assert f'id="{node}"' in html
    assert "const apiBase = 'http://127.0.0.1:18110'" in html
    assert "['18080','18081'].includes(location.port)" in html
    assert "actions.get(action)" in html
    assert "window.confirm(" in html
    assert "apiBase+'/v1/shell'" not in html
    assert "new Option(" in html
    assert 'localStorage' not in html and 'sessionStorage' not in html
    assert 'innerHTML' not in html



def test_state_changing_container_controls_verify_exact_immutable_target():
    bridge = RUNNER.read_text(encoding="utf-8")
    assert "Assert-AllowedMutation" in bridge
    assert "TARGET_IMAGE_MISMATCH" in bridge
    assert "TARGET_LOOPBACK_BINDING_MISMATCH" in bridge
    assert "UNSAFE_CONTAINER_CONFIGURATION" in bridge
    assert "ola-zbook-local:test" in bridge
    assert "127.0.0.1" in bridge
    assert "18080" in bridge
    assert "TARGET_NOT_PAUSED" in bridge
    assert "TARGET_NOT_STOPPED" in bridge


def test_authentication_controls_are_independent():
    html = HTML.read_text(encoding="utf-8")
    assert 'id="verifyApiKey"' in html
    assert '/auth/session' in html
    assert "UWIERZYTELNIONY" in html
    assert "NIEZWERYFIKOWANY" in html
    assert "credential" not in html.lower() or "localToken" in html
    assert "localToken" in html and "apiKey" in html
    auth = (ROOT / "workstation" / "OLA-Preview-Auth.ps1").read_text(encoding="utf-8")
    assert "AUTH_NOT_CONFIGURED" in auth
    assert "KEY_ISSUANCE_FAILED_OR_DUPLICATE_TENANT" in auth
    assert "docker.exe exec" in auth
    assert "OLA_API_KEY_PEPPER" in auth
    assert "no container restart" in auth
