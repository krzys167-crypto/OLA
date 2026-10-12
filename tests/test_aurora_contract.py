"""Contract tests: existing OLA APIs, never invented endpoints or fabricated status."""
from html.parser import HTMLParser
from pathlib import Path
import re
import subprocess
import shutil
import tempfile

HTML = Path(__file__).resolve().parents[1] / "web/index.html"


class IndexParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.buttons = []
        self.scripts = []
        self.inscript = False
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.add(attrs["id"])
        if tag == "button":
            self.buttons.append(attrs)
        if tag == "script" and "src" not in attrs:
            self.inscript = True
    def handle_endtag(self, tag):
        if tag == "script":
            self.inscript = False
    def handle_data(self, data):
        if self.inscript:
            self.scripts.append(data)


def page():
    text = HTML.read_text(encoding="utf-8")
    p = IndexParser()
    p.feed(text)
    return text, p


def test_aurora_has_real_control_surfaces():
    _, p = page()
    assert {"apiKey", "chatForm", "chatInput", "chatMessages", "healthStatus", "auditForm", "auditTask", "runForm", "runTask", "approvalForm", "approverKey", "evidenceForm", "evidenceId", "statusLog"} <= p.ids


def test_real_api_routes_and_no_fake_performance():
    text, _ = page()
    for path in ['/health', '/chat', '/nina-run', '/audit', '/evidence/', '/approve']:
        assert path in text
    # Product telemetry is not in OLA Core. We must never fabricate CPU or uptime metrics.
    assert 'Math.random(' not in text
    assert '1.2 Gbps' not in text
    assert 'No threats found' not in text
    assert 'All systems operational' not in text


def test_security_no_secrets_in_storage_no_html_injection():
    text, _ = page()
    assert 'localStorage' not in text
    assert 'sessionStorage' not in text
    assert 'innerHTML' not in text
    assert 'textContent' in text
    assert 'X-API-Key' in text
    assert 'Bearer ' in text


def test_mobile_accessibility_and_error_handling():
    text, p = page()
    assert '<html lang="pl">' in text
    assert 'name="viewport"' in text
    assert '@media' in text
    assert 'aria-live' in text
    assert 'AbortController' in text
    assert 'response.ok' in text
    assert 'Niepodłączone' in text


def test_inline_javascript_syntax():
    if not shutil.which('node'):
        return
    _, p = page()
    assert p.scripts, 'No inline script'
    with tempfile.TemporaryDirectory() as d:
        script = Path(d) / 'aurora.js'
        script.write_text('\n'.join(p.scripts), encoding='utf-8')
        res = subprocess.run(['node','--check',str(script)],capture_output=True,text=True)
        assert res.returncode == 0, res.stderr

def test_tenant_switch_revokes_stale_ui_and_inflight_results():
    text, _ = page()
    assert 'resetTenantSession' in text
    assert 'session.activeControllers.forEach(controller=>controller.abort())' in text
    assert text.count('epoch!==session.epoch') >= 5
    for view in ('chatMessages', 'runResult', 'approvalResult', 'auditResult', 'evidenceResult'):
        assert view in text
