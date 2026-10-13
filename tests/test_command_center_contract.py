"""OLA Command Center: no fabricated agent states or bypass of existing AURORA controls."""
from html.parser import HTMLParser
from pathlib import Path

HTML = Path(__file__).resolve().parents[1] / "web" / "index.html"


class Elements(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.routes = []
        self.views = []
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if attrs.get("id"):
            self.ids.add(attrs["id"])
        if attrs.get("data-view"):
            self.views.append(attrs["data-view"])


def page():
    text = HTML.read_text(encoding="utf-8")
    parsed = Elements()
    parsed.feed(text)
    return text, parsed


def test_real_command_center_is_part_of_original_audited_aurora():
    text, parsed = page()
    required = {"ccCore", "ccNina", "ccEvidence", "ccIgor", "ccGate", "ccReplay",
                "ccLive", "healthStatus", "ninaStatus", "igorStatus",
                "replayStatus", "humanStatus", "chatForm", "auditForm",
                "runForm", "approvalForm", "apiKey"}
    assert required.issubset(parsed.ids)
    assert all(view in parsed.views for view in ("chat", "operations", "evidence", "audit"))
    assert "new MutationObserver(reflect)" in text
    assert "/openapi.json" in text
    assert "ROUTE READY" in text


def test_visual_and_accessibility_contract():
    text, _ = page()
    assert "data:image/webp;base64," in text
    assert "cc-reticle" in text
    assert "aria-label" in text
    assert "@media(max-width:720px)" in text
    assert "prefers-reduced-motion" in text
    assert "MODEL PRZEPŁYWU" in text


def test_fail_closed_no_invented_telemetry_or_secrets():
    text, _ = page()
    assert "API UNKNOWN" in text
    assert "UNKNOWN" in text
    for unsafe in ("localStorage", "sessionStorage", "innerHTML", "Math.random("):
        assert unsafe not in text
    for invented in ("1,284", "12,931", "48,672", "All systems operational"):
        assert invented not in text
    assert "X-API-Key" in text
    assert "resetTenantSession" in text
    assert "epoch!==session.epoch" in text
