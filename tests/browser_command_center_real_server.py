"""Command Center in a real browser against a REAL OLA server.

Nothing is stubbed: a uvicorn subprocess serves the app over real HTTP on a
temporary SQLite database; tenants are provisioned by DB insert (as in the
product gate) and real /agent-run, /nina-run and /approve calls create the
evidence. NINA, IGOR, replay and the Human Gate run the production code in
``OLA_LLM_MODE=deterministic`` with the local model (no external LLM).

Run explicitly (it is not collected by the default suite because it needs a
browser; the aurora-e2e workflow runs it and fails if playwright is missing):

    python -m pip install playwright==1.57.0 && python -m playwright install chromium
    python -m pytest tests/browser_command_center_real_server.py -q

What it proves: the console renders exactly what /control/overview returns,
labels stored states as REC / LOCAL (never as independent VERIFIED), resets on
error and key change, never shows another tenant's data, and never shows GO.
It is not production evidence: the source commit is declared, not signed.
"""
from __future__ import annotations

import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import pytest
from playwright.sync_api import sync_playwright

from app.api_key_crypto import hash_api_key

REPO = Path(__file__).resolve().parents[1]
COMMIT = "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12"  # declared, unsigned -> DECLARED_SHA_NOT_SIGNED
TASK = "Calculate 17 * 23 and return the verified result."
EVIDENCE_DIR = Path(os.getenv("AURORA_EVIDENCE_DIR", str(REPO / "aurora-evidence")))
MOCKUP_NUMBERS = ("1,284", "12,931", "48,672")
POSITIVE_GO = re.compile(r"(?<![A-Za-z-])GO(?![A-Za-z-])")


@dataclass
class Tenant:
    name: str
    tenant_id: str
    key: str
    approver_key: str | None = None
    runs: list[str] = field(default_factory=list)  # oldest first


@dataclass
class Server:
    base: str
    tenants: dict[str, Tenant]

    def overview(self, key: str) -> dict:
        r = httpx.get(self.base + "/control/overview", headers={"X-API-Key": key}, timeout=30)
        assert r.status_code == 200, r.text
        return r.json()


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _provision(db: Path, name: str, keys: int = 1) -> Tenant:
    tenant_id = str(uuid.uuid4())
    raw = [f"cc-e2e-{name}-{uuid.uuid4().hex}" for _ in range(keys)]
    con = sqlite3.connect(db, timeout=15)
    try:
        con.execute("INSERT INTO tenants(id,name) VALUES (?,?)", (tenant_id, f"cc-e2e-{name}"))
        for token in raw:
            con.execute(
                "INSERT INTO api_keys(id,tenant_id,key_hash) VALUES (?,?,?)",
                (str(uuid.uuid4()), tenant_id, hash_api_key(token)),
            )
        con.commit()
    finally:
        con.close()
    return Tenant(name=name, tenant_id=tenant_id, key=raw[0], approver_key=raw[1] if keys > 1 else None)


def _nina_run(base: str, tenant: Tenant) -> dict:
    r = httpx.post(
        base + "/nina-run",
        headers={"X-API-Key": tenant.key},
        json={"task": TASK, "requested_tools": ["safe_expression"], "human_approved": False},
        timeout=60,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["nina"]["status"] == "VERIFIED" and body["igor"]["status"] == "VERIFIED", body
    tenant.runs.append(body["run_id"])
    return body


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    work = tmp_path_factory.mktemp("cc-real-server")
    db = work / "ola.db"
    env = {
        k: v for k, v in os.environ.items()
        if k not in {"OLA_LLM_PROVIDER", "OLA_LLM_MODEL", "OPENAI_API_KEY", "OLLAMA_BASE_URL"}
    }
    env.update(
        OLA_EG_DB_PATH=str(db),
        OLA_LLM_MODE="deterministic",
        OLA_RUNTIME_COMMIT=COMMIT,
        PYTHONDONTWRITEBYTECODE="1",
    )
    assert len(env["OLA_API_KEY_PEPPER"].encode()) >= 32
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    log_path = work / "server.log"
    with log_path.open("w") as log:
        proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
            cwd=REPO, env=env, stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.time() + 45
            while True:
                if proc.poll() is not None:
                    pytest.fail("server exited early:\n" + log_path.read_text())
                try:
                    if httpx.get(base + "/health", timeout=2).status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                if time.time() > deadline:
                    pytest.fail("server did not become healthy:\n" + log_path.read_text())
                time.sleep(0.3)

            a = _provision(db, "A")
            b = _provision(db, "B")
            c = _provision(db, "C", keys=2)
            d = _provision(db, "D")
            e = _provision(db, "E")  # never runs anything: no evidence at all
            ok = httpx.post(base + "/agent-run", headers={"X-API-Key": a.key}, json={"task": TASK}, timeout=60)
            assert ok.status_code == 200 and ok.json()["status"] == "VERIFIED", ok.text
            _nina_run(base, a)
            _nina_run(base, a)
            _nina_run(base, b)
            run_c = _nina_run(base, c)
            approval = httpx.post(
                f"{base}/nina-run/{run_c['run_id']}/approve",
                headers={"Authorization": f"Bearer {c.approver_key}"},
                json={"tip_hash": run_c["tip_hash"]},
                timeout=60,
            )
            assert approval.status_code == 200, approval.text
            _nina_run(base, d)
            yield Server(base=base, tenants={"A": a, "B": b, "C": c, "D": d, "E": e})
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as p:
        no_sandbox = ["--no-sandbox"] if getattr(os, "geteuid", lambda: 1)() == 0 else []
        b = p.chromium.launch(headless=True, args=no_sandbox)
        yield b
        b.close()


@pytest.fixture
def page(browser, server):
    ctx = browser.new_context(viewport={"width": 1440, "height": 900})
    pg = ctx.new_page()
    pg.set_default_timeout(15000)
    script_errors: list[str] = []
    pg.on("pageerror", lambda exc: script_errors.append(str(exc)))
    pg.goto(server.base + "/")
    pg.wait_for_selector("#ccQueue")
    pg.wait_for_function("document.getElementById('ccEvidence').textContent==='ROUTE READY'")
    yield pg
    ctx.close()
    assert not script_errors, script_errors


# ---------------------------------------------------------------- helpers
def nav(page, view: str) -> None:
    page.locator(f'[data-view="{view}"]').first.click()


def text(page, element_id: str) -> str:
    return (page.locator("#" + element_id).text_content() or "").strip()


def authenticate(page, key: str) -> None:
    nav(page, "settings")
    page.fill("#apiKey", key)
    page.click("#verifyApiKey")
    page.locator("#keyState").get_by_text("UWIERZYTELNIONY").wait_for()
    page.wait_for_function("document.getElementById('ccMonitorState').textContent.startsWith('AUTHENTICATED')")


def queue_ids(page) -> list[str]:
    return page.eval_on_selector_all("#ccQueue button.cc-run", "bs=>bs.map(b=>b.dataset.runId)")


def band_is_empty(page) -> bool:
    return (
        text(page, "ccmRecords") == "UNKNOWN"
        and "Brak zweryfikowanej sesji" in text(page, "ccQueue")
        and "tip " not in text(page, "ccChain")
        and queue_ids(page) == []
    )


def agent_core(page) -> dict[str, str]:
    return {i: text(page, i) for i in ("ccNina", "ccCore", "ccEvidence", "ccIgor", "ccGate", "ccReplay")}


def visible_state_text(page) -> str:
    return page.evaluate(
        "['.cc-grid','.cc-band','#panel-control'].map(s=>document.querySelector(s).textContent).join('\\n')"
    )


def fulfill_overview(page, payload: dict | None = None, status: int = 200) -> None:
    page.route(
        "**/control/overview",
        lambda route: route.fulfill(status=status, content_type="application/json", body=json.dumps(payload or {})),
    )


# ---------------------------------------------------------------- tests
def test_fixture_is_not_vacuous(server):
    """If the seeds were wrong the browser tests below would pass for the wrong reason."""
    a, b, c, e = (server.tenants[k] for k in "ABCE")
    ov = server.overview(a.key)
    assert ov["schema"] == "ola.command-center.v1" and ov["tenant_id"] == a.tenant_id
    assert ov["evidence"]["status"] == "VERIFIED" and ov["evidence"]["record_count"] >= 20
    assert [r["run_id"] for r in ov["runs"]] == list(reversed(a.runs)) and len(ov["runs"]) == 2
    assert all(r["human_approval_recorded"] is False and r["nina_status_recorded"] == "VERIFIED" for r in ov["runs"])
    assert ov["production"]["status"] == "NO-GO" and ov["source"]["status"] == "DECLARED_SHA_NOT_SIGNED"
    assert len(server.overview(b.key)["runs"]) == 1
    assert server.overview(c.key)["runs"][0]["human_approval_recorded"] is True
    empty = server.overview(e.key)
    assert empty["evidence"]["status"] == "UNKNOWN" and empty["runs"] == []
    assert len({t.tenant_id for t in server.tenants.values()}) == 5


def test_unauthenticated_everything_unknown(page):
    assert band_is_empty(page)
    core = agent_core(page)
    assert core["ccNina"] == core["ccIgor"] == core["ccGate"] == core["ccReplay"] == "UNKNOWN"
    assert core["ccEvidence"] == "ROUTE READY"  # route exists in /openapi.json: presence, not execution
    assert text(page, "ccrProd") == "NO-GO"
    assert not [v for v in core.values() if v.startswith(("REC ", "LOCAL "))], core  # the legend text may say REC; a badge must not


def test_wrong_key_never_populates(page):
    nav(page, "settings")
    page.fill("#apiKey", "definitely-not-a-key")
    page.click("#verifyApiKey")
    page.locator("#statusLog").get_by_text("HTTP 401").wait_for()
    assert text(page, "keyState") != "UWIERZYTELNIONY"
    assert band_is_empty(page) and agent_core(page)["ccNina"] == "UNKNOWN"


def test_band_renders_exactly_what_the_api_returns(page, server):
    a = server.tenants["A"]
    api = server.overview(a.key)
    authenticate(page, a.key)
    page.wait_for_selector("#ccQueue button.cc-run")

    assert queue_ids(page) == [r["run_id"] for r in api["runs"]]
    first_row = page.locator("#ccQueue li").first.text_content()
    latest = api["runs"][0]
    assert f"NINA {latest['nina_status_recorded']}" in first_row
    assert latest["candidate_status_recorded"] in first_row
    assert "RECORDED, nie niezależny podpis" in first_row

    recent = api["recent_events"]
    assert page.locator("#ccEvents li.row").count() == len(recent)
    newest = recent[-1]
    assert page.locator("#ccEvents li.row").first.text_content().startswith(f"#{newest['seq']} · {newest['type']}")
    blocks = page.locator("#ccChain .cc-block")
    assert blocks.count() == len(recent)
    tip = blocks.last
    assert "tip" in (tip.get_attribute("class") or "")
    assert f"tip {api['evidence']['tip_hash'][:12]}" in tip.text_content()
    meta = text(page, "ccChainMeta")
    assert f"rekordy: {api['evidence']['record_count']}" in meta
    assert "LOCAL_SQLITE_HASH_CHAIN_NOT_EXTERNAL_ATTESTATION" in meta

    assert text(page, "ccmRecords") == str(api["evidence"]["record_count"])
    assert text(page, "ccmRuns") == str(len(api["runs"]))
    assert text(page, "ccrProd") == "NO-GO"
    assert text(page, "ccrSource").startswith(COMMIT[:12]) and "DECLARED_SHA_NOT_SIGNED" in text(page, "ccrSource")
    assert "łączność UNKNOWN" in text(page, "ccrLlm")
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    page.locator(".cc-grid").scroll_into_view_if_needed()
    page.screenshot(path=str(EVIDENCE_DIR / "command-center-real-server.png"), full_page=True, animations="disabled")


def test_agent_core_and_band_tell_the_same_recorded_story(page, server):
    a, c = server.tenants["A"], server.tenants["C"]
    authenticate(page, a.key)
    page.wait_for_selector("#ccQueue button.cc-run")
    core = agent_core(page)
    row = page.locator("#ccQueue li").first.text_content()
    assert core["ccNina"] == "REC VERIFIED" and "NINA VERIFIED" in row
    assert core["ccReplay"] == "REC VERIFIED" and "REPLAY VERIFIED" in row
    assert core["ccGate"] == "REC REVIEW" and "REVIEW" in row and "APPROVAL RECORDED" not in row
    assert core["ccEvidence"] == "LOCAL VERIFIED" and "Łańcuch: VERIFIED" in text(page, "ccChainMeta")
    assert core["ccIgor"] == "UNKNOWN"  # IGOR is not stored in evidence: no invented state
    for element_id in ("ccNina", "ccGate", "ccReplay", "ccEvidence"):
        classes = page.locator("#" + element_id).get_attribute("class") or ""
        assert "recorded" in classes and "verified" not in classes.split(), (element_id, classes)
        assert page.locator("#" + element_id).get_attribute("data-source") in {"recorded", "local-chain"}
    # Stored approval is shown as a stored approval, on both panels.
    authenticate(page, c.key)
    page.wait_for_selector("#ccQueue button.cc-run")
    assert agent_core(page)["ccGate"] == "REC APPROVAL"
    assert "APPROVAL RECORDED" in page.locator("#ccQueue li").first.text_content()


def test_live_session_answer_beats_recorded_and_is_not_labelled_rec(page, server):
    d = server.tenants["D"]
    authenticate(page, d.key)
    page.wait_for_selector("#ccQueue button.cc-run")
    assert agent_core(page)["ccNina"] == "REC VERIFIED"
    nav(page, "operations")
    page.fill("#runTask", TASK)
    page.click("#runSend")
    page.wait_for_function("document.getElementById('runResult').textContent.includes('\"tip_hash\"')")
    core = agent_core(page)
    assert core["ccNina"] == "VERIFIED" and core["ccIgor"] == "VERIFIED", core
    assert not any(v.startswith("REC ") for k, v in core.items() if k in {"ccNina", "ccIgor", "ccReplay"})
    assert "verified" in (page.locator("#ccNina").get_attribute("class") or "").split()
    # Forgetting the key must drop BOTH the recorded and the live state: no residue of the tenant.
    nav(page, "settings")
    page.click("#forgetKey")
    page.wait_for_function("document.getElementById('ccNina').textContent==='UNKNOWN'")
    core = agent_core(page)
    assert core["ccNina"] == core["ccIgor"] == core["ccGate"] == core["ccReplay"] == "UNKNOWN", core
    assert core["ccEvidence"] == "ROUTE READY" and band_is_empty(page)


def test_typing_a_new_key_clears_everything_immediately(page, server):
    authenticate(page, server.tenants["A"].key)
    page.wait_for_selector("#ccQueue button.cc-run")
    page.fill("#apiKey", "x")
    assert band_is_empty(page)
    core = agent_core(page)
    assert core["ccNina"] == core["ccGate"] == core["ccReplay"] == "UNKNOWN" and core["ccEvidence"] == "ROUTE READY"
    assert text(page, "ccrProd") == "NO-GO"


def test_forget_key_clears_band_and_agent_core(page, server):
    authenticate(page, server.tenants["A"].key)
    page.wait_for_selector("#ccQueue button.cc-run")
    page.click("#forgetKey")
    page.wait_for_function("document.getElementById('ccmRecords').textContent==='UNKNOWN'")
    assert band_is_empty(page) and agent_core(page)["ccNina"] == "UNKNOWN"
    assert page.locator("#apiKey").input_value() == ""


def test_server_error_resets_to_unknown_and_keeps_no_go(page, server):
    authenticate(page, server.tenants["A"].key)
    page.wait_for_selector("#ccQueue button.cc-run")
    fulfill_overview(page, status=500)
    nav(page, "control")
    page.click("#ccRefresh")
    page.wait_for_function("document.getElementById('ccMonitorDetails').textContent==='CONTROL PLANE: HTTP 500'")
    assert band_is_empty(page)
    assert agent_core(page)["ccNina"] == "UNKNOWN" and agent_core(page)["ccEvidence"] == "ROUTE READY"
    assert text(page, "ccMonitorState") == "UNKNOWN" and text(page, "ccrProd") == "NO-GO"


def test_wrong_schema_is_refused_not_rendered(page, server):
    authenticate(page, server.tenants["A"].key)
    page.wait_for_selector("#ccQueue button.cc-run")
    fulfill_overview(page, {"schema": "evil.v9", "tenant_id": "t", "runs": [{"run_id": "zzzzzzzz-fake", "candidate_status_recorded": "VERIFIED"}]})
    nav(page, "control")
    page.click("#ccRefresh")
    page.wait_for_function("document.getElementById('ccMonitorDetails').textContent==='CONTROL PLANE: INVALID_CONTROL_SCHEMA'")
    assert band_is_empty(page) and "zzzzzzzz" not in page.content()


def test_hostile_overview_values_are_text_never_markup(page, server):
    a = server.tenants["A"]
    real = server.overview(a.key)
    hostile = "<img src=x onerror=window.__pwned=1>"
    forged = json.loads(json.dumps(real))
    forged["runs"][0].update(run_id=hostile, nina_status_recorded=hostile, candidate_status_recorded=hostile)
    forged["recent_events"][-1].update(type=hostile)
    forged["llm"]["provider_configured"] = hostile
    authenticate(page, a.key)
    page.wait_for_selector("#ccQueue button.cc-run")
    fulfill_overview(page, forged)
    nav(page, "control")
    page.click("#ccRefresh")
    page.wait_for_function("document.querySelector('#ccQueue button.cc-run').dataset.runId.startsWith('<img')")
    assert page.evaluate("window.__pwned") is None
    assert page.locator(".cc-band img, .cc-grid img, #panel-control img").count() == 0
    assert hostile in (page.locator("#ccQueue li").first.text_content() or "")  # shown literally


def test_no_data_crosses_tenants_when_switching_keys(page, server):
    a, c = server.tenants["A"], server.tenants["C"]
    api_a, api_c = server.overview(a.key), server.overview(c.key)
    authenticate(page, a.key)
    page.wait_for_selector("#ccQueue button.cc-run")
    assert queue_ids(page) == [r["run_id"] for r in api_a["runs"]]
    nav(page, "settings")
    page.fill("#apiKey", c.key)
    assert band_is_empty(page) and agent_core(page)["ccGate"] == "UNKNOWN"  # cleared before C is even verified
    page.click("#verifyApiKey")
    page.wait_for_function("document.querySelectorAll('#ccQueue button.cc-run').length===1")
    assert queue_ids(page) == [r["run_id"] for r in api_c["runs"]]
    assert not set(queue_ids(page)) & {r["run_id"] for r in api_a["runs"]}
    assert text(page, "ccmRecords") == str(api_c["evidence"]["record_count"]) != str(api_a["evidence"]["record_count"])
    dom = page.content()
    leaked = [a.tenant_id, api_a["evidence"]["tip_hash"], a.key, *[r["run_id"] for r in api_a["runs"]]]
    assert not [token for token in leaked if token in dom], "tenant A data still present after switching to C"


def test_late_response_of_previous_tenant_never_renders(page, server):
    a, c = server.tenants["A"], server.tenants["C"]
    api_a, api_c = server.overview(a.key), server.overview(c.key)
    authenticate(page, a.key)
    page.wait_for_selector("#ccQueue button.cc-run")
    held = []

    def handler(route):
        if route.request.headers.get("x-api-key") == a.key:
            held.append(route)  # A's read stays in flight
        else:
            route.continue_()

    page.route("**/control/overview", handler)
    nav(page, "control")
    page.click("#ccRefresh")
    page.wait_for_function("document.getElementById('ccMonitorState').textContent==='SCANNING'")
    assert held, "A's refresh was not held in flight"
    nav(page, "settings")
    page.fill("#apiKey", c.key)  # operator switches tenant while A's read is pending
    page.click("#verifyApiKey")
    page.wait_for_function("document.querySelectorAll('#ccQueue button.cc-run').length===1")
    for route in held:  # now A's stale answer finally arrives
        try:
            route.fulfill(status=200, content_type="application/json", body=json.dumps(api_a))
        except Exception:
            pass  # the browser already aborted it; either outcome must leave C on screen
    page.wait_for_timeout(600)
    assert queue_ids(page) == [r["run_id"] for r in api_c["runs"]]
    dom = page.content()
    assert a.tenant_id not in dom and api_a["evidence"]["tip_hash"] not in dom


def test_click_on_a_run_opens_the_replay_inspector(page, server):
    a = server.tenants["A"]
    runs = [r["run_id"] for r in server.overview(a.key)["runs"]]
    authenticate(page, a.key)
    page.wait_for_selector("#ccQueue button.cc-run")
    for index, run_id in enumerate(runs):
        nav(page, "home")
        page.locator("#ccQueue button.cc-run").nth(index).click()
        page.wait_for_function(
            "id=>document.getElementById('ccMonitorDetails').textContent.includes(id)&&document.getElementById('ccMonitorDetails').textContent.includes('LOCAL_HASH_AND_REPLAY_ONLY')",
            arg=run_id,
        )
        assert page.locator("#panel-control").is_visible()
        assert page.locator("#ccRunSelect").input_value() == run_id
        state = text(page, "ccMonitorState")
        assert state == "LOCAL REPLAY VERIFIED · RELEASE NO-GO", state
        detail = json.loads(text(page, "ccMonitorDetails"))
        assert detail["run_id"] == run_id and detail["scope"] == "LOCAL_HASH_AND_REPLAY_ONLY"
        assert detail["production"] == "NO-GO" and detail["independent_release_verification"] == "UNKNOWN"
        assert a.key not in text(page, "ccMonitorDetails")


def test_tenant_without_evidence_is_unknown_not_verified(page, server):
    authenticate(page, server.tenants["E"].key)
    assert "Brak zapisanych runów" in text(page, "ccQueue")
    core = agent_core(page)
    assert core["ccEvidence"] == "LOCAL UNKNOWN" and core["ccNina"] == core["ccGate"] == core["ccReplay"] == "UNKNOWN"
    badges = " ".join(list(core.values()) + [text(page, i) for i in ("ccL1", "ccL2", "ccL3", "ccL4", "ccL5", "ccChainMeta", "ccQueue")])
    assert "VERIFIED" not in badges, badges
    assert text(page, "ccrProd") == "NO-GO"


def test_release_stays_no_go_in_every_state(page, server):
    a = server.tenants["A"]
    states = {}

    def sample(label):
        states[label] = (text(page, "ccrProd"), POSITIVE_GO.findall(visible_state_text(page)))

    sample("unauthenticated")
    authenticate(page, a.key)
    page.wait_for_selector("#ccQueue button.cc-run")
    sample("authenticated")
    page.locator("#ccQueue button.cc-run").first.click()
    page.wait_for_function("document.getElementById('ccMonitorState').textContent.startsWith('LOCAL REPLAY')")
    sample("replay")
    assert "RELEASE NO-GO" in text(page, "ccMonitorState")
    fulfill_overview(page, status=500)
    page.click("#ccRefresh")
    page.wait_for_function("document.getElementById('ccMonitorDetails').textContent==='CONTROL PLANE: HTTP 500'")
    sample("after-error")
    assert states and all(prod == "NO-GO" and not go for prod, go in states.values()), states
    assert server.overview(a.key)["production"]["status"] == "NO-GO"


def test_no_invented_telemetry(page, server):
    authenticate(page, server.tenants["A"].key)
    page.wait_for_selector("#ccQueue button.cc-run")
    shown = visible_state_text(page) + page.locator("body").inner_text()
    assert not [n for n in MOCKUP_NUMBERS if n in shown]
    assert not re.search(r"\d+\s*%", page.locator(".cc-grid, .cc-band").evaluate_all("els=>els.map(e=>e.textContent).join(' ')"))
    metrics = page.locator(".cc-band .cc-kv").first
    values = metrics.locator("dd")
    for i in range(values.count()):
        dd = values.nth(i)
        element_id = dd.get_attribute("id")
        if element_id in {"ccmRecords", "ccmRuns"}:
            assert (dd.text_content() or "").strip().isdigit()
        else:
            assert (dd.text_content() or "").strip() == "Niepodłączone" and "na" in (dd.get_attribute("class") or "").split()
    labels = metrics.locator("dt").all_text_contents()
    for unmeasured in ("Zdarzenia / h", "Opóźnienie API", "CPU · RAM · GPU"):
        assert unmeasured in labels


def test_phone_layout_keeps_the_band_without_horizontal_scroll(browser, server):
    ctx = browser.new_context(viewport={"width": 390, "height": 844})
    pg = ctx.new_page()
    pg.set_default_timeout(15000)
    pg.goto(server.base + "/")
    pg.evaluate("document.querySelector('[data-view=settings]').click()")
    pg.fill("#apiKey", server.tenants["A"].key)
    pg.click("#verifyApiKey")
    pg.wait_for_selector("#ccQueue button.cc-run")
    assert pg.evaluate("document.documentElement.scrollWidth<=window.innerWidth+1")
    assert pg.locator(".cc-band").is_visible() and pg.locator("#ccChain").is_visible()
    ctx.close()
