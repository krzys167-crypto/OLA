"""Lower Command Center band: real /control/overview data or an explicit 'Niepodłączone'. No invented telemetry."""
import re
from pathlib import Path

HTML = Path(__file__).resolve().parents[1] / "web" / "index.html"
REQUIRED_IDS = ("ccQueue", "ccEvents", "ccChain", "ccChainMeta", "ccmRecords", "ccmRuns",
                "ccrProd", "ccrSource", "ccrLlm", "ccrTrust")


def _text():
    return HTML.read_text(encoding="utf-8")


def _band_markup():
    text = _text()
    start = text.index('<section class="cc-band"')
    end = text.index('<section class="cc-local"')
    return text[start:end]


def test_band_has_required_ids_and_starts_unknown():
    band = _band_markup()
    for ident in REQUIRED_IDS:
        assert f'id="{ident}"' in band, ident
    assert 'id="ccmRecords">UNKNOWN<' in band
    assert 'id="ccrSource">UNKNOWN<' in band


def test_band_markup_contains_no_invented_numbers():
    visible = re.sub(r"<[^>]+>", " ", _band_markup())
    assert set(re.findall(r"\d+", visible)) <= {"12", "30"}  # "≤12 runs window", "refresh every 30 s"


def test_metrics_the_api_cannot_supply_are_marked_not_connected():
    band = _band_markup()
    assert band.count("Niepodłączone") >= 3
    for label in ("Zdarzenia / h", "Opóźnienie API", "CPU · RAM · GPU"):
        assert label in band


def test_band_is_fed_only_by_control_overview_and_resets_with_the_tenant_session():
    text = _text()
    assert "renderBand(result)" in text      # populated from /control/overview
    assert "renderBand(null)" in text        # cleared on key change / forget / error
    assert "ola.command-center.v1" in text   # schema gate stays in front of rendering
    # DOM is built with textContent/createElement only (innerHTML is already forbidden file-wide)
    assert "node('button','cc-run')" in text.replace('"', "'")


def test_run_status_is_labelled_recorded_not_independently_verified():
    text = _text()
    assert "RECORDED, nie niezależny podpis" in text
    assert "NO-GO" in _band_markup()


def test_agent_core_reads_the_same_overview_and_never_upgrades_recorded_to_verified():
    text = _text()
    assert "function syncAgentCore(data)" in text and "document.dispatchEvent(new Event('ola:recorded'))" in text
    assert "target.textContent = 'REC ' + recorded;" in text            # stored state is labelled REC
    assert "target.classList.remove('verified'); target.classList.add('recorded');" in text
    assert "chain.textContent = 'LOCAL ' + chain.dataset.recorded;" in text  # local recompute, not attestation
    assert "publish('ccIgor',null)" in text                              # IGOR is not in evidence: stays session-only
    assert "żaden nie jest niezależną weryfikacją" in text
