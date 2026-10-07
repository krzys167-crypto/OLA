"""The sales pipeline drafts and schedules; it must never contact anyone it was told not to, never invent a contact,
and never send."""
import csv
import datetime as dt
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sales_pipeline", ROOT / "scripts" / "sales_pipeline.py")
sp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sp)

D = dt.date(2026, 10, 7)


def write(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=sp.FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({**dict.fromkeys(sp.FIELDS, ""), **row})


@pytest.fixture
def table(tmp_path):
    path = tmp_path / "p.csv"
    write(path, [
        {"company": "Alpha", "sector": "accounting", "stage": "NEW", "contact": "hello@alpha.example"},
        {"company": "Beta", "sector": "property", "stage": "NEW", "contact": ""},
        {"company": "Gamma", "sector": "logistics", "stage": "DO_NOT_CONTACT", "contact": "x@gamma.example"},
    ])
    return path


def test_the_shipped_prospect_list_is_the_18_companies_from_the_issue_with_no_invented_contacts():
    rows = sp.load(sp.DEFAULT_CSV)
    assert len(rows) == 18 and {r["sector"] for r in rows} == {"property", "accounting", "logistics"}
    assert all(r["stage"] == "NEW" and r["contact"] == "" for r in rows)
    assert len({r["company"] for r in rows}) == 18


def test_a_prospect_without_a_contact_is_never_due(table, capsys):
    sp.main(["--csv", str(table), "due", "--today", D.isoformat()])
    out = capsys.readouterr()
    assert "Alpha" in out.out and "Beta" not in out.out
    assert "without a contact (cannot be touched): 1" in out.err


@pytest.mark.parametrize("stage", ["DO_NOT_CONTACT", "LOST", "WON"])
def test_a_closed_prospect_is_never_due_and_never_drafted(tmp_path, stage):
    path = tmp_path / "p.csv"
    write(path, [{"company": "Z", "sector": "x", "stage": stage, "contact": "z@z.example", "next_due": "2020-01-01"}])
    row = sp.load(path)[0]
    assert sp.is_due(row, D) is False
    with pytest.raises(SystemExit):
        sp.render(row, "en", "me")


def test_followups_follow_the_cadence_and_the_sequence_ends(table):
    rows = sp.load(table)
    alpha = sp.find(rows, "Alpha")
    sp.advance(alpha, "CONTACTED", D)
    assert alpha["next_due"] == "2026-10-10" and not sp.is_due(alpha, D) and sp.is_due(alpha, D + dt.timedelta(days=3))
    sp.advance(alpha, "FOLLOWUP1", D + dt.timedelta(days=3))
    assert alpha["next_due"] == "2026-10-14"
    sp.advance(alpha, "FOLLOWUP2", D + dt.timedelta(days=7))
    assert alpha["next_due"] == "" and not sp.is_due(alpha, D + dt.timedelta(days=365))   # the sequence ends, no endless nagging


def test_a_closed_prospect_is_not_reopened_by_the_script(table):
    gamma = sp.find(sp.load(table), "Gamma")
    with pytest.raises(SystemExit):
        sp.advance(gamma, "CONTACTED", D)
    sp.advance(gamma, "LOST", D)                                          # moving between closed stages is allowed


def test_unknown_stage_and_unknown_company_are_refused(table):
    with pytest.raises(SystemExit):
        sp.advance(sp.find(sp.load(table), "Alpha"), "FRIEND", D)
    with pytest.raises(SystemExit):
        sp.find(sp.load(table), "Nobody")


@pytest.mark.parametrize("lang", ["en", "fr"])
@pytest.mark.parametrize("stage", ["NEW", "CONTACTED", "FOLLOWUP1"])
def test_every_draft_names_the_company_has_an_opt_out_and_no_unfilled_placeholder(table, lang, stage):
    row = sp.find(sp.load(table), "Alpha")
    row["stage"] = stage
    text = sp.render(row, lang, "Krzysztof, AI STUDIO")
    assert "Alpha" in text and "Krzysztof, AI STUDIO" in text
    assert ("stop" in text.lower()) and "{" not in text and "}" not in text


def test_drafts_make_no_claim_the_offer_doc_forbids(table):
    row = sp.find(sp.load(table), "Alpha")
    for lang in ("en", "fr"):
        text = sp.render(row, lang, "me").lower()
        for banned in ("guarantee", "certif", "garanti", "reference", "référence", "save you", "% "):
            assert banned not in text


def test_the_cli_writes_the_new_stage_and_never_sends(table, capsys):
    assert sp.main(["--csv", str(table), "advance", "Alpha", "CONTACTED", "--on", "2026-10-07", "--note", "emailed"]) == 0
    row = sp.find(sp.load(table), "Alpha")
    assert row["stage"] == "CONTACTED" and row["last_action"] == "2026-10-07" and row["note"] == "emailed"
    import ast
    tree = ast.parse((ROOT / "scripts" / "sales_pipeline.py").read_text())
    imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert not imported & {"smtplib", "email", "requests", "httpx", "urllib", "socket", "subprocess", "http"}


def test_the_offer_doc_states_that_the_prices_are_hypotheses_and_the_flow_takes_only_99():
    doc = (ROOT / "docs" / "sales" / "offer.md").read_text()
    assert "hypotheses, not measured" in doc and "exactly EUR 99" in doc and "NOT PROVEN" in doc


@pytest.mark.parametrize("stage, marker", [("NEW", "one repetitive process at"), ("CONTACTED", "short follow-up"),
                                           ("FOLLOWUP1", "last note from me")])
def test_each_stage_gets_its_own_template(table, stage, marker):
    row = sp.find(sp.load(table), "Alpha")
    row["stage"] = stage
    assert marker in sp.render(row, "en", "me").lower()
