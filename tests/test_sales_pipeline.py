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
    with pytest.raises(SystemExit):
        sp.advance(gamma, "LOST", D)                                      # an opt-out marker is not downgraded by a script
    with pytest.raises(SystemExit):
        sp.advance(gamma, "WON", D)
    assert gamma["stage"] == "DO_NOT_CONTACT"


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


def test_the_daily_workflow_only_reports_it_has_no_secret_no_write_permission_and_sends_nothing():
    import re
    raw = (ROOT / ".github" / "workflows" / "sales-daily.yml").read_text()
    text = "\n".join(line for line in raw.splitlines() if not line.lstrip().startswith("#")) + "\n"
    assert re.search(r"^permissions:\n  contents: read\n", text, re.M)
    assert "secrets." not in text and "write" not in text
    for word in ("sendmail", "smtp", "curl", "mail ", "gh issue", "gh api", "slack"):
        assert word not in text.lower().split("jobs:")[1]
    assert "schedule:" in text and "workflow_dispatch:" in text


def test_a_contacted_prospect_never_goes_back_to_new_or_backwards(table):
    alpha = sp.find(sp.load(table), "Alpha")
    sp.advance(alpha, "CALL_BOOKED", D)
    for stage in ("NEW", "CONTACTED", "REPLIED"):
        with pytest.raises(SystemExit):
            sp.advance(alpha, stage, D)
    sp.advance(alpha, "LOST", D)                                          # closing is always allowed from an open stage


def test_an_opt_out_covers_the_same_contact_and_the_company_domain_on_other_rows(tmp_path):
    path = tmp_path / "p.csv"
    write(path, [
        {"company": "A", "sector": "x", "stage": "DO_NOT_CONTACT", "contact": "boss@corp.example"},
        {"company": "B", "sector": "x", "stage": "NEW", "contact": "boss@corp.example"},
        {"company": "C", "sector": "x", "stage": "NEW", "contact": "other@corp.example"},
        {"company": "D", "sector": "x", "stage": "NEW", "contact": "other@else.example"},
        {"company": "E", "sector": "x", "stage": "DO_NOT_CONTACT", "contact": "me@gmail.com"},
        {"company": "F", "sector": "x", "stage": "NEW", "contact": "you@gmail.com"},
    ])
    rows = sp.load(path)
    block = sp.suppressed(rows)
    assert [r["company"] for r in rows if sp.is_due(r, D, block)] == ["D", "F"]   # a freemail domain is not blocked wholesale
    with pytest.raises(SystemExit):
        sp.render(sp.find(rows, "B"), "en", "me", block)
    assert sp.render(sp.find(rows, "D"), "en", "me", block)


def test_spreadsheet_formulas_are_neutralised_on_disk_and_restored_on_load(tmp_path):
    path = tmp_path / "p.csv"
    write(path, [{"company": '=HYPERLINK("http://x","c")', "sector": "x", "stage": "NEW", "contact": "+32 2 123 45 67",
                  "note": "@SUM(1)"}])
    rows = sp.load(path)
    sp.save(path, rows)
    raw = path.read_text(encoding="utf-8")
    assert "'=HYPERLINK" in raw and "'+32 2 123 45 67" in raw and "'@SUM(1)" in raw
    assert not any(cell.startswith(("=", "+", "@")) for row in csv.reader(raw.splitlines()) for cell in row)
    again = sp.load(path)
    assert again[0]["company"] == '=HYPERLINK("http://x","c")' and again[0]["contact"] == "+32 2 123 45 67"
    assert again[0]["note"] == "@SUM(1)"


def test_a_bom_a_semicolon_delimiter_and_a_rewritten_date_are_handled_or_fail_with_a_clear_message(tmp_path):
    path = tmp_path / "p.csv"
    path.write_text("\ufeffcompany;sector;stage;contact;last_action;next_due;note\nAlpha;x;NEW;a@a.example;;;\n", encoding="utf-8")
    assert sp.load(path)[0]["company"] == "Alpha"
    path.write_text("company,sector,stage,contact,last_action,next_due,note\nAlpha,x,CONTACTED,a@a.example,,10/10/2026,\n", encoding="utf-8")
    with pytest.raises(SystemExit) as error:
        sp.load(path)
    assert "not YYYY-MM-DD" in str(error.value)
    path.write_text("company,sector\nAlpha,x\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        sp.load(path)


def test_company_names_cannot_inject_workflow_commands_or_fences_into_the_report():
    assert "\n" not in sp.safe("a\n::warning::x") and not sp.safe("::set-output name=x::1").startswith("::")
    assert "```" not in sp.safe("x ``` y")
