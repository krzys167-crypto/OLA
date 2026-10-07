#!/usr/bin/env python3
"""Prospect pipeline for the OLA audit offer. It keeps a CSV, tells you who is due for a touch, and renders a DRAFT text.

It never sends anything and never invents a contact: `contact` stays empty until a human fills in an address or URL that
the prospect published for business use. A prospect in DO_NOT_CONTACT (or LOST) is never listed as due and never drafted.

  sales_pipeline.py list                         every prospect and stage
  sales_pipeline.py due [--today YYYY-MM-DD]     who needs a touch today (needs a contact)
  sales_pipeline.py draft COMPANY --lang en|fr   render the next message as text, to stdout
  sales_pipeline.py advance COMPANY STAGE [--on YYYY-MM-DD] [--note TEXT]
  sales_pipeline.py report                       counts per stage and per sector
"""
import argparse
import csv
import datetime as dt
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CSV = ROOT / "sales" / "prospects.csv"
TEMPLATES = ROOT / "sales" / "templates"
FIELDS = ["company", "sector", "stage", "contact", "last_action", "next_due", "note"]
STAGES = ("NEW", "CONTACTED", "FOLLOWUP1", "FOLLOWUP2", "REPLIED", "CALL_BOOKED", "PROPOSAL_SENT", "WON", "LOST",
          "DO_NOT_CONTACT")
NEVER_CONTACT = {"DO_NOT_CONTACT", "LOST", "WON"}
CADENCE_DAYS = {"CONTACTED": 3, "FOLLOWUP1": 4}          # days after the touch until the next one is due; FOLLOWUP2 ends it
NEXT_DRAFT = {"NEW": "first", "CONTACTED": "followup1", "FOLLOWUP1": "followup2"}
HOOKS = {
    "property": ("viewing requests, listing texts and lease paperwork", "demandes de visite, textes d'annonces et dossiers de bail"),
    "accounting": ("collecting and sorting client documents", "collecte et tri des documents clients"),
    "logistics": ("delivery documents and status messages to customers", "documents de livraison et messages de statut aux clients"),
}
DEFAULT_HOOK = ("repetitive paperwork", "tâches administratives répétitives")


def load(path):
    with open(path, newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    for row in rows:
        if row["stage"] not in STAGES:
            raise SystemExit(f"{row['company']}: unknown stage {row['stage']!r}")
    return rows


def save(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def find(rows, company):
    hits = [row for row in rows if row["company"].lower() == company.lower()]
    if len(hits) != 1:
        raise SystemExit(f"{company!r}: {len(hits)} matches")
    return hits[0]


def is_due(row, today):
    if row["stage"] in NEVER_CONTACT or row["stage"] not in NEXT_DRAFT or not row["contact"].strip():
        return False
    if row["stage"] == "NEW":
        return True
    return bool(row["next_due"]) and dt.date.fromisoformat(row["next_due"]) <= today


def render(row, lang, sender):
    if row["stage"] in NEVER_CONTACT or row["stage"] not in NEXT_DRAFT:
        raise SystemExit(f"{row['company']}: nothing to draft in stage {row['stage']}")
    en, fr = HOOKS.get(row["sector"], DEFAULT_HOOK)
    name = f"{NEXT_DRAFT[row['stage']]}_{lang}.md"
    text = (TEMPLATES / name).read_text(encoding="utf-8")
    return text.format(company=row["company"], hook=en, hook_fr=fr, sender=sender)


def advance(row, stage, on, note=""):
    if stage not in STAGES:
        raise SystemExit(f"unknown stage {stage!r}")
    if row["stage"] in NEVER_CONTACT and stage not in NEVER_CONTACT:
        raise SystemExit(f"{row['company']} is {row['stage']}; it is not reopened by a script (edit the CSV on purpose)")
    row["stage"], row["last_action"] = stage, on.isoformat()
    row["next_due"] = (on + dt.timedelta(days=CADENCE_DAYS[stage])).isoformat() if stage in CADENCE_DAYS else ""
    if note:
        row["note"] = note


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--csv", default=str(DEFAULT_CSV))
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    due = sub.add_parser("due")
    due.add_argument("--today", default=None)
    draft = sub.add_parser("draft")
    draft.add_argument("company")
    draft.add_argument("--lang", choices=("en", "fr"), default="en")
    draft.add_argument("--sender", default="Krzysztof, AI STUDIO")
    adv = sub.add_parser("advance")
    adv.add_argument("company")
    adv.add_argument("stage")
    adv.add_argument("--on", default=None)
    adv.add_argument("--note", default="")
    sub.add_parser("report")
    args = parser.parse_args(argv)
    rows = load(args.csv)

    if args.cmd == "list":
        for row in rows:
            print(f"{row['stage']:<15} {row['sector']:<11} {row['company']}")
    elif args.cmd == "due":
        today = dt.date.fromisoformat(args.today) if args.today else dt.date.today()
        hits = [row for row in rows if is_due(row, today)]
        for row in hits:
            print(f"{row['company']} ({row['stage']} -> {NEXT_DRAFT[row['stage']]})")
        print(f"due: {len(hits)}; without a contact (cannot be touched): "
              f"{sum(1 for r in rows if r['stage'] == 'NEW' and not r['contact'].strip())}", file=sys.stderr)
    elif args.cmd == "draft":
        row = find(rows, args.company)
        print(render(row, args.lang, args.sender))
    elif args.cmd == "advance":
        on = dt.date.fromisoformat(args.on) if args.on else dt.date.today()
        advance(find(rows, args.company), args.stage, on, args.note)
        save(args.csv, rows)
    elif args.cmd == "report":
        for key in ("stage", "sector"):
            counts = {}
            for row in rows:
                counts[row[key]] = counts.get(row[key], 0) + 1
            print(key, dict(sorted(counts.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
