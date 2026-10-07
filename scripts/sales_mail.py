#!/usr/bin/env python3
"""Rules for the mailbox side of the sales flow: what a reply means, what may be sent without a human, call slots and a
calendar invite. Pure functions plus a small CLI; it has no mail or network code. The scheduled task that talks to the
mailbox (Gmail connector) calls these rules and must obey `plan_action` and `send_decision`.

Defaults are conservative on purpose (sales/policy.json): mode "draft" until a human has approved
`approved_sends_required` first messages; a reply that is not an opt-out is never answered without a human."""
import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "sales" / "policy.json"
TEMPLATES = ROOT / "sales" / "templates"
BRUSSELS = ZoneInfo("Europe/Brussels")

_OPT_OUT = re.compile(r"\b(stop|unsubscribe|remove me|do not contact|don't contact|d[ée]sinscri\w*|ne plus (me )?contacter|"
                      r"plus de mails?|uitschrijven|niet meer contact\w*|nie pisz\w*|wypisz\w*)\b", re.I)
_DECLINE = re.compile(r"(not interested|no thank|no, thank|pas int[ée]ress[ée]|non merci|geen interesse|niet ge[ïi]nteresseerd|"
                      r"nie jestem zainteresowan\w*|nie dziękuj\w*)", re.I)
_INTEREST = re.compile(r"\b(yes|sure|ok(ay)?|interested|call|let'?s talk|oui|int[ée]ress[ée]|appel|disponible|ja|graag|"
                       r"tak|zainteresowan\w*|rozmow\w*)\b", re.I)


def classify_reply(text: str) -> str:
    """OPT_OUT, DECLINE, INTEREST or OTHER. The order is the safety rule: leaving the list beats everything, a decline
    beats an interest word ("not interested" contains "interested")."""
    if _OPT_OUT.search(text):
        return "OPT_OUT"
    if _DECLINE.search(text):
        return "DECLINE"
    if _INTEREST.search(text):
        return "INTEREST"
    return "OTHER"


def load_policy(path=POLICY) -> dict:
    policy = json.loads(Path(path).read_text(encoding="utf-8"))
    if policy.get("mode") not in ("draft", "send"):
        raise ValueError("policy.mode must be 'draft' or 'send'")
    for key in ("approved_sends_required", "daily_cap"):
        if not isinstance(policy.get(key), int) or isinstance(policy.get(key), bool) or policy[key] < 0:
            raise ValueError(f"policy.{key} must be a non-negative integer")
    if not 1 <= policy["daily_cap"] <= 20:
        raise ValueError("policy.daily_cap must be between 1 and 20")
    if policy.get("auto_replies", {}).get("everything_else") != "draft_only":
        raise ValueError("auto_replies.everything_else must stay 'draft_only'")
    return policy


def send_decision(policy: dict, *, sent_today: int, approved_sends: int, now: dt.datetime) -> str:
    """SEND only when the policy says send, enough first messages were approved by a human, the daily cap is not reached
    and it is a weekday inside the send window (Brussels time). Anything else is DRAFT: a draft is always safe."""
    local = now.astimezone(BRUSSELS)
    start, end = (dt.time.fromisoformat(t) for t in policy["send_window_brussels"])
    if (policy["mode"] == "send" and approved_sends >= policy["approved_sends_required"]
            and sent_today < policy["daily_cap"] and local.weekday() < 5 and start <= local.time() < end):
        return "SEND"
    return "DRAFT"


def plan_action(reply_class: str) -> dict:
    """What to do with a reply. `human` True means a person must read and approve before anything is sent."""
    if reply_class == "OPT_OUT":
        return {"stage": "DO_NOT_CONTACT", "reply": "optout", "human": False}
    if reply_class == "DECLINE":
        return {"stage": "LOST", "reply": None, "human": False}
    if reply_class == "INTEREST":
        return {"stage": "REPLIED", "reply": "slots", "human": True}
    return {"stage": "REPLIED", "reply": "draft_for_human", "human": True}


def slots(today: dt.date, count: int = 3, hours=(10, 14)) -> list:
    """The next `count` weekday slots (10:00 and 14:00 Brussels), starting the next weekday after `today`."""
    out, day = [], today
    while len(out) < count:
        day += dt.timedelta(days=1)
        if day.weekday() >= 5:
            continue
        for hour in hours:
            if len(out) < count:
                out.append(dt.datetime.combine(day, dt.time(hour), tzinfo=BRUSSELS))
    return out


def ics_invite(summary: str, start: dt.datetime, minutes: int, uid: str, organizer: str, attendee: str) -> str:
    """A minimal RFC 5545 invite (UTC times). Lines are CRLF-terminated as the format requires."""
    stamp = lambda value: value.astimezone(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")  # noqa: E731
    clean = lambda value: re.sub(r"[\r\n,;\\]", " ", value)  # noqa: E731
    lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//AI STUDIO//OLA sales//EN", "METHOD:REQUEST", "BEGIN:VEVENT",
             f"UID:{clean(uid)}", f"DTSTAMP:{stamp(dt.datetime.now(dt.timezone.utc))}", f"DTSTART:{stamp(start)}",
             f"DTEND:{stamp(start + dt.timedelta(minutes=minutes))}", f"SUMMARY:{clean(summary)}",
             f"ORGANIZER:mailto:{clean(organizer)}", f"ATTENDEE;RSVP=TRUE:mailto:{clean(attendee)}", "END:VEVENT",
             "END:VCALENDAR"]
    return "\r\n".join(lines) + "\r\n"


def render(name: str, lang: str, **values) -> str:
    return (TEMPLATES / f"{name}_{lang}.md").read_text(encoding="utf-8").format(**values)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("policy")
    cls = sub.add_parser("classify")
    cls.add_argument("text")
    slot = sub.add_parser("slots")
    slot.add_argument("--today", default=None)
    args = parser.parse_args(argv)
    if args.cmd == "policy":
        print(json.dumps(load_policy(), indent=2))
    elif args.cmd == "classify":
        kind = classify_reply(args.text)
        print(json.dumps({"class": kind, **plan_action(kind)}))
    else:
        today = dt.date.fromisoformat(args.today) if args.today else dt.date.today()
        for item in slots(today):
            print(item.isoformat())
    return 0


if __name__ == "__main__":
    sys.exit(main())
