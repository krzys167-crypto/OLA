#!/usr/bin/env python3
"""Rules for the mailbox side of the sales flow: what a reply means, what may be sent without a human, call slots and a
calendar invite. Pure functions plus a small CLI; it has no mail or network code. The scheduled task that talks to the
mailbox (Gmail connector) calls these rules and must obey `plan_action` and `send_decision`.

Defaults are conservative on purpose (sales/policy.json): mode "draft" until a human has approved
`approved_sends_required` (at least 1) first messages; a reply that is not an opt-out confirmation is never sent without
a human. Anything the rules cannot place goes to a human (OTHER), never to an automatic action."""
import argparse
import datetime as dt
import json
import re
import sys
import unicodedata
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "sales" / "policy.json"
TEMPLATES = ROOT / "sales" / "templates"
BRUSSELS = ZoneInfo("Europe/Brussels")

_OPT_OUT = re.compile(
    r"(unsubscribe|remove me|take me off|do not (contact|e-?mail|write)|don't (contact|e-?mail|write)|stop (writing|e-?mailing|"
    r"contacting|sending|messaging)|please stop|d[ée]sinscri\w*|d[ée]sabonn\w*|ne plus (me )?contacter|ne me contactez plus|"
    r"ne m'[ée]crivez plus|plus de mails?|uitschrijven|geen contact meer|niet meer contact\w*|neem geen contact|verwijder me|"
    r"nie pisz\w*|nie pisa[cć]|nie kontaktuj\w*|wypisz\w*|usu[nń] mnie)", re.I)
_STOP_ALONE = re.compile(r"^\W*(stop|unsubscribe|stoppen|arr[êe]t\w*|stop\w* proszę)\W*$", re.I)
_DECLINE = re.compile(
    r"(not\s+(really\s+|currently\s+)?interested|no\s+longer\s+interested|no\s+thank|no,\s+thank|no\s+interest|"
    r"pas\s+int[ée]ress[ée]|ne\s+m'int[ée]resse\s+pas|non\s+merci|geen\s+interesse|niet\s+ge[ïi]nteresseerd|"
    r"nie\s+jeste(m|śmy)\s+zainteresowan\w*|nie,?\s+dzi[eę]kuj\w*|nie\s+dzi[eę]kuj\w*|nie\s+potrzebuj\w*)", re.I)
_MIXED = re.compile(r"\b(but|however|though|later|mais|plus tard|maar|ale|q[1-4]|next (year|quarter|month|week))\b", re.I)
_INTEREST = re.compile(r"\b(yes|sure|okay|ok|interested|let'?s talk|oui|int[ée]ress[ée]|graag|zainteresowan\w*|rozmow\w*)\b", re.I)
_YES_START = re.compile(r"^\W*(tak|ja)\b", re.I)
_AUTO_TEXT = re.compile(r"(out of office|automatic reply|auto-?reply|r[ée]ponse automatique|absence du bureau|"
                        r"afwezigheidsmelding|automatisch antwoord|odpowiedź automatyczna|undeliverable|delivery status)", re.I)
_AUTO_SENDER = re.compile(r"(mailer-daemon|postmaster|no-?reply|do-?not-?reply|bounce)", re.I)
_QUOTE_START = re.compile(r"^(on .{5,120} wrote:|le .{5,120} a [ée]crit\s*:|op .{5,120} schreef .*:|-----+\s*original message.*|"
                          r"from:\s.+|de\s*:\s.+)$", re.I)


def _own_text(text: str) -> str:
    """What the person wrote: quoted lines, the quoted-mail header and everything after it are dropped, quotes and accents
    are normalised. Our own opt-out line ('reply stop') comes back inside every reply that quotes our message."""
    text = unicodedata.normalize("NFC", text.replace("’", "'").replace("‘", "'"))
    kept = []
    for line in text.splitlines():
        stripped = line.strip()
        if _QUOTE_START.match(stripped):
            break
        if stripped.startswith(">"):
            continue
        kept.append(stripped)
    return re.sub(r"\s+", " ", " ".join(kept)).strip()


def classify_reply(text: str, sender: str = "") -> str:
    """AUTO (out-of-office, bounce, no-reply sender: never answered), OPT_OUT, DECLINE, INTEREST or OTHER (a human reads it).
    The order is the safety rule: an automatic message is never answered, leaving the list beats everything, and a decline
    that is mixed with a condition ('no thanks, but call in Q1') or with an interest word is a human decision."""
    if _AUTO_SENDER.search(sender or "") or _AUTO_TEXT.search(text):
        return "AUTO"
    own = _own_text(text)
    first_line = next((line.strip() for line in text.replace("’", "'").splitlines()
                       if line.strip() and not line.strip().startswith(">")), "")
    if _OPT_OUT.search(own) or _STOP_ALONE.match(own) or _STOP_ALONE.match(first_line):
        return "OPT_OUT"
    if _DECLINE.search(own):
        rest = _DECLINE.sub(" ", own)
        return "OTHER" if _MIXED.search(rest) or _INTEREST.search(rest) else "DECLINE"
    if _INTEREST.search(own) or _YES_START.match(own):
        return "INTEREST"
    return "OTHER"


def _int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def check_policy(policy: dict) -> dict:
    if policy.get("mode") not in ("draft", "send"):
        raise ValueError("policy.mode must be 'draft' or 'send'")
    if not _int(policy.get("approved_sends_required")) or policy["approved_sends_required"] < 1:
        raise ValueError("policy.approved_sends_required must be an integer >= 1 (a human approves the first messages)")
    if not _int(policy.get("daily_cap")) or not 1 <= policy["daily_cap"] <= 20:
        raise ValueError("policy.daily_cap must be an integer between 1 and 20")
    if policy.get("auto_replies", {}).get("everything_else") != "draft_only":
        raise ValueError("auto_replies.everything_else must stay 'draft_only'")
    window = policy.get("send_window_brussels")
    if not (isinstance(window, list) and len(window) == 2):
        raise ValueError("policy.send_window_brussels must be [start, end]")
    dt.time.fromisoformat(window[0]), dt.time.fromisoformat(window[1])
    return policy


def load_policy(path=POLICY) -> dict:
    return check_policy(json.loads(Path(path).read_text(encoding="utf-8")))


def send_decision(policy: dict, *, sent_today: int, approved_sends: int, now: dt.datetime,
                  has_contact: bool, stage_due: bool) -> str:
    """SEND only when ALL hold: policy mode is send; a human approved at least `approved_sends_required` first messages;
    fewer than `daily_cap` were sent today; a human filled in the contact; the stage is due; `now` (timezone-aware) is a
    weekday inside the send window in Brussels. Anything else, including bad input, is DRAFT or an error."""
    check_policy(policy)
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if not (_int(sent_today) and _int(approved_sends) and sent_today >= 0 and approved_sends >= 0):
        raise ValueError("sent_today and approved_sends must be non-negative integers")
    if has_contact is not True or stage_due is not True:
        return "DRAFT"
    local = now.astimezone(BRUSSELS)
    start, end = (dt.time.fromisoformat(t) for t in policy["send_window_brussels"])
    if (policy["mode"] == "send" and approved_sends >= policy["approved_sends_required"]
            and sent_today < policy["daily_cap"] and local.weekday() < 5 and start <= local.time() < end):
        return "SEND"
    return "DRAFT"


def plan_action(reply_class: str, policy: dict = None) -> dict:
    """What to do with a reply. `human` True means a person must read and approve before anything is sent. The opt-out
    confirmation is the only message sent without a human, in every mode, unless the policy switches it off."""
    if reply_class == "AUTO":
        return {"stage": None, "reply": None, "human": False}
    if reply_class == "OPT_OUT":
        confirm = True if policy is None else bool(policy.get("auto_replies", {}).get("opt_out_confirmation"))
        return {"stage": "DO_NOT_CONTACT", "reply": "optout" if confirm else None, "human": False}
    if reply_class == "DECLINE":
        return {"stage": "LOST", "reply": None, "human": False}
    if reply_class == "INTEREST":
        return {"stage": "REPLIED", "reply": "slots", "human": True}
    return {"stage": "REPLIED", "reply": "draft_for_human", "human": True}


def _easter(year: int) -> dt.date:
    a, b, c = year % 19, year // 100, year % 100
    d, e = divmod(b, 4)
    g = (8 * b + 13) // 25
    h = (19 * a + b - d - g + 15) % 30
    i, k = divmod(c, 4)
    l = (32 + 2 * e + 2 * i - h - k) % 7  # noqa: E741
    m = (a + 11 * h + 19 * l) // 433
    month, day = divmod(h + l - 7 * m + 114, 31)
    return dt.date(year, month, day + 1)


def belgian_holidays(year: int) -> set:
    easter = _easter(year)
    fixed = [(1, 1), (5, 1), (7, 21), (8, 15), (11, 1), (11, 11), (12, 25)]
    return {dt.date(year, m, d) for m, d in fixed} | {easter + dt.timedelta(days=n) for n in (1, 39, 50)}


def slots(today: dt.date, count: int = 3, hours=(10, 14), lead_days: int = 2) -> list:
    """The next `count` slots (10:00 and 14:00 Brussels) on business days (no weekend, no Belgian public holiday), the
    first one at least `lead_days` business days after `today`."""
    out, day, skipped = [], today, 0
    while len(out) < count:
        day += dt.timedelta(days=1)
        if day.weekday() >= 5 or day in belgian_holidays(day.year):
            continue
        if skipped < lead_days - 1:
            skipped += 1
            continue
        for hour in hours:
            if len(out) < count:
                out.append(dt.datetime.combine(day, dt.time(hour), tzinfo=BRUSSELS))
    return out


def _fold(line: str) -> str:
    """RFC 5545 line folding: at most 75 octets per line, continuation lines start with one space."""
    raw, parts = line.encode("utf-8"), []
    while len(raw) > 75:
        cut = 75
        while (raw[cut] & 0xC0) == 0x80:      # never split a UTF-8 character
            cut -= 1
        parts.append(raw[:cut].decode("utf-8"))
        raw = b" " + raw[cut:]
    parts.append(raw.decode("utf-8"))
    return "\r\n".join(parts)


def ics_invite(summary: str, start: dt.datetime, minutes: int, uid: str, organizer: str, attendee: str) -> str:
    """A minimal RFC 5545 invite (UTC times). Lines are CRLF-terminated and folded as the format requires."""
    if start.tzinfo is None:
        raise ValueError("start must be timezone-aware")
    stamp = lambda value: value.astimezone(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")  # noqa: E731
    clean = lambda value: re.sub(r"[\r\n,;\\]", " ", value)  # noqa: E731
    lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//AI STUDIO//OLA sales//EN", "METHOD:REQUEST", "BEGIN:VEVENT",
             f"UID:{clean(uid)}", f"DTSTAMP:{stamp(dt.datetime.now(dt.timezone.utc))}", f"DTSTART:{stamp(start)}",
             f"DTEND:{stamp(start + dt.timedelta(minutes=minutes))}", f"SUMMARY:{clean(summary)}",
             f"ORGANIZER:mailto:{clean(organizer)}", f"ATTENDEE;RSVP=TRUE:mailto:{clean(attendee)}", "END:VEVENT",
             "END:VCALENDAR"]
    return "\r\n".join(_fold(line) for line in lines) + "\r\n"


def render(name: str, lang: str, **values) -> str:
    return (TEMPLATES / f"{name}_{lang}.md").read_text(encoding="utf-8").format(**values)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("policy")
    cls = sub.add_parser("classify")
    cls.add_argument("text")
    cls.add_argument("--sender", default="")
    slot = sub.add_parser("slots")
    slot.add_argument("--today", default=None)
    args = parser.parse_args(argv)
    if args.cmd == "policy":
        print(json.dumps(load_policy(), indent=2))
    elif args.cmd == "classify":
        kind = classify_reply(args.text, args.sender)
        print(json.dumps({"class": kind, **plan_action(kind, load_policy())}))
    else:
        today = dt.date.fromisoformat(args.today) if args.today else dt.datetime.now(BRUSSELS).date()
        for item in slots(today):
            print(item.isoformat())
    return 0


if __name__ == "__main__":
    sys.exit(main())
