"""Mailbox rules: leaving the list always wins, nothing but an opt-out confirmation is answered without a human, and
SEND is the exception that needs a policy, human-approved first messages, a cap and a weekday window."""
import datetime as dt
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sales_mail", ROOT / "scripts" / "sales_mail.py")
sm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sm)

TUE_11 = dt.datetime(2026, 10, 6, 11, 0, tzinfo=sm.BRUSSELS)
SAT_11 = dt.datetime(2026, 10, 10, 11, 0, tzinfo=sm.BRUSSELS)
SEND = {"mode": "send", "approved_sends_required": 5, "daily_cap": 5, "send_window_brussels": ["09:00", "17:00"],
        "auto_replies": {"everything_else": "draft_only"}}


@pytest.mark.parametrize("text, kind", [
    ("STOP", "OPT_OUT"), ("Please unsubscribe me", "OPT_OUT"), ("Merci, ne plus me contacter svp", "OPT_OUT"),
    ("Désinscrivez-moi", "OPT_OUT"), ("Proszę nie pisz więcej", "OPT_OUT"),
    ("not interested", "DECLINE"), ("Non merci, pas intéressé", "DECLINE"), ("geen interesse", "DECLINE"),
    ("Yes, let's talk", "INTEREST"), ("Oui, un appel serait bien", "INTEREST"), ("tak, zainteresowani", "INTEREST"),
    ("What does it cost?", "OTHER"), ("", "OTHER"), ("Out of office until Monday", "OTHER"),
    ("not interested, stop writing", "OPT_OUT"),             # opt-out beats decline
    ("I am not interested, call someone else", "DECLINE"),   # decline beats the interest words "interested" and "call"
])
def test_reply_classification(text, kind):
    assert sm.classify_reply(text) == kind


def test_stopping_is_matched_as_a_word_not_inside_other_words():
    assert sm.classify_reply("The bus stopped") == "OTHER" and sm.classify_reply("nonstop deliveries") == "OTHER" and sm.classify_reply("Stop.") == "OPT_OUT"


def test_only_leaving_the_list_and_declining_are_handled_without_a_human_and_neither_sends_a_sales_message():
    assert sm.plan_action("OPT_OUT") == {"stage": "DO_NOT_CONTACT", "reply": "optout", "human": False}
    assert sm.plan_action("DECLINE") == {"stage": "LOST", "reply": None, "human": False}
    for kind in ("INTEREST", "OTHER"):
        assert sm.plan_action(kind)["human"] is True


def test_the_shipped_policy_is_valid_and_starts_in_draft_mode():
    policy = sm.load_policy()
    assert policy["mode"] == "draft" and policy["approved_sends_required"] >= 1
    assert sm.send_decision(policy, sent_today=0, approved_sends=99, now=TUE_11) == "DRAFT"


@pytest.mark.parametrize("bad", [{"mode": "auto"}, {"daily_cap": 0}, {"daily_cap": 21}, {"daily_cap": True},
                                 {"approved_sends_required": -1}, {"auto_replies": {"everything_else": "send"}}])
def test_an_invalid_or_loosened_policy_is_refused(tmp_path, bad):
    path = tmp_path / "p.json"
    path.write_text(json.dumps({**SEND, **bad}))
    with pytest.raises(ValueError):
        sm.load_policy(path)


@pytest.mark.parametrize("over, expected", [
    ({}, "SEND"), ({"approved_sends": 4}, "DRAFT"), ({"sent_today": 5}, "DRAFT"), ({"sent_today": 4}, "SEND"),
    ({"now": SAT_11}, "DRAFT"), ({"now": TUE_11.replace(hour=8, minute=59)}, "DRAFT"),
    ({"now": TUE_11.replace(hour=17)}, "DRAFT"), ({"now": TUE_11.replace(hour=16, minute=59)}, "SEND"),
    ({"now": TUE_11.astimezone(dt.timezone.utc)}, "SEND"),                        # the same instant in UTC
])
def test_send_decision_needs_every_condition(over, expected):
    args = {"sent_today": 0, "approved_sends": 5, "now": TUE_11, **over}
    assert sm.send_decision(SEND, **args) == expected


def test_draft_mode_never_sends_whatever_else_is_true():
    assert sm.send_decision({**SEND, "mode": "draft"}, sent_today=0, approved_sends=100, now=TUE_11) == "DRAFT"


def test_slots_are_the_next_weekdays_at_10_and_14_brussels_and_skip_the_weekend():
    out = sm.slots(dt.date(2026, 10, 9))                      # a Friday
    assert [s.isoformat() for s in out] == ["2026-10-12T10:00:00+02:00", "2026-10-12T14:00:00+02:00", "2026-10-13T10:00:00+02:00"]
    assert all(s.weekday() < 5 for s in sm.slots(dt.date(2026, 10, 7), count=20))


def test_the_invite_is_a_wellformed_utc_event_with_crlf_and_no_injected_lines():
    start = dt.datetime(2026, 10, 13, 10, 0, tzinfo=sm.BRUSSELS)
    text = sm.ics_invite("Call, Alpha\r\nX-EVIL:1", start, 20, "uid-1", "me@ai-studio.example", "a@alpha.example")
    assert text.startswith("BEGIN:VCALENDAR\r\n") and text.endswith("END:VCALENDAR\r\n")
    assert "DTSTART:20261013T080000Z" in text and "DTEND:20261013T082000Z" in text
    assert "\nX-EVIL" not in text and "METHOD:REQUEST" in text
    assert all(line.count(":") >= 1 for line in text.strip().split("\r\n"))


@pytest.mark.parametrize("name", ["optout", "slots"])
@pytest.mark.parametrize("lang", ["en", "fr"])
def test_reply_templates_fill_completely(name, lang):
    text = sm.render(name, lang, subject="S", sender="me", slots="- a\n- b")
    assert "{" not in text and "}" not in text and "me" in text
    assert "guarantee" not in text.lower() and "garanti" not in text.lower()


def test_the_module_has_no_mail_or_network_code():
    import ast
    tree = ast.parse((ROOT / "scripts" / "sales_mail.py").read_text())
    names = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    names |= {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert not names & {"smtplib", "email", "imaplib", "requests", "httpx", "urllib", "socket", "subprocess", "http"}
