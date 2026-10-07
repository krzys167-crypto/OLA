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
    ("What does it cost?", "OTHER"), ("", "OTHER"), ("Out of office until Monday", "AUTO"),
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
    assert sm.send_decision(policy, sent_today=0, approved_sends=99, now=TUE_11, has_contact=True, stage_due=True) == "DRAFT"


@pytest.mark.parametrize("bad", [{"mode": "auto"}, {"daily_cap": 0}, {"daily_cap": 21}, {"daily_cap": True},
                                 {"approved_sends_required": -1}, {"approved_sends_required": 0}, {"approved_sends_required": True},
                                 {"send_window_brussels": ["09:00"]}, {"auto_replies": {"everything_else": "send"}}])
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
    ({"has_contact": False}, "DRAFT"), ({"stage_due": False}, "DRAFT"), ({"has_contact": 1}, "DRAFT"),
])
def test_send_decision_needs_every_condition(over, expected):
    args = {"sent_today": 0, "approved_sends": 5, "now": TUE_11, "has_contact": True, "stage_due": True, **over}
    assert sm.send_decision(SEND, **args) == expected


def test_draft_mode_never_sends_whatever_else_is_true():
    assert sm.send_decision({**SEND, "mode": "draft"}, sent_today=0, approved_sends=100, now=TUE_11, has_contact=True, stage_due=True) == "DRAFT"


def test_slots_skip_weekends_holidays_and_the_first_business_day():
    out = sm.slots(dt.date(2026, 10, 9))                      # a Friday: Monday is too soon, Tuesday is the first offer
    assert [s.isoformat() for s in out] == ["2026-10-13T10:00:00+02:00", "2026-10-13T14:00:00+02:00", "2026-10-14T10:00:00+02:00"]
    assert all(s.weekday() < 5 for s in sm.slots(dt.date(2026, 10, 7), count=40))
    assert all(s.date() not in sm.belgian_holidays(s.year) for s in sm.slots(dt.date(2026, 12, 20), count=40))
    assert dt.date(2026, 12, 25) not in {s.date() for s in sm.slots(dt.date(2026, 12, 22), count=6)}


def test_belgian_holidays_for_2026():
    assert sm.belgian_holidays(2026) == {dt.date(2026, d[0], d[1]) for d in
        [(1, 1), (4, 6), (5, 1), (5, 14), (5, 25), (7, 21), (8, 15), (11, 1), (11, 11), (12, 25)]}


def test_the_slot_offsets_follow_daylight_saving_time():
    out = sm.slots(dt.date(2026, 3, 24))
    assert out[0].utcoffset() == dt.timedelta(hours=1) and sm.slots(dt.date(2026, 3, 27))[0].utcoffset() == dt.timedelta(hours=2)


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


def test_long_ics_lines_are_folded_at_75_octets_without_splitting_a_character():
    start = dt.datetime(2026, 10, 13, 10, 0, tzinfo=sm.BRUSSELS)
    text = sm.ics_invite("Rozmowa o automatyzacji " + "ł" * 80, start, 20, "u", "me@x.be", "a@b.be")
    lines = text.split("\r\n")
    assert all(len(line.encode()) <= 75 for line in lines)
    unfolded = text.replace("\r\n ", "")
    assert "SUMMARY:Rozmowa o automatyzacji " + "ł" * 80 in unfolded


def test_a_naive_clock_is_refused_not_guessed():
    with pytest.raises(ValueError):
        sm.send_decision(SEND, sent_today=0, approved_sends=5, now=dt.datetime(2026, 10, 7, 16, 30), has_contact=True, stage_due=True)
    with pytest.raises(ValueError):
        sm.ics_invite("s", dt.datetime(2026, 10, 7, 10), 20, "u", "a@b", "c@d")


@pytest.mark.parametrize("sent, approved", [(-5, 5), (0, -1), (True, 5), (0, True), (1.0, 5), ("0", 5)])
def test_counters_that_are_not_plain_non_negative_integers_are_refused(sent, approved):
    with pytest.raises(ValueError):
        sm.send_decision(SEND, sent_today=sent, approved_sends=approved, now=TUE_11, has_contact=True, stage_due=True)


QUOTED = 'Yes, call me.\n\nOn Tue, 6 Oct 2026 at 10:00, Krzysztof <k@x.be> wrote:\n> Reply "stop" and I will not contact you again.'


@pytest.mark.parametrize("text, kind", [
    (QUOTED, "INTEREST"),                                           # our own opt-out line, quoted back, is not an opt-out
    ('Yes, call me.\n> Reply "stop" and I will not contact you again.', "INTEREST"),
    ("non-stop travelling, ok let's talk", "INTEREST"),
    ("Please don’t contact me again", "OPT_OUT"), ("Ne me contactez plus, je ne suis pas disponible", "OPT_OUT"),
    ("Neem geen contact meer op", "OPT_OUT"), ("Proszę nie pisać", "OPT_OUT"), ("Take me off your list", "OPT_OUT"),
    ("stop", "OPT_OUT"), ("> hello\nSTOP", "OPT_OUT"), ("Stop\nThanks, Anna", "OPT_OUT"),
    ("Yes\n> If you want to unsubscribe from these mails, reply", "INTEREST"),
    ("Yes, call me\n-----Original Message-----\nIf you want to unsubscribe, reply", "INTEREST"),
    ("Yes, call me\nFrom: Krzysztof <k@x.be>\nunsubscribe me", "INTEREST"),
    ("Nie jesteśmy zainteresowani", "DECLINE"), ("We are not really interested", "DECLINE"), ("no longer interested", "DECLINE"),
    ("Ça ne m'intéresse pas", "DECLINE"), ("Nie, dziękuję", "DECLINE"), ("no interest", "DECLINE"), ("not  interested", "DECLINE"),
    ("No thanks, but call me in Q1", "OTHER"), ("Non merci, mais plus tard peut-être", "OTHER"),
    ("Nie, tak nie", "OTHER"), ("Yes please, but not interested in the second option", "OTHER"),
    ("Out of office until Monday", "AUTO"), ("Automatic reply: I am away", "AUTO"),
])
def test_review_regressions_in_reply_classification(text, kind):
    assert sm.classify_reply(text) == kind


@pytest.mark.parametrize("sender", ["MAILER-DAEMON@x.be", "noreply@shop.be", "postmaster@x.be", "bounce+1@m.example"])
def test_mail_from_automatic_senders_is_never_answered_even_when_it_says_unsubscribe(sender):
    assert sm.classify_reply("Click here to unsubscribe", sender) == "AUTO"
    assert sm.plan_action("AUTO") == {"stage": None, "reply": None, "human": False}


def test_the_opt_out_confirmation_follows_the_policy_flag_and_is_sent_in_every_mode():
    on = {"auto_replies": {"opt_out_confirmation": True, "everything_else": "draft_only"}, "mode": "draft"}
    off = {"auto_replies": {"opt_out_confirmation": False, "everything_else": "draft_only"}}
    assert sm.plan_action("OPT_OUT", on)["reply"] == "optout" and sm.plan_action("OPT_OUT", off)["reply"] is None
    assert sm.plan_action("OPT_OUT", off)["stage"] == "DO_NOT_CONTACT"


def test_the_first_message_templates_and_the_offer_doc_agree_on_the_claims():
    first = (ROOT / "sales" / "templates" / "first_en.md").read_text().lower()
    offer = (ROOT / "docs" / "sales" / "offer.md").read_text().lower()
    assert "tamper-evident evidence record" in first and "hash-chained evidence record" in offer
    assert "fixed price" not in first and "every statement" not in first
