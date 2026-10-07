# Sales automation - what runs, who decides

## Pieces
| Piece | Where | Does |
|---|---|---|
| Queue and drafts | `scripts/sales_pipeline.py`, `sales/prospects.csv` | stages, follow-up timing, EN/FR drafts |
| Mailbox rules | `scripts/sales_mail.py`, `sales/policy.json` | reply classification, what may be sent unattended, call slots, `.ics` invite |
| Daily report | `.github/workflows/sales-daily.yml` | who is due today (read-only) |
| Mailbox I/O | a scheduled Claude task with the Gmail connector (not in this repo) | reads replies, creates drafts, sends only when the rules say SEND |

## Rules the mailbox task must follow (tested in `tests/test_sales_mail.py`)
1. **Mode is `draft` until a human has approved 5 first messages** (`sales/policy.json`). Drafts go into the Gmail drafts
   folder; the owner sends them. Switch `mode` to `send` only on purpose, in a reviewed commit.
2. `send_decision` returns SEND only when all hold: `mode` is send, at least `approved_sends_required` (>= 1) first
   messages were approved by a human, fewer than `daily_cap` were sent today, the contact was filled in by a human
   (`has_contact`), the stage is due (`stage_due`), and `now` (timezone-aware) is a weekday 09:00-17:00 Brussels. The
   count of approved messages is supplied by the caller; the repo does not count it.
3. An **opt-out** sets DO_NOT_CONTACT at once; its one-line confirmation is the only message sent without a human, **in
   every mode** (switch it off with `auto_replies.opt_out_confirmation`). Quoted text, our own "reply stop" line,
   out-of-office and bounce mail (class AUTO) are ignored when classifying; AUTO is never answered. A reply that mixes a
   decline with a condition ("no thanks, but call in Q1") goes to a human. A **decline** sets LOST and sends nothing.
4. **Interest** and **anything else** produce a draft (slots, or a draft for a person) and are never sent unattended:
   price, scope, legal or contract questions are never answered by a script.
5. Calendar: no calendar connector is attached to this account, so the task proposes three slots and attaches an `.ics`
   invite to the confirmation; connect a calendar to book directly.
6. A contact is never invented or scraped; the column is filled from what the company itself published for business use.
7. Cold B2B e-mail in Belgium/EU has rules (legitimate interest, identification, opt-out in every message, language):
   check with a lawyer before switching to `send`.

## The scheduled task (create after this is merged; a fresh session needs the scripts in the default branch)
Weekdays 07:00 Brussels: run `scripts/sales_pipeline.py due`; for each due prospect with a contact call `send_decision`;
SEND -> send the rendered first/follow-up message via Gmail, else create a draft; then search the inbox for replies from
known contacts, classify each with `classify_reply`, apply `plan_action` (update the CSV via `advance`, send only the
opt-out confirmation, draft the rest). Report counts only; never print message bodies of third parties into logs.
