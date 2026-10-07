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
2. SEND additionally needs: fewer than `daily_cap` sent today, a weekday, 09:00-17:00 Brussels, a contact filled in by a
   human, and a stage that is due.
3. An **opt-out** ("stop", "unsubscribe", "ne plus me contacter", ...) sets DO_NOT_CONTACT at once and is the only reply
   sent without a human (a one-line confirmation). A **decline** sets LOST and sends nothing.
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
