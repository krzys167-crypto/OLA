# OLA audit offer - tiers, scope, claims (v0, a hypothesis to test)

Status: **prices are hypotheses, not measured.** No customer has paid; production payment is NOT PROVEN
(`docs/revenue-marketing-flow.md`). The first ten conversations decide the price, not this table.

## Who it is for
Brussels SMEs with repetitive administrative work: property agencies, accounting firms, logistics companies
(prospect list: `sales/prospects.csv`, from issue #38). This is not the regulated-fintech market (DORA/NIS2), where
comparable assessments start around EUR 5 000-10 000; that market is a later, separate offer.

## Tiers
| Tier | Price (excl. VAT) | What the customer gets | How it is paid |
|---|---|---|---|
| Quick Map | EUR 490 | one process, one sample set, 5-page map of what can and cannot be automated, evidence record of the analysis, 30-min call | invoice |
| Process Audit | EUR 1 500 | up to three processes, estimates per finding, fixed-price implementation quote, evidence trail of the analysis, 60-min walkthrough; the fee is credited against implementation | invoice |
| Monthly Watch | EUR 250-400 / month | re-run of the checks on new samples, change log, one call a month; sold only after a Process Audit | invoice or subscription |
| Flow test | EUR 99 | only to test the Stripe checkout end to end; not a public price | Stripe |

The automated Stripe flow accepts exactly EUR 99 (`/checkout`, strict amount check). The paid tiers are therefore
**invoiced by hand** until a deliberate change makes the flow accept them. Do not describe the EUR 1 500 tier as running
through the automatic flow.

Payment of an invoice directly to the owner's Revolut account (link or SEPA transfer), and how it may be called, is in
`payment-revolut.md`. It needs no live Stripe set-up. Nothing has been paid yet.

## What may be claimed (and what may not)
May: the analysis is run on the customer's samples; the run is recorded in a hash-chained evidence record that can be
re-verified; scope and price are fixed in advance.
May not: compliance certification, guaranteed savings, named references (there are none), "verified" without saying by
whom, or an independent judge model (not part of the paid path today).

## Process
1. Prospect gets a short first message (`sales/templates/`, drafts only; a human sends it, from a business address the
   prospect published, with an opt-out line).
2. 20-minute call; scope and price confirmed in writing.
3. Customer provides sample documents (no production access, no personal data beyond what the samples contain).
4. Delivery: report + evidence + walkthrough. Implementation is quoted separately.

## What is automated, and what stays human
Automated: the prospect queue, follow-up timing, draft texts (EN/FR), a weekday report of who is due
(`.github/workflows/sales-daily.yml`: read-only, no secrets, sends nothing; it fires on a schedule only after it is merged to
the default branch), and for the EUR 99 flow: checkout, webhook, run, evidence, delivery and `GET /revenue/proof`.
Human by design: sending any message, adding a contact, the call, the price, the invoice, and the first live payment.

## Open decisions for the owner
- Price points above (test them: if 0 of the first 10 conversations object to EUR 1 500, raise it).
- VAT/invoicing set-up and the company entity that invoices.
- Whether to make the Stripe flow accept the paid tiers.
- Which Revolut account (legal entity) receives the invoice payments, and the invoice/VAT format (`payment-revolut.md`).
- B2B cold e-mail rules in Belgium (legitimate interest, opt-out, language): check with a lawyer before sending in bulk.
