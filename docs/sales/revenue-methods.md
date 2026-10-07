# Revenue methods for the OLA ecosystem - ranked, with status and a cheap test for each

Honest baseline: no customer has paid; production payment is NOT PROVEN; every number below that is a price is a
hypothesis. Each method says what exists in the repo, what is missing, how to test demand cheaply and when to drop it.
"Innovative" here means: something the product can do that an ordinary audit or an LLM-observability tool does not.

| # | Method | Status in repo | Why it differs | Cheapest demand test | Drop it if |
|---|---|---|---|---|---|
| 1 | **Verifiable Receipt** attached to every paid result | BUILT: `GET /revenue/receipt/{session}`, `tools/verify_receipt.py` (offline, no OLA code), tests + mutations | The customer can re-check the chain, the payment-to-result links and that the delivered result is the one recorded, without trusting a screenshot or a PDF | Show the receipt and the verifier in the first call; ask "would you attach this to your own client file?" | 0 of the first 10 prospects care |
| 2 | **Anchored receipt** (head hash timestamped outside OLA) | PARTIAL: `app/anchor_external.py` (RFC 3161) exists; not wired into the receipt (`anchor` is empty) | Closes the receipt's main limit: an operator writing the whole chain afresh | Wire it only after #1 shows interest | Customers do not ask who could forge the chain |
| 3 | **Audit credit**: fee credited against implementation | IDEA (doc only, `offer.md`) | Lowers the risk of the first purchase; a market precedent exists (a EUR 3 500 code audit credited to repair work) | Offer it in the first 5 proposals | It lowers the audit price they accept without raising conversion |
| 4 | **Sector packs**: ready scenarios for property, accounting, logistics | PARTIAL: sector hooks in `sales_pipeline.py`; no sector scenarios yet | Faster, repeatable delivery; a pack can be priced by itself | Do the first 3 audits by hand and keep what repeats | Each client needs a different process |
| 5 | **Monthly Watch**: re-run on new samples, a fresh receipt each month | IDEA | Recurring revenue backed by recurring proof, not a report that goes stale | Sell only after a Process Audit; ask at the debrief | Nobody renews after month 1 |
| 6 | **Channel through accountants**: they resell the audit to their own clients | IDEA | One accountant holds many small clients; the receipt is something they can show clients | Ask 2 accounting prospects (5 in the queue) | They want a white label you cannot support |
| 7 | **Open verifier, paid hosting/anchoring** (open-core) | PARTIAL: verifier is stdlib-only and importable by anyone | Free tool earns trust and inbound; money comes from anchoring and hosting | Publish the verifier with the offer; count who asks about hosting | Nobody uses the free verifier |
| 8 | **Evidence for AI-use policies** (what a company can show an auditor or insurer) | IDEA, needs legal review | Turns the receipt into a document in the customer's compliance file | Ask 2 prospects whether anyone has asked them to document AI use | The question never comes up, or a lawyer says the claim is too strong |
| 9 | **CFR training range** (fault-injection scenarios for engineers) | EXISTS as scenarios in `cfr_scenarios`; no billing | A different market (engineering teams); longer sales cycle | Not before 1-3 | Do not start before the first paid audit |

## Order of work
1. Keep #1 in every conversation; it is built and tested. 2. Run 10 conversations from `sales/prospects.csv` (a human
sends the messages). 3. Decide #2, #3, #5 from what prospects actually say. 4. Everything else waits for a first
payment. Do not build #4-#9 on speculation.

## What this document does not claim
No market size, no conversion rate and no revenue forecast: none was measured. The receipt shows consistency of the
operator's own records, not that Stripe took the money and not an independent verification of the work.
