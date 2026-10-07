# OLA Revenue + Marketing Flow

## Verified base

Current main contains a verified sandbox payment boundary:

MARKETING SURFACE → STRIPE PAYMENT LINK (SANDBOX) → checkout.session.completed → payment evidence → OLA six-agent runtime → completion evidence → customer result.

The repository's E2E gate verifies the checkout webhook signature, paid status, exact EUR 99 offer/price, OLA execution, evidence creation and webhook idempotency.

## Current commercial state

- OLA runtime: VERIFIED in CI-tested scope.
- Stripe checkout → OLA execution: VERIFIED in sandbox/CI-tested scope.
- Existing Stripe Payment Link: active in test mode, EUR 99.
- Production payment/webhook: NOT VERIFIED.
- Real customer / first euro: NOT PROVEN.
- Marketing distribution: NOT YET CONNECTED to an external channel.

## Concrete flow

1. **MARKETING** — publish the offer page through an approved channel.
2. **LEAD** — visitor arrives with campaign/source context.
3. **CHECKOUT** — one CTA points to the Stripe Payment Link.
4. **CONFIRMED PAYMENT** — Stripe emits `checkout.session.completed`.
5. **OLA EXECUTION** — webhook validates the offer, payment and audit task, then starts OLA.
6. **EVIDENCE** — payment and completion records are appended to the tenant hash chain.
7. **VERIFIED RESULT** — OLA runtime returns the result and its evidence IDs.
8. **CUSTOMER DELIVERY** — the customer receives the completed audit result.
9. **MEASUREMENT** — campaign → checkout → paid → completed audit is measured only from observed events.

## Gate policy

Never promote:

- sandbox payment to real revenue;
- CI evidence to production evidence;
- an unverified marketing claim to a verified product claim.

The production activation gate remains:

PUBLIC HTTPS WEBHOOK + LIVE STRIPE CONFIGURATION + LIVE PAYMENT + OBSERVED WEBHOOK + OLA EXECUTION + EVIDENCE + INDEPENDENT VERIFY + CUSTOMER DELIVERY.

Until that chain is observed end-to-end, status stays **NOT PROVEN**.

## Computed proof (`GET /revenue/proof`, tenant API key)

The status above is no longer only a sentence: `app/revenue_proof.py` computes it from the tenant's evidence chain and the
webhook table. It never calls Stripe and reads no configuration flag. A paid session is `PROVEN` only when all six steps
hold: `LIVE_PAYMENT` (the payment evidence carries Stripe's `livemode: true`; recorded since this change, older payments
and non-boolean values are mode `UNKNOWN` and never count), `OBSERVED_WEBHOOK`, `RUN_PERFORMED`, `RUN_VERIFIED`,
`EVIDENCE_BOUND` (event, session, payment evidence and run ids agree) and `RESULT_SERVED` (`revenue.result_served`
carries the digest of the stored result, written when `/payment-success` hands the result over). A broken hash chain
means nothing is trusted. With no live payment the answer is `NOT_PROVEN` with the list of what is missing.

Still not observable from records, and always listed in `not_observable`: that the webhook URL is public HTTPS, that the
customer received the result, and an independent judge (the paid run is verified by the runtime itself).
