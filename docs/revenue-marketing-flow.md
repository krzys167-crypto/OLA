# OLA Revenue + Marketing Flow

## Verified implementation scope

OLA contains a payment execution path:

MARKETING SURFACE → Stripe Checkout Session → signed `checkout.session.completed` webhook → payment validation → OLA execution → Evidence V2 records → customer result.

The source implements:
- Checkout Session creation with offer, task and tenant metadata;
- Stripe webhook HMAC signature and timestamp verification;
- offer/product, paid status, EUR 99 amount and task checks;
- idempotency by Stripe event ID;
- payment and execution evidence appended to the tenant evidence chain.

**This source path is not the same as a live payment proof.**

The current automated checks have these scopes:
- `tests/test_stripe_webhook.py` validates signature and payment fields with synthetic payloads and a test webhook secret;
- `tests/test_payment_session_binding.py` replaces the Stripe session retrieval function with a test stub;
- `revenue-surface.yml` checks static page content and the presence of a hard-coded test URL. It does not call Stripe or verify that the Payment Link is active.

These checks are useful regression controls, but they do not demonstrate an actual Stripe Checkout Session or a customer payment.

## Current commercial state — rechecked 2026-11-05

- OLA agent runtime: VERIFIED in isolated CI-tested scope (see exact-source Ollama and NINA/IGOR runs recorded in OLA issue #153).
- Stripe webhook and checkout logic: IMPLEMENTED; synthetic signature, validation and session-binding tests exist.
- Connected Stripe account: only `ola sandbox`, with `livemode=false`.
- Payment Links returned by the connected sandbox account: **0**.
- Checkout Sessions returned by the connected sandbox account: **0**.
- The marketing page still contains a hard-coded Stripe test URL and labels the offer as a sandbox preview. Its current existence/availability is **NOT VERIFIED** against the connected Stripe account.
- A Stripe LIVE account is not available in the connected integration.
- Production payment/webhook: NOT VERIFIED.
- Real customer / first euro: NOT PROVEN.
- Marketing distribution: NOT YET CONNECTED to an external channel.

The empty Stripe API lists apply only to the connected sandbox account. They do not prove that the public URL is invalid or that no other Stripe account exists. They do mean that the repository must not claim an active Payment Link on the currently connected account.

## Concrete flow

1. **MARKETING** — publish the offer page through an approved channel.
2. **LEAD** — visitor arrives with campaign/source context.
3. **CHECKOUT** — use a Payment Link or Checkout Session whose existence and configuration have been independently checked in the intended Stripe account.
4. **CONFIRMED PAYMENT** — Stripe emits `checkout.session.completed`; the webhook signature and paid status are verified.
5. **OLA EXECUTION** — webhook validates the exact offer, payment and audit task, then starts OLA.
6. **EVIDENCE** — payment and completion records are appended to the tenant hash chain.
7. **VERIFIED RESULT** — OLA runtime returns the result and its evidence IDs; independent verification checks the complete evidence.
8. **CUSTOMER DELIVERY** — the customer receives the completed audit result.
9. **MEASUREMENT** — campaign → checkout → paid → completed audit is measured only from observed events.

## Gate policy

Never promote:
- sandbox payment to real revenue;
- synthetic webhook fixtures to a live Stripe event;
- a hard-coded Payment Link URL to an active link without an account-side read;
- CI evidence to production evidence;
- an unverified marketing claim to a verified product claim.

The production activation gate remains:

PUBLIC HTTPS WEBHOOK + LIVE STRIPE CONFIGURATION + LIVE PAYMENT + OBSERVED WEBHOOK + OLA EXECUTION + EVIDENCE + INDEPENDENT VERIFY + CUSTOMER DELIVERY.

Until that chain is observed end-to-end, status stays **NOT PROVEN**.
