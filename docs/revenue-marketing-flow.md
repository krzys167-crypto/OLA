# OLA Revenue + Marketing Flow

## Backend implementation scope

The repository contains a payment execution path:

MARKETING SURFACE → Stripe Checkout Session → signed `checkout.session.completed` webhook → payment validation → OLA execution → Evidence V2 records → session-bound result lookup.

The source implements:
- Checkout Session creation with offer, task and tenant metadata;
- Stripe webhook HMAC signature and timestamp verification;
- validation of the offer, paid status, EUR 99 amount and task;
- idempotency by Stripe event ID;
- payment and execution evidence appended to the tenant evidence chain;
- `/payment-success` lookup bound to the exact Checkout Session, so a result from another order is not returned.

**Implemented backend code is not the same as an available public checkout or a live payment proof.**

## Connected Stripe account — read-only check 2026-11-05

The connected Stripe account `ola sandbox` (`livemode=false`) returned:
- Products: **0**;
- Prices: **0**;
- Payment Links: **0**;
- Checkout Sessions: **0**.

No Stripe LIVE account is available in the connected integration. These results describe only the connected sandbox account; they do not prove that no other account exists.

The EUR 99 amount in the repository's former static CTA was not a configured Stripe Price. No product, Price, Payment Link, Checkout Session or customer payment was created during this audit.

## Actual public marketing site — Vercel read-only check 2026-11-05

A Vercel project named `ola-ai-trust-express` has a Production deployment marked `READY`; its public domain `ola-ai-trust-express.vercel.app` returned HTTP 200 during this check.

This is a **static marketing/enquiry page**, not evidence of a deployed OLA backend:
- Vercel project lookup filtered by Git repository `krzysztofcieciwa07-ship-it/OLA` returned **0 projects**.
- The Git-linked project inventory did not list the OLA repository.
- Deployment details requested with Git repository metadata did not return a `gitSource` / source commit binding.
- The live page invites email enquiries, explicitly says there are no online payments or binding orders on the site, and labels €490 as an indicative introductory pilot price.
- There is no observed payment, customer tenant provisioning, authenticated backend checkout or automatic OLA execution from that public page.

**Do not treat the Vercel deployment as a production deployment of the current OLA repository.** Its source-to-repository relationship is UNKNOWN.

## Repository landing-page artifact — PR #175

The repository file `revenue/index.html` is a separate static artifact. Its previous version contained a hard-coded Stripe TEST URL despite the connected sandbox having no Payment Links. It was not confirmed as the source of the Vercel public page.

PR #175:
- removes that unverified Stripe URL from the repository artifact;
- marks €99 as a planned price, not an active Stripe Price;
- replaces the clickable test link with a disabled checkout state;
- marks the runtime label `CI-VERIFIED` rather than an unqualified `VERIFIED`;
- adds a static guard and a regression test against reintroducing a hard-coded Stripe URL.

**PR #175 does not update the existing Vercel deployment**, because that Vercel project is not linked to the OLA Git repository. No Vercel project, domain or deployment mutation was made.

## Customer path and current commercial status

- A public email enquiry path exists on the separate Vercel page.
- The public page does not accept online payments or binding orders.
- `POST /checkout` in the repository requires an existing tenant `X-API-Key`; the public page does not provision that tenant or invoke this endpoint.
- No public customer-onboarding path connects the email enquiry to automated tenant provisioning or the repository's `/checkout` endpoint.
- A manual email enquiry is a lead, not a paid order.
- Stripe webhook tests use synthetic payloads and a test secret; they do not demonstrate a LIVE Stripe event.
- `tests/test_payment_session_binding.py` stubs Checkout Session retrieval; it does not perform a real Stripe request.
- No production payment, real customer, first euro or completed customer delivery is proven.

## Required next chain

1. Confirm the canonical offer and price (the live enquiry page currently says indicative €490; the repository had a separate €99 placeholder).
2. Establish a source-controlled relationship between the public marketing page and the approved OLA repository, without silently replacing the existing Vercel deployment.
3. Decide the compliant customer intake and contracting/invoicing process for the pilot.
4. If online checkout is required, configure an authorized Stripe LIVE account and a verified product/one-time Price.
5. Implement safe customer/tenant provisioning without exposing API keys, then connect the landing-page enquiry/checkout bootstrap to the backend.
6. Configure the LIVE API key and webhook secret in the authorized production environment.
7. Verify signed LIVE webhook delivery, exact Price ID, paid status and idempotent processing.
8. Run OLA, independently verify evidence and deliver the exact order-bound customer result.
9. Observe a real payment and customer delivery before marking revenue LIVE.

Never promote:
- sandbox configuration to live revenue;
- synthetic webhook fixtures to a live Stripe event;
- a hard-coded Payment Link URL to an active link without an account-side read;
- an unverified Vercel deployment to a deployment of the current OLA Git SHA;
- CI evidence to production evidence;
- a runtime proof to a customer-delivery claim.

Until the complete chain is observed end-to-end, status remains **LIVE_PAYMENT_NOT_PROVEN**.
