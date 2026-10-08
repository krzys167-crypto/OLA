# Taking the first payment through Revolut (manual, owner-attested)

Status: **nothing in this document has been executed. No customer has paid. First euro: NOT PROVEN.**
It describes a path that needs no Stripe account in live mode. Prices are the hypotheses from `offer.md`.

**Correction, 2026-10-08.** The first version of this file treated the owner's *personal* Revolut account as a possible
receiving account and listed its permitted use as an open question. Revolut's own terms answer that question (below): a
personal account is not the account to invoice to. The path itself (invoice, transfer, owner attests the credit) is unchanged;
only the receiving account changes.

## Why this path
The paid tiers in `offer.md` (Quick Map, Process Audit, Monthly Watch) are already **invoiced by hand**. They never ran
through the automatic Stripe flow, which accepts exactly EUR 99 and is a test. So the customer can pay the invoice
directly to a bank account of the owner, and the product does not have to wait for a live Stripe set-up or a public webhook.

## What Revolut's own terms say (read by the author on 2026-10-08; not legal advice)
The quotes below were returned by a page-reading tool, which summarises; open the pages (listed at the end) before relying
on them.
- **Personal Terms, Revolut Bank UAB Belgian Branch, Section 2:** "You must not use it for business purposes." The following
  sentence says that a customer who wants to use the account for business must apply for a Revolut Pro account or a Revolut
  Business account (Section 4: "you will need to apply for a Revolut Pro account under the Revolut Pro account terms").
  The same sentence is in the version that applies from 31 March 2026 (PDF) and in the version the web page says applies
  from 2 December 2026.
- **Section 24** lists "your personal account is used for non-personal purposes" among the circumstances in which Revolut
  may suspend or close the account.
- **Revolut.Me:** "You cannot use Revolut.Me to receive payments unless you first enter into a Payment Processing Services
  Agreement with us." The page calls it "an easy way to accept payments from your customers" and does not say which account
  types may use it. Limits and fee are not stated there ("which we will show you in the app"; the fee is "set out in our
  Fees Page").
- **Revolut Pro** (help centre, Belgium): "Pro is made for freelancers, side-hustlers, sole traders, and those who are
  self-employed"; "Pro isn't for legal entities or partnerships."; "You can use Pro if you're not registered in your local
  business registry (depending on regional requirements)." Whether Belgian rules let the owner invoice without a registered
  activity is **UNKNOWN** here and is a question for the accountant, not something Revolut's page decides.
- **Revolut Pro Account terms** (Belgium page, "This version of the Terms applies from 13 June 2025"): Section 3 "are a
  self-employed natural person (not a company);" and Section 4 "Revolut Pro is only available to self-employed natural persons
  (not companies)" and requires an existing Revolut Personal account. Section 5: "it's a separate account. It has its own
  separate balance, its own account number". Section 6: "It can only be used for business purposes."; accepting payments
  from "people who purchase your goods or services" is tied to a payment processing product and only "If we accept you can use
  this product". Section 7: "There is no fee to open or hold a Revolut Pro account." and the fees for using it "are the same
  as the fees that apply for using your Personal account."
- **Revolut Pro features** (help centre): "It comes with a separate IBAN, payment acceptance tools," listing Payment Links,
  Revolut Reader, Tap to Pay on iPhone and a Shopify plugin. That page does **not** describe incoming SEPA transfers and does not
  say what country code the Pro IBAN has: both **UNKNOWN**. **Payment Links** (Pro help page): customers can "complete
  purchases or settle invoices"; fees shown: "1.0% + £0.20 (or currency equivalent)" for domestic personal Visa/Mastercard
  and "2.8% + £0.20 (or currency equivalent)" for international and commercial cards (the page shows £). The page does not say
  who may use Payment Links.

Reading of the author: fee income for services is business use, so it does not belong on a personal account. Whether a
transfer would technically arrive is a different question from whether the terms allow it, and the terms are what count.
This document does not claim that Revolut would block any particular transfer.

## Ways for the customer to pay
- **A. SEPA transfer to a business-capable account:** a Revolut Pro account (it has its own IBAN), Revolut Business, or an
  account at another bank that accepts business income. Whether the Pro IBAN accepts ordinary SEPA transfers from company
  clients, and which country code it has: **UNKNOWN** on the pages read; ask Revolut. The payee and IBAN on the invoice must
  match the person or entity that invoices.
- **B. Payment link** (Revolut Pro Payment Links, or Revolut.Me where the account type has it): it needs Revolut's acceptance
  for payment processing (Pro Terms Section 6; Payment Processing Services Agreement for Revolut.Me). The fees shown are card
  fees (above). Fees and limits for an ordinary incoming transfer to Pro: **UNKNOWN** (not on the pages read).
- **Not recommended: payment to the personal account** (SEPA or Revolut.Me). It conflicts with Section 2 as read above and
  puts the account at risk under Section 24.

**Never put an IBAN, a payment link, a token or a card detail in this repository, in issues, in PR comments or in CI.**
They go only into the invoice or the message the owner sends to the customer. The repository is public.

## What the owner has to settle first (none of it was decided by the author)
- With the **accountant:** whether the activity must be registered (BCE/KBO) before the first invoice, which status or
  entity invoices, VAT treatment in Belgium for this service, invoice content and numbering.
- With **Revolut** (in the app chat), questions worth asking verbatim:
  1. "I live in Belgium and want to open Revolut Pro as a self-employed natural person. Is a Belgian BCE/KBO enterprise
     number mandatory before my Pro account can be approved?"
  2. "Your Belgian Pro help page says I can use Pro without registration in the local business registry 'depending on regional
     requirements'. What exactly are the regional requirements for Belgium?"
  3. "Can a Belgian Revolut Pro IBAN receive ordinary EUR SEPA bank transfers directly from companies paying my invoices?"
  4. "Will my Pro account get a BE IBAN? Are there incoming-transfer fees or limits specific to Pro?"
- Whether to take the full amount up front (simplest for EUR 490) or a deposit (an option for EUR 1 500).
- Cold-mail rules for B2B in Belgium before any bulk sending (already listed in `offer.md`).

## Flow
1. The call ends with scope and price confirmed **in writing** (`offer.md`, process step 2).
2. The owner issues the invoice: number, date, scope, amount, VAT as the accountant says, due date, payment reference.
3. The customer pays by A or B.
4. **The owner checks the credit in the receiving account**: amount, currency, reference, date. Nothing starts before that.
5. Delivery as in `offer.md` step 4 (report, evidence, walkthrough). The evidence of the analysis is the pipeline session,
   checked with the stand-alone verifier; the Stripe-based receipt does not exist for an invoiced payment.
6. The owner writes one line in the delivery note: invoice number, date the credit was seen, amount.

## What may be called what
| State | Meaning | Who can say it |
|---|---|---|
| PAYMENT_CLAIMED | the customer says they paid | nobody may count it as money |
| PAYMENT_ATTESTED | the owner saw the matching credit (amount + reference + date) in the receiving account | the owner, a human attestation |
| PROVEN (system) | `GET /revenue/proof` shows a live Stripe payment, webhook and run | only the Stripe path can reach it |

`GET /revenue/proof` is computed from Stripe evidence (`livemode: true`) and will stay `NOT_PROVEN` for a customer who paid
by transfer. That is correct, not a bug: the system cannot see a bank. Call the first such payment
**PAYMENT_ATTESTED by the owner**. Do not call it VERIFIED.

## Texts for the customer (fill the placeholders by hand; send from the business address)
Placeholders: `{name}`, `{scope}`, `{amount}`, `{invoice_no}`, `{pay_link_or_iban}`, `{sender}`. No placeholder is ever
filled in this repository.

### EN - after the call, with the invoice attached
> Hello {name},
>
> As agreed on our call: {scope}, fixed price EUR {amount} excl. VAT, delivered after payment. The invoice {invoice_no} is
> attached.
>
> You can pay by SEPA transfer to the IBAN on the invoice, or with this payment link: {pay_link_or_iban}. Please use
> {invoice_no} as the payment reference. I start as soon as I see the payment and will confirm by e-mail.
>
> If you would rather not go ahead, just tell me; nothing is owed until you pay.
>
> {sender}

### FR - après l'appel, facture jointe
> Bonjour {name},
>
> Comme convenu lors de notre appel : {scope}, prix fixe de {amount} EUR HTVA, livré après paiement. La facture {invoice_no}
> est jointe.
>
> Vous pouvez payer par virement SEPA sur l'IBAN indiqué sur la facture, ou avec ce lien de paiement : {pay_link_or_iban}.
> Merci d'indiquer {invoice_no} comme communication. Je commence dès que je vois le paiement et vous le confirmerai par e-mail.
>
> Si vous préférez ne pas donner suite, dites-le-moi simplement ; rien n'est dû tant que vous n'avez pas payé.
>
> {sender}

### EN - after the credit is seen
> Hello {name}, I have received the payment for invoice {invoice_no}. I am starting now; you will get the report, the
> evidence record and a walkthrough slot by e-mail.

## Pages the quotes come from (opened 2026-10-08)
- Personal Terms, Belgian branch, web page (text applying from 2 December 2026): <https://www.revolut.com/en-BE/legal/terms/>
- Personal Terms, same branch, version applying from 31 March 2026 (PDF):
  <https://cdn.revolut.com/terms_and_conditions/pdf/personal_terms_5b72a354_1.8.0_1775130881_en.pdf>
- Payment Terms - Revolut.Me: <https://www.revolut.com/en-BE/legal/payment-terms-revme/>
- Revolut Pro eligibility (help centre):
  <https://help.revolut.com/en-BE/help/more/revolut-pro/who-can-use-pro-and-how-to-get-started/>
- Revolut Pro Account terms: <https://www.revolut.com/en-BE/legal/pro/>
- Revolut Pro features: <https://help.revolut.com/en-BE/help/more/revolut-pro/features-available-with-revpro/>
- Revolut Pro Payment Links:
  <https://help.revolut.com/en-BE/help/more/revolut-pro/accepting-customer-payments/payment-links-and-how-to-use-them-for-pro/>

## What this document does not claim
No customer, no conversion rate, no revenue forecast and no fee figure: none was measured. It says nothing about tax or
company-law obligations beyond the questions above, and it does not say what Revolut would do with any particular payment;
it reports what the terms say.
