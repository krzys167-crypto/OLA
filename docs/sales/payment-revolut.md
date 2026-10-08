# Taking the first payment through Revolut (manual, owner-attested)

Status: **nothing in this document has been executed. No customer has paid. First euro: NOT PROVEN.**
It describes a path that needs no Stripe account in live mode. Prices are the hypotheses from `offer.md`.

**Correction, 2026-10-08.** The first version of this file treated the owner's *personal* Revolut account as a possible
receiving account and listed its permitted use as an open question. Revolut's own terms answer that question (below): a
personal account is not the account to invoice to. Later the same day the owner pointed out that the account has a Polish
address, so the Polish-region documents were read too: the conclusion holds there (Section 2), and one clause cited at first
(Section 24, "non-personal purposes") is in the Belgian text only. The path itself (invoice, transfer, owner attests the
credit) is unchanged; only the receiving account changes.

## Why this path
The paid tiers in `offer.md` (Quick Map, Process Audit, Monthly Watch) are already **invoiced by hand**. They never ran
through the automatic Stripe flow, which accepts exactly EUR 99 and is a test. So the customer can pay the invoice
directly to a bank account of the owner, and the product does not have to wait for a live Stripe set-up or a public webhook.

## What Revolut's own terms say (read by the author on 2026-10-08; not legal advice)
**Which terms apply.** The owner says the Revolut account has a **Polish address**, so the Polish-region documents most likely
govern it (in both regions the provider named is Revolut Bank UAB, Lithuania). Which version applies to this account:
**UNKNOWN**; the owner can see it in the app. The author read the Polish and the Belgian pages. The quotes were returned by
a page-reading tool, which summarises; open the pages (listed at the end) before relying on them.

**Personal Terms, Polish region** ("Regulamin kont osobistych"; the page says "Ta wersja Regulaminu będzie obowiązywać od
9 października 2023 roku" and shows no newer version):
- Section 2: "Nie możesz używać go do celów biznesowych." (English page of the same document: "You must not use it for
  business purposes.") The next sentence says that anyone who wants to use the account for business must apply for a Revolut
  Pro or a Revolut Business account. Section 4 repeats the restriction.
- Section 24 (suspension, closure) in this version has no item about "non-personal purposes"; it lists cases and "other
  reasons". The wording "your personal account is used for non-personal purposes" is in the **Belgian** text that applies from
  31 March 2026 (Section 24), not in the Polish text read.
- Section 16: "You may be able to send or receive payments from others using Revolut.Me links."

**Revolut.Me Payment Terms** (Belgian page; the Polish page was not read): "You cannot use Revolut.Me to receive payments
unless you first enter into a Payment Processing Services Agreement with us." The page calls it "an easy way to accept payments
from your customers" and does not say which account types may use it. Limits and fee are not stated there ("which we will show
you in the app"; the fee is "set out in our Fees Page").

**Revolut Pro, Polish region.** Pro Account terms (page: "This version of the terms applies from 26 December 2023"):
Section 3 "are a self-employed natural person (not a company);"; Section 4 requires an existing Personal account; Section 5
"it's a separate account", "its own separate balance, its own account number"; Section 6 "It can only be used for business
purposes." and accepting payments from "people who purchase your goods or services" only "If we accept you can use this
product"; Section 7 "There is no fee to open or hold a Revolut Pro account", fees "the same as" the Personal account and
"will depend on what type of Personal account you have", except a different fee for ordering a Pro card. Help centre (Polish):
"Konto Pro możesz założyć nawet wtedy, gdy nie jesteś zarejestrowany w lokalnym rejestrze przedsiębiorstw" followed by
"(wymagania mogą różnić się w zależności od regionu)"; the page does not mention CEIDG, NIP or REGON; Revolut "możemy poprosić o
potwierdzenie prowadzenia działalności gospodarczej" (a business URL, or "dowodu rejestracji"); the application asks for a
business category and a description. Whether the owner's own country's rules require registering before the first invoice is
**UNKNOWN** here: a question for the accountant, not something Revolut's page decides.

**Revolut Pro features and Payment Links** (English pages of the Belgian region; Polish equivalents not read): "It comes with a
separate IBAN, payment acceptance tools," listing Payment Links, Revolut Reader, Tap to Pay on iPhone and a Shopify plugin.
That page does **not** describe incoming SEPA transfers and does not say what country code the Pro IBAN has: both **UNKNOWN**.
Payment Links: customers can "complete purchases or settle invoices"; fees shown: "1.0% + £0.20 (or currency equivalent)" for
domestic personal Visa/Mastercard and "2.8% + £0.20 (or currency equivalent)" for international and commercial cards (the page
shows £). The page does not say who may use Payment Links.

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
- **Not recommended: payment to the personal account** (SEPA or Revolut.Me). It conflicts with Section 2 as read above (and the
  Belgian text lists such use among the grounds to suspend or close the account).

**Never put an IBAN, a payment link, a token or a card detail in this repository, in issues, in PR comments or in CI.**
They go only into the invoice or the message the owner sends to the customer. The repository is public.

## What the owner has to settle first (none of it was decided by the author)
- With the **accountant:** in which country the activity is (or will be) registered and which country's rules apply to the
  invoice (the Revolut account has a Polish address, the prospects are in Brussels: this document does not decide that);
  whether registration is needed before the first invoice, which status or entity invoices, VAT treatment for a service sold
  to a company in another EU country, invoice content, numbering and any e-invoicing rule in force.
- With **Revolut** (in the app chat), questions worth asking verbatim:
  1. "I have a Revolut account with a Polish address. I want to open Revolut Pro as a self-employed natural person to invoice
     companies in other EU countries. Is registration in a business register (CEIDG or other) mandatory before my Pro account
     can be approved?"
  2. "Your Polish Pro help page says I can open Pro even if I am not registered in the local business registry, and that the
     requirements may differ by region. What exactly are the requirements for Poland?"
  3. "Can a Polish Revolut Pro IBAN receive ordinary EUR SEPA transfers from companies paying my invoices, and what is the
     IBAN's country code?"
  4. "Are there incoming-transfer fees or limits specific to Pro?"
- Whether to take the full amount up front (simplest for EUR 490) or a deposit (an option for EUR 1 500).
- Cold-mail rules for B2B (recipients in Belgium, sender elsewhere) before any bulk sending (listed in `offer.md`).

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
- Personal Terms, Polish region (Polish and English pages): <https://www.revolut.com/pl-PL/legal/terms/> and
  <https://www.revolut.com/en-PL/legal/terms/>
- Revolut Pro Account terms, Polish region: <https://www.revolut.com/pl-PL/legal/pro/>
- Revolut Pro eligibility, Polish help centre: <https://help.revolut.com/pl-PL/help/more/revolut-pro/who-can-use-pro-and-how-to-get-started/>
- Personal Terms, Belgian region, web page (text applying from 2 December 2026): <https://www.revolut.com/en-BE/legal/terms/>
- Personal Terms, Belgian region, version applying from 31 March 2026 (PDF):
  <https://cdn.revolut.com/terms_and_conditions/pdf/personal_terms_5b72a354_1.8.0_1775130881_en.pdf>
- Payment Terms - Revolut.Me (Belgian page): <https://www.revolut.com/en-BE/legal/payment-terms-revme/>
- Revolut Pro features and Payment Links (English, Belgian region):
  <https://help.revolut.com/en-BE/help/more/revolut-pro/features-available-with-revpro/> and
  <https://help.revolut.com/en-BE/help/more/revolut-pro/accepting-customer-payments/payment-links-and-how-to-use-them-for-pro/>

## What this document does not claim
No customer, no conversion rate, no revenue forecast and no fee figure: none was measured. It says nothing about tax or
company-law obligations beyond the questions above, and it does not say what Revolut would do with any particular payment;
it reports what the terms say.
