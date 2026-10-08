# Taking the first payment through Revolut (manual, owner-attested)

Status: **nothing in this document has been executed. No customer has paid. First euro: NOT PROVEN.**
It describes a path that needs no Stripe account in live mode. Prices are the hypotheses from `offer.md`.

## Why this path
The paid tiers in `offer.md` (Quick Map, Process Audit, Monthly Watch) are already **invoiced by hand**. They never ran
through the automatic Stripe flow, which accepts exactly EUR 99 and is a test. So the customer can pay the invoice
directly to the owner's Revolut account, and the product does not have to wait for a live Stripe set-up or a public
webhook.

## Two ways for the customer to pay
- **A. Revolut payment link.** The owner creates it in the Revolut Business app (amount, description, invoice number).
  The customer pays by card or wallet. Fees and limits are set by Revolut: UNKNOWN here, read them in the app.
- **B. SEPA transfer** to the owner's Revolut Business IBAN, with the invoice number as the payment reference.

**Never put an IBAN, a payment link, a token or a card detail in this repository, in issues, in PR comments or in CI.**
They go only into the invoice or the message the owner sends to the customer. The repository is public.

## What the owner has to settle first (not legal advice; none of it was checked by the author)
- Which legal entity invoices, and that the receiving Revolut account is in that entity's name and accepts business payments.
- Invoice content, numbering and VAT treatment in Belgium for this service: ask the accountant.
- Whether to take the full amount up front (simplest for EUR 490) or a deposit (an option for EUR 1 500).
- Cold-mail rules for B2B in Belgium before any bulk sending (already listed in `offer.md`).

## Flow
1. The call ends with scope and price confirmed **in writing** (`offer.md`, process step 2).
2. The owner issues the invoice: number, date, scope, amount, VAT as the accountant says, due date, payment reference.
3. The customer pays by A or B.
4. **The owner checks the credit in the Revolut app**: amount, currency, reference, date. Nothing starts before that.
5. Delivery as in `offer.md` step 4 (report, evidence, walkthrough), with the verifiable receipt from the run.
6. The owner writes one line in the delivery note: invoice number, date the credit was seen, amount.

## What may be called what
| State | Meaning | Who can say it |
|---|---|---|
| PAYMENT_CLAIMED | the customer says they paid | nobody may count it as money |
| PAYMENT_ATTESTED | the owner saw the matching credit in Revolut (amount + reference + date) | the owner, a human attestation |
| PROVEN (system) | `GET /revenue/proof` shows a live Stripe payment, webhook and run | only the Stripe path can reach it |

`GET /revenue/proof` is computed from Stripe evidence (`livemode: true`) and will stay `NOT_PROVEN` for a customer who paid
through Revolut. That is correct, not a bug: the system cannot see Revolut. Call the first Revolut payment
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

## What this document does not claim
No customer, no conversion rate, no revenue forecast and no fee figure: none was measured. It says nothing about tax or
company-law obligations beyond the questions above.
