# Labelling rubric (Derby evaluation)

Every test message gets one of three labels. The label describes the **risk to the recipient if they act on the message**. TrustGate is meant to judge scam, fraud and impersonation risk before money or credentials move. It does not judge whether a message is spam.

The rubric was written before any system output was produced. The same rubric was given to:
- the independent agents that labelled the real messages
- the separate agent that wrote the synthetic set

## dangerous

The message is a scam, phishing or fraud attempt. Through deception, impersonation, false urgency, or a malicious or look-alike link, it tries to get the recipient to do one of these:
- send money, gift cards or crypto
- reveal passwords, one-time codes, card details or identity data
- install remote-access software
- pay a fee for a prize, job, loan, parcel or refund

This includes:
- advance-fee ("419") fraud
- fake prizes and lotteries
- fake bank, government or courier notices with links
- credential phishing
- investment schemes promising guaranteed or extraordinary returns
- sextortion and blackmail
- fake invoices
- requests to pay a "new" account under pressure or secrecy
- messages that instruct an AI assistant to approve a payment

## suspicious

The message is not clearly fraudulent, but it contains a request or signal that should be **verified through a trusted channel before acting**. For example:
- a known supplier or colleague announces changed bank details, with no other red flags
- an unexpected payment request from someone the recipient knows, through an unusual channel
- an unknown sender asks to continue the conversation on WhatsApp or Telegram
- an unsolicited offer of a loan, job, investment, medication or goods from an unknown sender, with a link but no explicit deception
- pressure to pay quickly, without other signs of fraud
- a link whose domain does not match the claimed sender

## safe

No meaningful risk if the recipient acts as a normal person would. For example:
- personal conversation
- genuine notifications: one-time codes that say "do not share", delivery updates without a payment request, bank alerts that point to the official app
- invoices to an account already on file
- newsletters

**Ordinary commercial spam is "safe" in this rubric**, as long as it asks for nothing beyond a normal purchase. If it uses deception or impersonation, or asks for money or credentials outside a normal purchase, it is "suspicious" or "dangerous".

## Rules of thumb

- Following the message could plausibly cause financial or credential loss: **dangerous**.
- You would tell a careful person "check this first through a channel you trust": **suspicious**.
- Otherwise: **safe**.
- Judge only what is shown: the text, and the sender, payment details and links if they are given. Do not assume facts that are not in the message.
- When torn between two labels, pick the one a cautious fraud analyst would pick, and mark the confidence "low".

## Output fields used by the labellers

- `label`: `dangerous`, `suspicious` or `safe`
- `confidence`: `high` or `low`
- `reason`: one category, with no quotes from the message. One of:
  - `prize`, `phishing_link`, `advance_fee`, `investment`, `impersonation`, `payment_change`
  - `loan`, `job`, `goods_or_pharma`, `gambling`, `extortion`
  - `marketing`, `personal`, `notification`, `other`
