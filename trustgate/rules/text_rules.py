"""Manipulation-tactic patterns for message text.

Patterns run on a normalized copy of the message (NFKC, straight quotes,
zero-width characters removed) and are matched case-insensitively. Each rule
targets a *tactic* (pressure, secrecy, payment redirection...) rather than a
writing style: we do not try to guess whether a human or an AI wrote the text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from trustgate.schemas import Severity

# A negation earlier in the same clause, e.g. "we will NEVER ask you to share your PIN".
_NEGATED = re.compile(r"\b(never|not|no one|nobody|don't|dont|do not|won't|will not|cannot|can't)\b[^.!?\n,;]{0,30}$", re.IGNORECASE)
# Protective advice about credentials, e.g. "do not tell anyone your PIN".
_PROTECTIVE = re.compile(r"\b(pin|password|passcode|code|otp|security details|card details)\b", re.IGNORECASE)

_MONEY = r"(?:[$€£₺]\s?\d[\d,.]*k?|\d[\d,.]*\s?(?:usd|eur|gbp|try|tl|dollars?|euros?|pounds?|lira|bucks|quid))"
_CRYPTO = r"(?:bitcoin|btc|ethereum|eth|usdt|tether|crypto(?:currency|currencies)?|stablecoins?)"


@dataclass(frozen=True)
class Pattern:
    regex: re.Pattern[str]
    severity: Severity
    # If this matches the text *before* the hit (same clause), the hit is ignored.
    unless_before: re.Pattern[str] | None = None
    # If this matches the text *after* the hit (same clause), the hit is ignored.
    unless_after: re.Pattern[str] | None = None


@dataclass(frozen=True)
class TextRule:
    rule_id: str
    category: str
    title: str
    explanation: str
    patterns: tuple[Pattern, ...]


def _p(regex: str, severity: Severity, unless_before: re.Pattern[str] | None = None, unless_after: re.Pattern[str] | None = None) -> Pattern:
    return Pattern(re.compile(regex, re.IGNORECASE), severity, unless_before, unless_after)


L, M, H, C = Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL

TEXT_RULES: tuple[TextRule, ...] = (
    TextRule(
        "text.urgency", "urgency", "Artificial urgency",
        "Pressure to act immediately leaves no time to check whether the request is real.",
        (
            _p(r"\burgent(ly)?\b", M),
            _p(r"\b(immediately|right away|right now|asap|as soon as possible)\b", M),
            _p(r"\bwithin (the next )?\d+\s*(hours?|hrs?|minutes?|mins?)\b", M),
            _p(r"\b(today|tonight) only\b", M),
            _p(r"\bbefore (midnight|end of (the )?(day|business)|it's too late|\d{1,2}(:\d\d)?\s*(am|pm))\b", M),
            _p(r"\b(final|last) (notice|warning|reminder|chance|attempt)\b", M),
            _p(r"\bact (now|fast|quickly)\b", M),
            _p(r"\b(expires?|expiring|will expire|will be cancelled) (today|tonight|soon|in \d+)\b", M),
            _p(r"\btime[- ]sensitive\b", M),
            _p(r"\b(don't delay|hurry|no time to explain)\b", M),
            _p(r"\bquick(ly)? favou?r\b", M),
            _p(r"\b(pay|transfer|send|wire|settle|process)\b[^.!?\n]{0,40}\b(today|tonight|now)\b", M),
        ),
    ),
    TextRule(
        "text.threat", "threat", "Threat or penalty",
        "Scammers threaten account closure, fines or legal trouble to make you panic.",
        (
            _p(r"\b(account|card|access|service|profile|subscription)\b[^.!?\n]{0,30}\b(will be|has been|is being|is now|have been)\s+(temporarily\s+|permanently\s+)?(suspended|locked|blocked|frozen|closed|deactivated|restricted|terminated|disabled|limited)\b", H),
            _p(r"\b(or|otherwise)\s+(it|they|your \w+)\s+will be\s+(permanently\s+)?(suspended|locked|blocked|frozen|closed|deactivated|deleted|cancelled|terminated)\b", H),
            _p(r"\b(you|your)\b[^.!?\n]{0,40}\b(legal action|lawsuit|arrest(ed)?|warrant|prosecut\w+|court (case|summons|order)|deport\w*|bailiffs?)\b", H),
            _p(r"\b(legal action|lawsuit|warrant|prosecution|court (case|summons|order)|bailiffs?)\b[^.!?\n]{0,30}\b(against you|in your name|for your arrest|at your (home|address))\b", H),
            _p(r"\b(warrant|summons)\b[^.!?\n]{0,30}\b(has been|will be|was)\s+(issued|filed)\b", H),
            _p(r"\b(you will|you'll) (lose|be charged|be fined|be penali[sz]ed|be reported)\b", H),
            _p(r"\bfailure to (respond|comply|pay|verify|act)\b", H),
            _p(r"\b(fine|penalty|surcharge) of\b", M),
            _p(r"\b(late|additional|extra)\s+(penalty|fees?|fines?|charges?)\b", M),
            _p(r"\bfurther (legal )?action\b", M),
        ),
    ),
    TextRule(
        "text.authority", "authority", "Claims authority",
        "The message leans on a bank, executive or official body to discourage questions.",
        (
            _p(r"\b(this is|we are|i am|i'm|calling from|message from|on behalf of)\s+(the\s+|your\s+)?(bank|fraud|security|tax|revenue|police|customs|government|ceo|cfo|director|managing director|head office|it department|tech(nical)? support|support team)\b", M),
            _p(r"\b(fraud|security|anti-?fraud|risk|compliance)\s+(team|department|unit|division|officer)\b", M),
            _p(r"\b(tax (office|authority|department)|revenue service|police department|customs (office|authority))\b", M),
            _p(r"\b(ceo|cfo|chief executive|managing director)\b", L),
        ),
    ),
    TextRule(
        "text.payment_change", "payment_change", "Changed payment details",
        "A request to pay a new or different account is the core move of invoice and CEO fraud.",
        (
            _p(r"\b(new|updated|changed|different|alternative|another)\s+(bank(ing)?|account|iban|payment|remittance|wire)\s+(details|information|info|account|number|instructions)\b", H),
            _p(r"\b(bank(ing)?|account|payment)\s+(details|information|account)\s+((have|has)\s+)?(changed|been (changed|updated)|are changing|will change)\b", H),
            _p(r"\b(to|into)\s+(the|our)\s+new\s+(bank\s+)?account\b", H),
            _p(r"\b(update|change)\s+(our|the)\s+(bank(ing)?|payment|remittance)\s+(details|information|account)\b", H),
            _p(r"\bdo not (use|pay (to|into)) (the|our) (old|previous|usual|existing) (account|details)\b", H),
            _p(r"\b(pay|transfer|send|wire)\b[^.!?\n]{0,40}\b(to|into) (this|the following|a new|our new) (account|iban)\b", H),
            _p(r"\b(account|bank) is (currently )?(under (audit|review)|being audited)\b", H),
        ),
    ),
    TextRule(
        "text.secrecy", "secrecy", "Asks for secrecy",
        "Being told not to tell anyone cuts you off from the people who would spot the scam.",
        (
            _p(r"\b(keep|treat)\s+(this|it|the matter|this request)\s+(strictly\s+)?(confidential|private|secret|quiet|between us|to yourself)\b", H),
            _p(r"\b(don't|dont|do not|please don't)\s+(tell|inform|mention (this|it) to|discuss (this|it) with|involve|call|contact)\b[^.!?\n]{0,30}\b(anyone|anybody|your bank|the bank|branch staff|family|dad|mum|mom|sister|brother|son|daughter|partner|friends?|colleagues|manager|accounts|treasury|police|husband|wife|others)\b", H, unless_after=_PROTECTIVE),
            _p(r"\b(no need to|don't|do not)\s+(loop in|involve|cc|copy in)\b", H),
            _p(r"\b(confidential|discreet|discretion)\b[^.!?\n]{0,40}\b(transaction|payment|deal|acquisition|matter|request|transfer|project)\b", H),
            _p(r"\b(this|the|your) (case|matter|investigation|transaction|request|operation) is (strictly |highly )?(confidential|secret|private|classified)\b", H),
            _p(r"\bbetween (you and me|us)\b", M),
        ),
    ),
    TextRule(
        "text.channel_avoidance", "channel_avoidance", "Avoids a real conversation",
        "Claiming they can't talk stops you from recognising the voice or confirming by phone.",
        (
            _p(r"\b(can't|cannot|unable to)\s+(talk|speak|call|answer|take calls|pick up)\b", M),
            _p(r"\b(i'm|i am)\s+(in|stuck in)\s+(a\s+)?(meeting|conference|board meeting)\b", M),
            _p(r"\b(only|just)\s+(text|message|whatsapp|email)\s+me\b", L),
            _p(r"\b(do not|don't)\s+(use|open|log into|call|visit|contact)\s+(the|your)\s+(banking\s+|mobile\s+)?(app|branch|website|bank)\b", H),
            _p(r"\b(unreachable|on a flight|about to board|boarding now)\b", M),
        ),
    ),
    TextRule(
        "text.new_contact", "new_contact", "Unknown number claims to be someone you know",
        "\"New number\" stories are how impersonators explain why you don't recognise them.",
        (
            _p(r"\b(this is|it's|here's)\s+my\s+new\s+(number|phone|mobile)\b", H),
            _p(r"\bnew (number|phone number|mobile number)\b", M),
            _p(r"\b(my\s+)?(phone|mobile)\s+(is|was|got)\s+(broken|broke|damaged|smashed|lost|stolen|dead)\b", H),
            _p(r"\b(broke|lost|dropped|smashed|cracked)\s+my\s+(phone|mobile)\b", H),
            _p(r"\bmy phone broke\b", H),
            _p(r"\b(save|update)\s+(this|my)\s+(new\s+)?number\b", M),
            _p(r"\b(temporary|borrowed|friend's) (number|phone)\b", M),
        ),
    ),
    TextRule(
        "text.money_request", "money_request", "Asks for money",
        "A direct request to send money from a message is the moment to stop and verify.",
        (
            _p(r"\b(send|transfer|wire|lend|loan|pay|give)\s+(me\s+|us\s+)?(some\s+)?(money|cash|funds)\b", M),
            _p(rf"\b(send|transfer|wire|lend|pay|cover)\b[^.!?\n]{{0,30}}?{_MONEY}", M),
            _p(rf"{_MONEY}[^.!?\n]{{0,30}}\b(to|into) (this|my|the following|a new) (account|iban)\b", M),
            _p(r"\bneed (some |a bit of )?(money|cash|help with (a|the) (bill|payment|rent))\b", M),
            _p(r"\bwithdraw\b[^.!?\n]{0,20}\b(cash|money|the money|savings)\b", M),
            _p(r"\b(bail|lawyer'?s? fees?|hospital (bill|fees?))\b", M),
        ),
    ),
    TextRule(
        "text.fee_request", "fee_request", "Small fee to release something",
        "Fake couriers, prizes and 'refunds' ask for a small fee to harvest card details.",
        (
            _p(r"\bpay\b[^.!?\n]{0,15}\b(small |customs |delivery |redelivery |re-delivery |shipping |release |processing |handling |admin |clearance |unpaid |outstanding )+(fee|charge|duty|postage)\b", H),
            _p(r"\b(processing|release|clearance|activation|unlock|withdrawal|redelivery|re-delivery|customs|shipping|handling) (fee|deposit|charge|payment)\b", M),
            _p(r"\b(unpaid|outstanding|overdue)\s+(\w+\s+)?(fee|charge|toll|fine|duty|balance)\b", M),
        ),
    ),
    TextRule(
        "text.cash_pickup", "cash_pickup", "Courier collecting cash or cards",
        "Sending a 'courier' to collect cash, cards or valuables from your door is a known fraud script.",
        (
            _p(r"\b(courier|driver|agent|officer|messenger|someone)\b[^.!?\n]{0,40}\b(collect|pick up|pick it up|come to your (house|home|door|address))\b", H),
        ),
    ),
    TextRule(
        "text.overpayment", "overpayment", "Overpayment and refund request",
        "A buyer who 'overpays' and asks you to refund the difference is running an overpayment scam.",
        (
            _p(r"\b(overpaid|overpayment|paid (you )?(too much|extra)|extra to cover)\b", H),
            _p(r"\brefund the (difference|extra|balance|excess)\b", H),
        ),
    ),
    TextRule(
        "text.gift_card", "gift_card", "Payment in gift cards",
        "No real bank, company or government accepts gift cards as payment. This is a classic scam signal.",
        (
            _p(r"\b(buy|purchase|get|pick up|grab)\b[^.!?\n]{0,40}\bgift\s*-?cards?\b", C),
            _p(r"\bpay\b[^.!?\n]{0,30}\b(with|in|using|via)\b[^.!?\n]{0,20}\bgift\s*-?cards?\b", C),
            _p(r"\b(scratch(ed)? off|photos? of|pictures? of|pics? of|snap)\b[^.!?\n]{0,30}\b(codes?|back of the cards?|cards?)\b", C),
            _p(r"\bgift\s*-?cards?\b", H),
            _p(r"\b(itunes|steam|google play|razer gold|vanilla|paysafe(card)?)\s+(gift\s+)?(cards?|vouchers?)\b", H),
        ),
    ),
    TextRule(
        "text.crypto", "crypto", "Cryptocurrency payment",
        "Crypto transfers are irreversible and anonymous, so scammers prefer them.",
        (
            _p(rf"\b(send|transfer|deposit|pay|buy|move)\b[^.!?\n]{{0,40}}\b{_CRYPTO}\b", H),
            _p(r"\b(bitcoin|crypto|btc) atm\b", C),
            _p(r"\bwallet address\b", H),
            _p(r"\b(bc1[a-z0-9]{25,60}|0x[a-f0-9]{40})\b", H),
            _p(rf"\b{_CRYPTO}\b", M),
        ),
    ),
    TextRule(
        "text.irreversible_payment", "irreversible_payment", "Hard-to-reverse payment method",
        "Wire services and peer-to-peer apps offer little or no buyer protection once money is sent.",
        (
            _p(r"\b(western union|moneygram|paysafecard)\b", H),
            _p(r"\b(money order|prepaid (card|voucher))\b", M),
            _p(r"\b(wire transfer|wire the (money|funds|payment))\b", M),
            _p(r"\b(zelle|cash ?app|venmo)\b", M),
        ),
    ),
    TextRule(
        "text.credential_request", "credential_request", "Asks for passwords or codes",
        "Banks and services never ask you to send passwords, PINs or one-time codes.",
        (
            _p(r"\b(enter|provide|send|share|give|tell|read|read out|confirm|forward|reply with|text back)\b[^.!?\n]{0,25}\b(password|passcode|pin|otp|one[- ]time (code|password|passcode)|verification code|security code|auth(entication)? code|2fa code|cvv|cvc|card number|full card details|login details|credentials|sms code|(the |your )?(\d-digit |\w+-digit )?code (we|you|i|that) (just |will )?(sent|send|received|got|text)( you)?)\b", C, unless_before=_NEGATED),
            _p(r"\b(verify|confirm|update|validate|re-?activate|unlock|restore|secure)\s+(your\s+)?(account|identity|details|information|card|payment (details|information|method)|login|billing( information)?)\b", H, unless_before=_NEGATED),
            _p(r"\b(log[- ]?in|sign[- ]?in)\s+(here|now|below|via the link|at the link|to (verify|confirm|restore|unlock))\b", M),
        ),
    ),
    TextRule(
        "text.link_call_to_action", "link_call_to_action", "Pushes you to click a link",
        "Pressure to click through instead of opening the official app or website yourself.",
        (
            _p(r"\b(click|tap|follow|open|use)\s+(here|the link|this link|the link below|below)\b", L),
        ),
    ),
    TextRule(
        "text.safe_account", "safe_account", "\"Safe account\" transfer",
        "Real banks never ask you to move your money to a 'safe' or 'holding' account.",
        (
            _p(r"\b(safe|secure|protected|holding)\s+(account|wallet)\b", C),
        ),
    ),
    TextRule(
        "text.remote_access", "remote_access", "Remote access or app install",
        "Remote-control apps let the caller see your screen and approve payments as you.",
        (
            _p(r"\b(anydesk|teamviewer|quick ?support|ultraviewer|rustdesk|logmein|screenconnect)\b", H),
            _p(r"\b(give|allow|grant|need|let)\b[^.!?\n]{0,25}\bremote (access|control|connection)\b", H),
            _p(r"\bremote (access|desktop|support|control)\b[^.!?\n]{0,20}\b(to )?your (computer|device|phone|pc|laptop|screen)\b", H),
            _p(r"\.apk\b|\bapk file\b", H),
            _p(r"\b(install|download)\b[^.!?\n]{0,30}\b(app|application|software)\b", M),
        ),
    ),
    TextRule(
        "text.investment_promise", "investment_promise", "Too-good-to-be-true returns",
        "Guaranteed or very high returns are the hook of investment and crypto scams.",
        (
            _p(r"\bguaranteed\s+(returns?|profits?|income|payouts?)\b", H),
            _p(r"\b(double|triple|10x|multiply)\s+your\s+(money|investment|capital|savings|crypto)\b", H),
            _p(r"\brisk[- ]free\b", M),
            _p(r"\b\d{1,3}(\.\d+)?\s?%\s+(daily|weekly|monthly|per (day|week|month)|a (day|week|month))\b", H),
            _p(r"\b(daily|weekly) (returns?|profits?|payouts?)\b", H),
            _p(r"\b(trading|investment) (platform|opportunity|group|mentor|signals?|bot)\b", M),
            _p(r"\bpassive income\b", L),
            _p(r"\b(made|earned|profited|got back)\s+[$€£]?\d[\d,.]*k?\b[^.!?\n]{0,25}\b(this|in a|in one|last)\s+(week|day|month)\b", M),
            _p(r"\b(capital|money|funds) (is |are )?(fully |100% )?(protected|guaranteed|insured)\b", H),
        ),
    ),
    TextRule(
        "text.prize", "prize", "Unexpected prize or refund",
        "Surprise winnings or refunds you never asked for are bait to collect fees or details.",
        (
            _p(r"\byou('ve| have)\s+(just\s+)?won\b", H),
            _p(r"\byou('ve| have)\s+been\s+(selected|chosen)\b[^.!?\n]{0,40}\b(prize|reward|winner|draw|lottery|gift|cash|bonus|voucher|giveaway)\b", H),
            _p(r"\b(claim|collect|redeem)\s+(your\s+)?(prize|reward|winnings|refund|bonus|gift)\b", H),
            _p(r"\b(lottery|sweepstakes|jackpot|prize draw)\b", M),
            _p(r"\bunclaimed\s+(funds|refund|prize|parcel|package|inheritance)\b", H),
            _p(r"\binheritance\b", M),
        ),
    ),
    TextRule(
        "text.job_offer", "job_offer", "Easy-money job offer",
        "Task-based 'jobs' that pay for likes or reviews end with you paying to withdraw.",
        (
            _p(r"\bearn\s+[$€£₺]?\s?\d[\d,.]*\s*(\+\s*)?(per|a|/)\s*(day|hour|week)\b", H),
            _p(r"\b(simple|easy) (online )?tasks?\b", M),
            _p(r"\b(like|liking|rate|rating|review|reviewing)\s+(videos|products|hotels|apps|movies)\b", M),
            _p(r"\b(work|job) from home\b", L),
        ),
    ),
    TextRule(
        "text.generic_greeting", "generic_greeting", "Generic greeting",
        "Organizations you have an account with usually address you by name.",
        (
            _p(r"\bdear\s+(customer|user|client|member|valued customer|account holder|sir|madam|sir/madam|beneficiary)\b", L),
        ),
    ),
    TextRule(
        "text.agent_manipulation", "agent_manipulation", "Instructions aimed at an AI assistant",
        "The text tries to instruct an AI assistant or automated checker. Legitimate messages never do this.",
        (
            _p(r"\bignore\s+(all\s+)?(previous|prior|above|earlier|your|any)\s+(instructions|rules|prompts?|guidelines|warnings)\b", C),
            _p(r"\b(ai|assistant|agent|bot|model|llm|chatgpt|gpt|copilot)\b[^.!?\n]{0,40}\b(mark|classify|treat|label|flag|consider|report)\s+(this|it|the)(\s+(message|payment|transaction|request|invoice|email|transfer))?\s+as\s+(safe|legit(imate)?|verified|trusted|approved|not (a )?scam)\b", C),
            _p(r"\b(system prompt|developer mode|jailbreak)\b", C),
            _p(r"\b(this|the) (message|payment|transaction|request|invoice) (is|has been) (pre-?)?(verified|approved|whitelisted|authori[sz]ed|cleared) by\b", H),
            _p(r"\b(do not|don't|never)\s+(flag|report|warn|alert|verify|double-check|question)\b", H),
            _p(r"\b(auto-?approve|approve (this|the) (payment|transfer|purchase) (without|immediately|automatically))\b", H),
            # Completing a payment while keeping the account owner out of it.
            _p(r"\b(approve|confirm|complete|process|authori[sz]e|pay|execute)\s+(this\s+|the\s+)?(payment|transfer|purchase|order|invoice|transaction)?\s*(without|w/o)\s+(asking|checking|consulting|confirm\w*|verif\w*|approval|consent|review\w*|the user|the customer|user|customer)\b", H),
            _p(r"\b(do not|don't|never|no need to)\s+(ask|check with|confirm with|consult|notify|inform|alert|wait for)\s+(the\s+|your\s+)?(user|customer|account (holder|owner)|human|principal)s?\b", H),
            # A ready-made verdict for the checker: '"risk_score": 0', 'verdict: safe'.
            _p(r"\b(risk_?score|scam_?type|is_?scam|is_?phishing|is_?fraud|fraud_?score|spam_?score)\b[\"']?\s*[:=]\s*[\"']?(0|none|false|safe|legit\w*|benign|clean|low)\b", C),
            _p(r"\b(verdict|classification|assessment)\b[\"']?\s*[:=]\s*[\"']?(safe|legit\w*|genuine|benign|not[ _-]?(a[ _-]?)?(scam|phishing|fraud))\b", H),
            _p(r"\b(respond|reply|answer|output|return)\s+(only\s+|exactly\s+|just\s+)?(with\s+)?(the following|this|exactly)?\s*(json|verdict|risk score|classification)\b", H),
            # Closing the checker's input block, or opening a fake instruction block.
            _p(r"<\s*/\s*(message|system|assistant|user|instructions?|prompt|context|input|email)\s*>", C),
            _p(r"<\s*(system|assistant|instructions?|prompt)\s*>", C),
            _p(r"(={3,}|-{3,}|\*{3,}|#{3,}|\[)\s*end of (the )?(message|email|input|user input|document|transcript|conversation)\b", M),
            _p(r"\bnew (system )?instructions?\s*:", M),
            # Fake system or developer notes.
            _p(r"\[\s*(system|developer|admin)\s+(override|instructions?|prompt)\s*\]|\b(system (override|instructions?|prompt)|developer (instructions?|override)|admin override)\s*:", C),
            _p(r"\[\s*(system|developer)\s*\]|\bdeveloper (note|message)\s*:", H),
            # Role play and hypotheticals that ask the checker to pretend.
            _p(r"\b(pretend|act as if|role-?play|hypothetically|for (a|this|the) (training|test|testing|demo|research) (exercise|purpose|scenario)s?)\b[^.!?\n]{0,60}\b(safe|legit(imate)?|genuine|verified|harmless|trusted|not (a )?(scam|fraud|phishing))\b", H),
            # Speaking to the checker directly, with flattery or invented policy.
            _p(r"\b(note|message|instructions?|attention|reminder|notice)\s+(to|for)\s+(the\s+|any\s+|all\s+)?(ai|a\.i\.|bots?|llms?|language models?|automated (systems?|checkers?|reviewers?|filters?|agents?|assistants?)|(shopping|payment|purchasing|virtual|digital) (assistants?|agents?))\b", H),
            _p(r"\bas an? (responsible|helpful|trustworthy|good|smart|advanced|honest|ethical|well-aligned)\s+(ai|ai assistant|assistant|language model|llm|chatbot)\b", H),
            _p(r"\b(flagging|blocking|reporting|warning about|questioning|delaying)\s+(this|it|verified|trusted|approved|partner)\w*\b[^.!?\n]{0,40}\b(violat\w*|against|breach\w*)\s+(your\s+|the\s+|our\s+)?(policy|policies|guidelines|terms|rules)\b", H),
            # Encoded payloads with an instruction to decode them.
            _p(r"\b(decode|base64)\b[\s\S]{0,80}?(?<![\w/.:-])[A-Za-z0-9+]{20,}={0,2}(?![\w/.])", H),
            # Addressing the checker by role, e.g. "automated reviewers: approve".
            _p(r"\b(automated|ai|a\.i\.)\s+(reviewers?|checkers?|systems?|assistants?|agents?|filters?|scanners?|moderators?)\s*:", H),
        ),
    ),
)

AGENT_RULE_ID = "text.agent_manipulation"
