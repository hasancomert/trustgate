"""Rule engine: deterministic, explainable signals with character spans."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import unquote_plus

from trustgate.rules import lexicons as lx
from trustgate.rules.link_analysis import LinkContext, analyze_links, extract_urls, lookalike_issues, parse_url, registered_domain, skeleton
from trustgate.rules.text_rules import AGENT_RULE_ID, TEXT_RULES as _BASE_TEXT_RULES
from trustgate.rules.text_rules_tr import with_turkish
from trustgate.schemas import LinkFinding, RedFlag, ScamType, SenderInfo, Severity, VerificationRequest

TEXT_RULES = with_turkish(_BASE_TEXT_RULES)
_AGENT_RULE = next(r for r in TEXT_RULES if r.rule_id == AGENT_RULE_ID)

MAX_HITS_PER_RULE = 3
# Brand names in the opening characters read as "who is writing"; later mentions are just content.
BRAND_CLAIM_WINDOW = 160

_ZERO_WIDTH = {"​", "‌", "‍", "⁠", "﻿", "­", "᠎"}
_QUOTES = {"‘": "'", "’": "'", "‛": "'", "′": "'", "“": '"', "”": '"'}
_CRYPTO_WALLET = re.compile(r"^(bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})$")
_WORD = re.compile(r"[^\W_]+", re.UNICODE)


@dataclass(frozen=True)
class NormalizedText:
    text: str
    index_map: tuple[int, ...]  # normalized index -> original index
    hidden_chars: int

    def span(self, start: int, end: int) -> tuple[int, int]:
        return self.index_map[start], self.index_map[end - 1] + 1


def normalize(message: str) -> NormalizedText:
    """NFKC + straight quotes + zero-width removal + Turkish letter folding.

    Every output character maps back to an original index, so red-flag spans
    always point at the text the user typed.
    """
    out: list[str] = []
    index_map: list[int] = []
    hidden = 0
    for i, ch in enumerate(message):
        if ch in _ZERO_WIDTH:
            hidden += 1
            continue
        norm = lx.fold_turkish(_QUOTES.get(ch) or unicodedata.normalize("NFKC", ch))
        for n in norm:
            out.append(n)
            index_map.append(i)
    return NormalizedText("".join(out), tuple(index_map), hidden)


@dataclass(frozen=True)
class Combo:
    rule_id: str
    title: str
    explanation: str
    required: frozenset[str]
    supporting: frozenset[str]


_LINK_BAD = frozenset({"link_lookalike", "link_obfuscation", "link_mismatch"})
COMBOS: tuple[Combo, ...] = (
    Combo("combo.gift_card_pressure", "Gift cards requested under pressure",
          "Gift-card payment combined with urgency, secrecy or an authority claim is almost always a scam.",
          frozenset({"gift_card"}), frozenset({"urgency", "secrecy", "money_request", "authority", "channel_avoidance", "new_contact"})),
    Combo("combo.payment_redirect_pressure", "New bank details plus pressure",
          "Changed payment details combined with authority, urgency or secrecy is the signature of invoice / CEO fraud.",
          frozenset({"payment_change", "payee_mismatch"}), frozenset({"authority", "urgency", "secrecy", "channel_avoidance"})),
    Combo("combo.new_number_money", "Unknown number asking for money",
          "Someone 'on a new number' asking for money is the 'Hi Mum' impersonation script.",
          frozenset({"new_contact"}), frozenset({"money_request", "fee_request", "gift_card", "crypto", "payment_change"})),
    Combo("combo.credentials_via_link", "Credential request with a disguised link",
          "A request to log in or confirm details through a link that is not the real site is phishing.",
          frozenset({"credential_request"}), _LINK_BAD | frozenset({"sender_spoof"})),
    Combo("combo.remote_access_authority", "Remote access requested by an 'official'",
          "Installing remote-access software for someone claiming authority hands them your accounts.",
          frozenset({"remote_access"}), frozenset({"authority", "safe_account", "money_request", "credential_request", "threat"})),
    Combo("combo.crypto_returns", "Crypto payment with promised returns",
          "Crypto deposits tied to guaranteed returns, prizes or task 'jobs' are investment-scam mechanics.",
          frozenset({"crypto"}), frozenset({"investment_promise", "prize", "job_offer"})),
    Combo("combo.fee_with_bad_link", "Fee demand through a suspicious link",
          "A 'small fee' paid through an unofficial link is how fake delivery and refund scams steal cards.",
          frozenset({"fee_request"}), _LINK_BAD | frozenset({"link_hygiene"})),
    Combo("combo.threat_with_bad_link", "Threat plus disguised link",
          "Threatening consequences and pushing you to a look-alike site is a phishing combination.",
          frozenset({"threat"}), _LINK_BAD),
    Combo("combo.advance_fee", "Pay a fee to unlock money or work",
          "Paying a deposit or fee to release a prize, refund, profit or job is advance-fee fraud.",
          frozenset({"fee_request"}), frozenset({"job_offer", "prize", "investment_promise", "overpayment"})),
    Combo("combo.cash_pickup_pressure", "Courier pickup with pressure",
          "A stranger collecting cash or cards under urgency or secrecy is courier fraud.",
          frozenset({"cash_pickup"}), frozenset({"urgency", "secrecy", "money_request", "authority", "threat", "overpayment"})),
    Combo("combo.agent_payment", "AI-agent instructions next to a payment request",
          "The message tries to steer an automated assistant while asking for money.",
          frozenset({"agent_manipulation"}), frozenset({"money_request", "payment_change", "gift_card", "crypto", "fee_request", "payee_mismatch"})),
)

# Weighted keyword hints used to guess the scam family. The LLM layer may refine it.
_TYPE_KEYWORDS: tuple[tuple[ScamType, re.Pattern[str], float], ...] = tuple(
    (t, re.compile(p, re.IGNORECASE), w)
    for t, p, w in (
        (ScamType.FAMILY_IMPERSONATION, r"\b(mum|mom|mummy|mommy|dad|daddy|grandma|grandpa|nan|nana|granny|auntie|aunt|son|daughter|sis|bro)\b", 2.0),
        (ScamType.CEO_INVOICE_FRAUD, r"\b(invoice|supplier|vendor|remittance|purchase order|accounts payable|acquisition|wire)\b", 1.5),
        (ScamType.CEO_INVOICE_FRAUD, r"\b(ceo|cfo|managing director|director|boss)\b", 1.5),
        (ScamType.FAKE_DELIVERY, r"\b(parcel|package|delivery|courier|shipment|redeliver\w*|tracking|postage|shipping)\b", 2.0),
        (ScamType.BANK_IMPERSONATION, r"\b(bank|banking|debit card|credit card)\b", 1.0),
        (ScamType.BANK_IMPERSONATION, r"\b(suspicious|unusual|unauthori[sz]ed|fraudulent) (activity|transaction|payment|login|sign-?in|charge)s?\b", 2.0),
        (ScamType.INVESTMENT_SCAM, r"\b(invest\w*|trading|returns?|profits?|portfolio|forex|stocks?|mentor|signals?)\b", 1.5),
        (ScamType.TECH_SUPPORT, r"\b(virus|malware|infected|hacked|tech(nical)? support|microsoft support|refund for (your )?subscription)\b", 2.0),
        (ScamType.ACCOUNT_PHISHING, r"\b(password|log[- ]?in|sign[- ]?in|verify your account|secure your account|mailbox|storage (is )?full|sim|esim)\b", 1.0),
        (ScamType.GOVERNMENT_IMPERSONATION, r"\b(tax|hmrc|irs|government|council|tolls?|court|police|dmv|social security|pension|customs office|revenue office|parking (fine|charge))\b", 1.5),
        (ScamType.PRIZE_LOTTERY, r"\b(winner|won|prize|congratulations|lottery|sweepstakes)\b", 1.5),
        (ScamType.ROMANCE_SCAM, r"\b(my love|darling|sweetheart|babe|soulmate|dear)\b", 2.0),
        (ScamType.ROMANCE_SCAM, r"\b(i trust you|our talk|thinking about you|my uncle)\b", 1.0),
        (ScamType.ROMANCE_SCAM, r"\b(visa fee|flight ticket|plane ticket|hospital bill|stuck abroad)\b", 1.0),
        (ScamType.JOB_SCAM, r"\b(job|position|salary|recruit\w*|hiring|commission)\b", 1.0),
        (ScamType.MARKETPLACE_SCAM, r"\b(overpaid|overpayment|refund the (difference|extra)|courier (will|to) (collect|pick up)|buyer|your listing|item you('re| are) selling)\b", 2.0),
        # Turkish (matched on folded text)
        (ScamType.FAMILY_IMPERSONATION, r"\b(anne\w*|baba\w*|abla\w*|abi\w*|kardes\w*|oglum|kizim|teyze\w*|dayi\w*|amca\w*|hala\w*|nine\w*|nene\w*|dede\w*)\b", 2.0),
        (ScamType.FAKE_DELIVERY, r"\b(kargo\w*|paket\w*|gonderi\w*|teslimat\w*|gumruk\w*|ptt)\b", 2.0),
        (ScamType.BANK_IMPERSONATION, r"\b(banka\w*|kredi kart\w*|banka kart\w*|supheli islem\w*|izinsiz islem\w*)\b", 1.5),
        (ScamType.BANK_IMPERSONATION, r"\b(kartiniz\w*|subeye|subenize|guvenlik birim\w*|musteri temsilci\w*)\b", 1.0),
        (ScamType.GOVERNMENT_IMPERSONATION, r"\b(e-?devlet|vergi\w*|maliye|sgk|trafik ceza\w*|hgs|ogs|mahkeme\w*|savcilik\w*|emniyet\w*|icra\w*|tapu)\b", 1.5),
        (ScamType.GOVERNMENT_IMPERSONATION, r"\b(komiser\w*|polis\w*|jandarma\w*|sorusturma\w*|yakalama karari|vergi iade\w*|iadeniz)\b", 1.5),
        (ScamType.INVESTMENT_SCAM, r"\b(yatirim\w*|borsa\w*|kripto\w*|forex|getiri\w*|kazanc\w*|kar payi)\b", 1.5),
        (ScamType.PRIZE_LOTTERY, r"\b(cekilis\w*|odul\w*|ikramiye\w*|kazandiniz|talihli\w*)\b", 1.5),
        (ScamType.ROMANCE_SCAM, r"\b(canim|askim|sevgilim|bebegim|hayatim)\b", 2.0),
        (ScamType.JOB_SCAM, r"\b(is ilan\w*|is firsati|evden calis\w*|gorev\w*|komisyon\w*|maas\w*)\b", 1.0),
        (ScamType.MARKETPLACE_SCAM, r"\b(ilan\w*|alici\w*|satici\w*)\b", 1.5),
        (ScamType.MARKETPLACE_SCAM, r"\b(kapora\w*|kaparo\w*)\b", 2.0),
        (ScamType.ACCOUNT_PHISHING, r"\b(sifre\w*|giris yap\w*|oturum\w*)\b", 1.0),
        (ScamType.TECH_SUPPORT, r"\b(virus\w*|hacklen\w*|ele gecir\w*|teknik destek)\b", 2.0),
    )
)

# Category -> (scam type, weight) boosts.
_TYPE_CATEGORY_BOOSTS: dict[str, tuple[tuple[ScamType, float], ...]] = {
    "new_contact": ((ScamType.FAMILY_IMPERSONATION, 3.0),),
    "payment_change": ((ScamType.CEO_INVOICE_FRAUD, 3.0),),
    "payee_mismatch": ((ScamType.CEO_INVOICE_FRAUD, 1.5),),
    "channel_avoidance": ((ScamType.CEO_INVOICE_FRAUD, 1.0), (ScamType.FAMILY_IMPERSONATION, 1.0)),
    "fee_request": ((ScamType.FAKE_DELIVERY, 2.0),),
    "overpayment": ((ScamType.MARKETPLACE_SCAM, 4.0),),
    "cash_pickup": ((ScamType.FAMILY_IMPERSONATION, 1.0), (ScamType.MARKETPLACE_SCAM, 0.5)),
    "safe_account": ((ScamType.BANK_IMPERSONATION, 4.0),),
    "remote_access": ((ScamType.TECH_SUPPORT, 3.0),),
    "credential_request": ((ScamType.ACCOUNT_PHISHING, 2.0),),
    "link_lookalike": ((ScamType.ACCOUNT_PHISHING, 1.0),),
    "investment_promise": ((ScamType.INVESTMENT_SCAM, 3.0),),
    "crypto": ((ScamType.INVESTMENT_SCAM, 1.5),),
    "prize": ((ScamType.PRIZE_LOTTERY, 3.0),),
    "job_offer": ((ScamType.JOB_SCAM, 4.0),),
    "threat": ((ScamType.GOVERNMENT_IMPERSONATION, 0.5), (ScamType.BANK_IMPERSONATION, 0.5)),
}
MIN_TYPE_SCORE = 2.5


@dataclass
class RuleResult:
    score: float
    floor: int | None
    red_flags: list[RedFlag]
    link_findings: list[LinkFinding]
    category_severity: dict[str, Severity]
    scam_type_scores: dict[ScamType, float] = field(default_factory=dict)

    @property
    def top_scam_type(self) -> ScamType | None:
        if not self.scam_type_scores:
            return None
        best, value = max(self.scam_type_scores.items(), key=lambda kv: kv[1])
        return best if value >= MIN_TYPE_SCORE else None

    @property
    def has_critical(self) -> bool:
        return any(f.severity is Severity.CRITICAL for f in self.red_flags)


class RuleEngine:
    def __init__(self, severity_points: dict[str, float], floor_critical_flag: int, floor_critical_combo: int, max_urls: int = 20, floor_high_flag: int = 0):
        self.severity_points = severity_points
        self.floor_high_flag = floor_high_flag
        self.floor_critical_flag = floor_critical_flag
        self.floor_critical_combo = floor_critical_combo
        self.max_urls = max_urls

    # ------------------------------------------------------------------ public

    def analyze(self, request: VerificationRequest) -> RuleResult:
        norm = normalize(request.message)
        flags = self._text_flags(request.message, norm)
        if norm.hidden_chars:
            flags.append(RedFlag(
                rule_id="text.hidden_characters", category="obfuscation", severity=Severity.MEDIUM,
                title="Hidden characters in the text",
                explanation=f"The message contains {norm.hidden_chars} invisible character(s), a trick used to slip past filters.",
            ))

        mentioned = _mentioned_brands(norm.text[:BRAND_CLAIM_WINDOW])
        sender_flags, ctx = _sender_analysis(request.sender, mentioned)
        flags += sender_flags
        flags += _payment_flags(request, ctx)
        flags += _field_injection_flags(request)

        links, link_flags = analyze_links(request.message, request.urls, ctx, max_urls=self.max_urls)
        flags += link_flags

        category_severity = _category_severity(flags)
        combos = _combo_flags(category_severity)
        flags += combos
        category_severity = _category_severity(flags)

        score = self._score(category_severity)
        floor = None
        if combos:
            floor = self.floor_critical_combo
        elif any(f.severity is Severity.CRITICAL for f in flags):
            floor = self.floor_critical_flag
        elif self.floor_high_flag and any(f.severity is Severity.HIGH for f in flags):
            floor = self.floor_high_flag

        return RuleResult(
            score=score,
            floor=floor,
            red_flags=_sort_flags(flags),
            link_findings=links,
            category_severity=category_severity,
            scam_type_scores=_scam_type_scores(norm.text, category_severity),
        )

    # ------------------------------------------------------------------ internals

    def _score(self, category_severity: dict[str, Severity]) -> float:
        remaining = 1.0
        for severity in category_severity.values():
            points = min(float(self.severity_points.get(severity.value, 0.0)), 95.0)
            remaining *= 1.0 - points / 100.0
        return round(100.0 * (1.0 - remaining), 1)

    def _text_flags(self, original: str, norm: NormalizedText) -> list[RedFlag]:
        flags: list[RedFlag] = []
        text = norm.text
        for rule in TEXT_RULES:
            hits: list[tuple[int, int, Severity]] = []
            for pattern in sorted(rule.patterns, key=lambda p: -p.severity.rank):
                for m in pattern.regex.finditer(text):
                    if m.end() == m.start():
                        continue
                    if pattern.unless_before and pattern.unless_before.search(text[max(0, m.start() - 60):m.start()]):
                        continue
                    if pattern.unless_after:
                        after = re.split(r"[.!?\n]", text[m.end():m.end() + 80], maxsplit=1)[0]
                        if pattern.unless_after.search(after):
                            continue
                    if any(m.start() < e and s < m.end() for s, e, _ in hits):
                        continue
                    hits.append((m.start(), m.end(), pattern.severity))
            hits.sort(key=lambda h: (-h[2].rank, h[0]))
            for start, end, severity in hits[:MAX_HITS_PER_RULE]:
                o_start, o_end = norm.span(start, end)
                flags.append(RedFlag(
                    rule_id=rule.rule_id, category=rule.category, severity=severity,
                    title=rule.title, explanation=rule.explanation,
                    evidence=original[o_start:o_end], start=o_start, end=o_end, source="rules",
                ))
        return flags


# ---------------------------------------------------------------------- helpers


def _sort_flags(flags: list[RedFlag]) -> list[RedFlag]:
    return sorted(flags, key=lambda f: (-f.severity.rank, f.start if f.start is not None else 10**9))


def _category_severity(flags: list[RedFlag]) -> dict[str, Severity]:
    result: dict[str, Severity] = {}
    for f in flags:
        current = result.get(f.category)
        if current is None or f.severity.rank > current.rank:
            result[f.category] = f.severity
    return result


def _combo_flags(category_severity: dict[str, Severity]) -> list[RedFlag]:
    present = {c for c, s in category_severity.items() if s.rank >= Severity.MEDIUM.rank}
    flags = []
    for combo in COMBOS:
        if present & combo.required and present & combo.supporting:
            flags.append(RedFlag(
                rule_id=combo.rule_id, category="combination", severity=Severity.CRITICAL,
                title=combo.title, explanation=combo.explanation, source="rules",
            ))
    return flags


def _scam_type_scores(text: str, category_severity: dict[str, Severity]) -> dict[ScamType, float]:
    scores: dict[ScamType, float] = {}
    for scam_type, pattern, weight in _TYPE_KEYWORDS:
        if pattern.search(text):
            scores[scam_type] = scores.get(scam_type, 0.0) + weight
    for category in category_severity:
        for scam_type, weight in _TYPE_CATEGORY_BOOSTS.get(category, ()):
            scores[scam_type] = scores.get(scam_type, 0.0) + weight
    return {k: round(v, 2) for k, v in sorted(scores.items(), key=lambda kv: -kv[1])}


def _brand_pattern(mention: str) -> re.Pattern[str]:
    # Short acronyms (UPS, DHL, IRS) are matched case-sensitively to avoid "ups and downs".
    if len(mention) <= 4:
        return re.compile(rf"\b{re.escape(mention.upper())}\b")
    return re.compile(rf"\b{re.escape(mention)}\b", re.IGNORECASE)


_BRAND_MENTIONS: tuple[tuple[lx.Brand, tuple[re.Pattern[str], ...]], ...] = tuple(
    (b, tuple(_brand_pattern(m) for m in b.mentions)) for b in lx.BRANDS
)


def _mentioned_brands(text: str) -> tuple[lx.Brand, ...]:
    return tuple(b for b, patterns in _BRAND_MENTIONS if any(p.search(text) for p in patterns))


def _words(name: str) -> list[str]:
    # Fold before lower(): "İ".lower() would add a combining dot.
    return [t.lower() for t in _WORD.findall(lx.fold_turkish(name))]


def _org_tokens(name: str | None) -> frozenset[str]:
    if not name:
        return frozenset()
    return frozenset(w for w in _words(name) if len(w) >= 3 and w not in lx.GENERIC_ORG_WORDS)


def _looks_like_org(name: str | None) -> bool:
    if not name:
        return False
    words = set(_words(name))
    return bool(words & lx.GENERIC_ORG_WORDS - {"the", "of", "and", "no", "co", "us", "uk"})


def _sender_analysis(sender: SenderInfo | None, mentioned: tuple[lx.Brand, ...]) -> tuple[list[RedFlag], LinkContext]:
    if sender is None:
        return [], LinkContext(mentioned_brands=mentioned)

    claim_text = " ".join(x for x in (sender.claimed_organization, sender.display_name) if x)
    claimed_brands = _mentioned_brands(claim_text) if claim_text else ()
    org_like = bool(sender.claimed_organization) or _looks_like_org(sender.display_name) or bool(claimed_brands)
    tokens = _org_tokens(sender.claimed_organization)
    if not tokens and _looks_like_org(sender.display_name):
        tokens = _org_tokens(sender.display_name)

    sender_domain = None
    flags: list[RedFlag] = []
    address = (sender.address or "").strip().lower()
    if "@" in address:
        domain = address.rsplit("@", 1)[1].strip(">").strip()
        parsed = parse_url(domain)
        if parsed is not None:
            sender_domain = parsed.registered_domain
            for issue in lookalike_issues(parsed):
                if issue.severity.rank >= Severity.HIGH.rank:
                    flags.append(RedFlag(
                        rule_id="sender.lookalike_domain", category="sender_spoof", severity=issue.severity,
                        title=f"Sender address imitates {issue.brand}",
                        explanation=f"The email comes from {sender_domain}, which is made to resemble {issue.brand}. {issue.explanation}",
                        evidence=sender.address, source="sender",
                    ))
                    break

        if sender_domain in lx.FREE_EMAIL_DOMAINS and org_like:
            who = sender.claimed_organization or sender.display_name or "an organization"
            flags.append(RedFlag(
                rule_id="sender.free_email_for_org", category="sender_spoof", severity=Severity.HIGH,
                title="Organization writing from a free email account",
                explanation=f"'{who}' is writing from a personal {sender_domain} address; real companies use their own domain.",
                evidence=sender.address, source="sender",
            ))
        elif sender_domain and not flags:
            for brand in claimed_brands:
                if not brand.owns(sender_domain):
                    flags.append(RedFlag(
                        rule_id="sender.brand_domain_mismatch", category="sender_spoof", severity=Severity.HIGH,
                        title=f"Claims to be {brand.name} but uses another domain",
                        explanation=f"{brand.name} sends email from {', '.join(brand.domains[:2])}, not {sender_domain}.",
                        evidence=sender.address, source="sender",
                    ))
                    break
            else:
                if tokens and sender_domain not in lx.FREE_EMAIL_DOMAINS and not any(skeleton(t) in skeleton(sender_domain) for t in tokens):
                    flags.append(RedFlag(
                        rule_id="sender.org_domain_mismatch", category="sender_spoof", severity=Severity.MEDIUM,
                        title="Sender domain doesn't match the claimed organization",
                        explanation=f"The sender presents as '{' '.join(sorted(tokens))}' but writes from {sender_domain}.",
                        evidence=sender.address, source="sender",
                    ))

    ctx = LinkContext(
        sender_domain=sender_domain,
        claimed_tokens=tokens if org_like else frozenset(),
        claimed_brands=claimed_brands,
        mentioned_brands=mentioned,
    )
    return flags, ctx


_URL_SEPARATORS = re.compile(r"[/_\-+.=&?#:~]+")


def _field_injection_flags(request: VerificationRequest) -> list[RedFlag]:
    """Instructions for AI systems hidden outside the message body: names, accounts, link paths."""
    fields: list[tuple[str, str, str | None]] = []
    if request.sender:
        fields += [("sender", "sender name", request.sender.display_name), ("sender", "claimed organization", request.sender.claimed_organization)]
    if request.payment:
        fields += [("payment", "payee name", request.payment.payee_name), ("payment", "payee account", request.payment.payee_account)]
    fields += [("links", "link", url) for url in [u.raw for u in extract_urls(request.message)] + list(request.urls)]

    patterns = sorted(_AGENT_RULE.patterns, key=lambda p: -p.severity.rank)
    flags: list[RedFlag] = []
    for source, label, value in fields:
        if not value:
            continue
        text = _URL_SEPARATORS.sub(" ", unquote_plus(value)) if source == "links" else value
        hit = next((p for p in patterns if p.regex.search(normalize(text).text)), None)
        if hit:
            flags.append(RedFlag(
                rule_id=_AGENT_RULE.rule_id, category=_AGENT_RULE.category, severity=hit.severity,
                title=_AGENT_RULE.title,
                explanation=f"The {label} carries instructions aimed at an AI assistant. Legitimate senders never do this.",
                evidence=value[:160], source=source,
            ))
    return flags


# A "large" first payment, in units of the payment currency; 1000 for currencies close to USD/EUR/GBP.
_LARGE_AMOUNT = {"TRY": 40_000, "JPY": 150_000, "INR": 85_000}


def _payment_flags(request: VerificationRequest, ctx: LinkContext) -> list[RedFlag]:
    payment = request.payment
    if payment is None:
        return []
    flags: list[RedFlag] = []

    if payment.method == "gift_card":
        flags.append(RedFlag(
            rule_id="payment.gift_card", category="gift_card", severity=Severity.CRITICAL,
            title="Payment in gift cards",
            explanation="No legitimate business or authority takes payment in gift cards.",
            source="payment",
        ))
    if payment.method == "crypto" or (payment.payee_account and _CRYPTO_WALLET.match(payment.payee_account.strip())):
        flags.append(RedFlag(
            rule_id="payment.crypto", category="crypto", severity=Severity.HIGH,
            title="Payment to a crypto wallet",
            explanation="Crypto payments cannot be reversed if this turns out to be fraud.",
            evidence=payment.payee_account, source="payment",
        ))

    if payment.new_payee:
        large = payment.amount is not None and payment.amount >= _LARGE_AMOUNT.get((payment.currency or "").upper(), 1000)
        flags.append(RedFlag(
            rule_id="payment.new_payee", category="new_payee", severity=Severity.MEDIUM if large else Severity.LOW,
            title="First payment to this recipient" + (" (large amount)" if large else ""),
            explanation="You have not paid this recipient before; confirm their details through a channel you already trust.",
            evidence=payment.payee_name, source="payment",
        ))

    if payment.payee_name:
        claimed = (request.sender.claimed_organization if request.sender else None) or (ctx.claimed_brands[0].name if ctx.claimed_brands else None)
        claim_tokens = _org_tokens(claimed)
        payee_tokens = {skeleton(t) for t in _org_tokens(payment.payee_name)} | {skeleton(t.lower()) for t in _WORD.findall(payment.payee_name)}
        if claim_tokens and not any(skeleton(t) in payee_tokens for t in claim_tokens):
            flags.append(RedFlag(
                rule_id="payment.payee_mismatch", category="payee_mismatch", severity=Severity.HIGH,
                title="Money goes to someone other than the claimed sender",
                explanation=f"The request claims to come from '{claimed}', but the payee is '{payment.payee_name}'.",
                evidence=payment.payee_name, source="payment",
            ))
    return flags


def build_engine(settings: Settings) -> RuleEngine:
    return RuleEngine(
        severity_points=settings.rules.severity_points,
        floor_critical_flag=settings.rules.floors.critical_flag,
        floor_critical_combo=settings.rules.floors.critical_combo,
        max_urls=settings.limits.max_urls,
        floor_high_flag=settings.rules.floors.high_flag,
    )


__all__ = ["RuleEngine", "RuleResult", "build_engine", "normalize"]
