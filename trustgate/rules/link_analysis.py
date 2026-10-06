"""Static link analysis.

Everything here works on the URL *string* only. Nothing is resolved, fetched,
redirected or contacted: no DNS, no HTTP, no WHOIS. Suspicious links must never
be visited by the verifier itself.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from encodings import idna as _idna
from urllib.parse import urlsplit

from trustgate.rules import lexicons as lx
from trustgate.schemas import LinkFinding, RedFlag, Severity

_BARE_TLDS = frozenset({
    "com", "net", "org", "info", "biz", "io", "co", "me", "app", "dev", "ai", "tv", "ly", "gl",
    "uk", "de", "fr", "es", "it", "nl", "tr", "ru", "cn", "jp", "au", "ca", "us", "be", "ch",
    "at", "pl", "se", "no", "dk", "fi", "pt", "gr", "ie", "in", "br", "mx", "za", "nz", "sg",
    "hk", "eu", "to", "cc", "ws", "gov", "edu",
}) | lx.SUSPICIOUS_TLDS | lx.LOW_TRUST_TLDS

_LABEL = r"[a-z0-9¡-￿](?:[a-z0-9¡-￿-]{0,61}[a-z0-9¡-￿])?"
_URL_RE = re.compile(
    rf"""
    (?:(?:https?|hxxps?)://|www\.)[^\s<>"'`]+                  # explicit scheme or www.
    |
    (?<![@\w./-])(?:{_LABEL}\.)+(?P<tld>[a-z]{{2,24}}|xn--[a-z0-9-]{{2,59}})
    (?::\d{{2,5}})?(?:/[^\s<>"'`]*)?(?![\w@])                   # bare domain, e.g. paypa1.com/login
    """,
    re.IGNORECASE | re.VERBOSE,
)
_TRAILING_PUNCT = ".,;:!?'\"»”’)]}>"


@dataclass(frozen=True)
class ExtractedUrl:
    raw: str
    start: int | None = None
    end: int | None = None


@dataclass(frozen=True)
class ParsedUrl:
    raw: str
    scheme: str | None
    host: str  # unicode, lower-case
    userinfo: str | None
    path: str
    registered_domain: str
    suffix: str
    subdomain_labels: tuple[str, ...]
    is_ip: bool
    is_idn: bool

    @property
    def reg_label(self) -> str:
        """The label just left of the public suffix: 'paypa1' in 'login.paypa1.com'."""
        return self.registered_domain.split(".")[0]


@dataclass(frozen=True)
class LinkContext:
    """What the message claims about its origin, used for mismatch checks."""

    sender_domain: str | None = None
    claimed_tokens: frozenset[str] = frozenset()
    claimed_brands: tuple[lx.Brand, ...] = ()
    # Brands named near the start of the message, where senders identify themselves ("PayPal: ...").
    mentioned_brands: tuple[lx.Brand, ...] = ()


# --------------------------------------------------------------------------- parsing


def extract_urls(text: str) -> list[ExtractedUrl]:
    found: list[ExtractedUrl] = []
    for m in _URL_RE.finditer(text):
        tld = m.group("tld")
        if tld is not None:
            if tld.lower() not in _BARE_TLDS and not tld.lower().startswith("xn--"):
                continue
            if tld[0].isupper() and tld[1:].islower():  # "telephony.Click" is a missing space, not a domain
                continue
        raw = m.group(0)
        while raw and raw[-1] in _TRAILING_PUNCT:
            if raw[-1] == ")" and raw.count("(") >= raw.count(")"):
                break
            raw = raw[:-1]
        if "." not in raw:
            continue
        found.append(ExtractedUrl(raw=raw, start=m.start(), end=m.start() + len(raw)))
    return found


def registered_domain(host: str) -> tuple[str, str, tuple[str, ...]]:
    """Split a host into (registered domain, public suffix, subdomain labels)."""
    labels = [label for label in host.split(".") if label]
    if len(labels) < 2:
        return host, "", ()
    if len(labels) >= 3 and ".".join(labels[-2:]) in lx.TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:]), ".".join(labels[-2:]), tuple(labels[:-3])
    return ".".join(labels[-2:]), labels[-1], tuple(labels[:-2])


def _to_unicode_host(host: str) -> str:
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = _idna.ToUnicode(label)
            except UnicodeError:
                pass
        labels.append(label)
    return ".".join(labels)


def parse_url(raw: str) -> ParsedUrl | None:
    candidate = re.sub(r"^hxxp", "http", raw.strip(), flags=re.IGNORECASE)
    has_scheme = re.match(r"^[a-z][a-z0-9+.-]*://", candidate, re.IGNORECASE) is not None
    if not has_scheme:
        candidate = "http://" + candidate
    try:
        parts = urlsplit(candidate)
    except ValueError:
        return None

    netloc = parts.netloc
    userinfo, _, hostport = netloc.rpartition("@")
    if hostport.startswith("["):
        host = hostport[1:].split("]", 1)[0]
    else:
        host = hostport.split(":", 1)[0]
    host = host.strip(".").lower()
    if not host:
        return None

    unicode_host = _to_unicode_host(host)
    is_idn = unicode_host != host or any(ord(ch) > 127 for ch in host)

    is_ip = False
    try:
        ipaddress.ip_address(host if not host.isdigit() else int(host))
        is_ip = True
    except ValueError:
        pass

    reg, suffix, subs = (host, "", ()) if is_ip else registered_domain(unicode_host)
    return ParsedUrl(
        raw=raw,
        scheme=parts.scheme.lower() if has_scheme else None,
        host=unicode_host,
        userinfo=userinfo or None,
        path=parts.path + (("?" + parts.query) if parts.query else ""),
        registered_domain=reg,
        suffix=suffix,
        subdomain_labels=subs,
        is_ip=is_ip,
        is_idn=is_idn,
    )


# --------------------------------------------------------------------------- lookalikes


def skeleton(text: str) -> str:
    """Collapse visually confusable characters so look-alikes compare equal."""
    decomposed = unicodedata.normalize("NFKD", text.lower())
    out = []
    for ch in decomposed:
        if unicodedata.combining(ch):
            continue
        out.append(lx.CONFUSABLES.get(ch, ch))
    result = "".join(out)
    for seq, repl in lx.CONFUSABLE_SEQUENCES:
        result = result.replace(seq, repl)
    return result.replace("-", "")


def edit_distance(a: str, b: str) -> int:
    """Optimal string alignment distance (Levenshtein + adjacent transpositions)."""
    if a == b:
        return 0
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[-1]


def owning_brand(registered: str) -> lx.Brand | None:
    for brand in lx.BRANDS:
        if brand.owns(registered):
            return brand
    return None


@dataclass(frozen=True)
class _Issue:
    rule_id: str
    category: str
    severity: Severity
    title: str
    explanation: str
    brand: str | None = None


def _contains_brand(label: str, brand_label: str) -> bool:
    label_sk, brand_sk = skeleton(label), skeleton(brand_label)
    if len(brand_label) >= 6 and brand_label not in lx.GENERIC_BRAND_LABELS:
        return brand_sk in label_sk
    tokens = [t for t in re.split(r"[-_]", label) if t]
    has_brand = any(skeleton(t) == brand_sk for t in tokens)
    has_bait = any(t in lx.SQUAT_KEYWORDS for t in tokens)
    return has_brand and has_bait


def lookalike_issues(parsed: ParsedUrl) -> list[_Issue]:
    """Brand impersonation through the domain name itself."""
    if parsed.is_ip or owning_brand(parsed.registered_domain):
        return []

    issues: list[_Issue] = []
    label = parsed.reg_label
    label_sk = skeleton(label)
    subdomain = ".".join(parsed.subdomain_labels)
    for brand in lx.BRANDS:
        for brand_label in brand.labels:
            brand_sk = skeleton(brand_label)
            official = ", ".join(brand.domains[:2])
            if label == brand_label:
                regional = lx.is_cctld(parsed.suffix) and parsed.suffix not in lx.SUSPICIOUS_TLDS
                issues.append(_Issue(
                    "link.brand_unofficial_domain", "link_lookalike",
                    Severity.LOW if regional else Severity.HIGH,
                    f"Uses the {brand.name} name on an unlisted domain",
                    f"{parsed.registered_domain} is not one of {brand.name}'s known domains ({official}).",
                    brand.name,
                ))
            elif label_sk == brand_sk:
                issues.append(_Issue(
                    "link.homoglyph_brand", "link_lookalike", Severity.CRITICAL,
                    f"Look-alike of {brand.name}'s domain",
                    f"'{parsed.registered_domain}' is built to look like {official} using look-alike characters.",
                    brand.name,
                ))
            elif (
                len(brand_label) >= 6
                and brand_label not in lx.GENERIC_BRAND_LABELS
                and label not in lx.NOT_TYPOSQUATS
                and edit_distance(label_sk, brand_sk) <= (1 if len(brand_label) < 9 else 2)
            ):
                issues.append(_Issue(
                    "link.typosquat_brand", "link_lookalike", Severity.CRITICAL,
                    f"Misspelling of {brand.name}'s domain",
                    f"'{parsed.registered_domain}' is one or two letters away from {official}.",
                    brand.name,
                ))
            elif _contains_brand(label, brand_label):
                issues.append(_Issue(
                    "link.combosquat_brand", "link_lookalike", Severity.HIGH,
                    f"{brand.name} name inside an unrelated domain",
                    f"'{parsed.registered_domain}' borrows the {brand.name} name but is not owned by {brand.name}.",
                    brand.name,
                ))

            if subdomain and (
                any(skeleton(sub) == brand_sk for sub in parsed.subdomain_labels)
                or (len(brand_label) >= 6 and brand_label not in lx.GENERIC_BRAND_LABELS and brand_sk in skeleton(subdomain))
            ):
                full_domain_prefix = any(d in subdomain for d in brand.domains)
                issues.append(_Issue(
                    "link.brand_in_subdomain", "link_lookalike",
                    Severity.CRITICAL if full_domain_prefix else Severity.HIGH,
                    f"{brand.name} name used as a disguise in the subdomain",
                    f"The link starts with '{subdomain}' but the real site is {parsed.registered_domain}.",
                    brand.name,
                ))
    return issues


# --------------------------------------------------------------------------- per-URL analysis


def _hygiene_issues(parsed: ParsedUrl) -> list[_Issue]:
    issues: list[_Issue] = []
    if parsed.userinfo:
        issues.append(_Issue(
            "link.userinfo_trick", "link_obfuscation", Severity.HIGH,
            "Link hides its real destination",
            f"Everything before '@' in a link is ignored; this one actually opens {parsed.host}.",
        ))
    if parsed.is_ip:
        issues.append(_Issue(
            "link.ip_address", "link_obfuscation", Severity.HIGH,
            "Link points to a raw IP address",
            "Legitimate organizations link to their named website, not a numeric server address.",
        ))
    if parsed.is_idn:
        issues.append(_Issue(
            "link.international_chars", "link_obfuscation", Severity.HIGH,
            "Domain uses international (punycode) characters",
            f"'{parsed.host}' contains non-Latin characters that can imitate familiar letters.",
        ))
    if parsed.registered_domain in lx.URL_SHORTENERS or parsed.host in lx.URL_SHORTENERS:
        issues.append(_Issue(
            "link.shortener", "link_obfuscation", Severity.MEDIUM,
            "Shortened link hides the destination",
            f"{parsed.host} is a URL shortener; the real website is not visible until you click.",
        ))

    tld = parsed.suffix.rsplit(".", 1)[-1]
    if tld in lx.SUSPICIOUS_TLDS:
        issues.append(_Issue(
            "link.suspicious_tld", "link_hygiene", Severity.MEDIUM,
            f"High-abuse domain ending (.{tld})",
            f".{tld} domains are cheap and heavily used in phishing campaigns.",
        ))
    elif tld in lx.LOW_TRUST_TLDS:
        issues.append(_Issue(
            "link.low_trust_tld", "link_hygiene", Severity.LOW,
            f"Uncommon domain ending (.{tld})",
            f"Established banks and couriers rarely use .{tld} domains.",
        ))

    if not parsed.is_ip:
        hyphens = parsed.reg_label.count("-")
        if hyphens >= 2 or len(parsed.subdomain_labels) >= 3 or len(parsed.host) > 45:
            issues.append(_Issue(
                "link.complex_host", "link_hygiene", Severity.LOW,
                "Unusually long or hyphenated web address",
                f"'{parsed.host}' is the kind of long, stitched-together address used to look official.",
            ))

    path = parsed.path.lower()
    words = [w for w in lx.CREDENTIAL_PATH_WORDS if w in path]
    if words:
        issues.append(_Issue(
            "link.credential_path", "link_hygiene", Severity.LOW,
            "Link leads to a login / verification page",
            f"The address contains '{words[0]}', typical of pages that collect passwords or card details.",
        ))
    if parsed.scheme == "http":
        issues.append(_Issue(
            "link.no_https", "link_hygiene", Severity.LOW,
            "Unencrypted link (http)",
            "The link does not use HTTPS.",
        ))
    return issues


def _context_issues(parsed: ParsedUrl, ctx: LinkContext, already_impersonated: bool) -> list[_Issue]:
    """Mismatch between who the message claims to be and where the link goes."""
    if parsed.is_ip:
        return []
    owner = owning_brand(parsed.registered_domain)

    for brand in ctx.claimed_brands:
        if not brand.owns(parsed.registered_domain) and not already_impersonated:
            return [_Issue(
                "link.claimed_brand_mismatch", "link_mismatch", Severity.HIGH,
                f"Sender claims to be {brand.name}, link goes elsewhere",
                f"The message claims to come from {brand.name}, but the link opens {parsed.registered_domain}.",
                brand.name,
            )]

    if ctx.claimed_tokens and not ctx.claimed_brands:
        label_sk = skeleton(parsed.registered_domain)
        claimed = " ".join(sorted(ctx.claimed_tokens))
        sub_sk = " ".join(skeleton(label) for label in parsed.subdomain_labels)
        in_subdomain = any(len(tok) >= 4 and skeleton(tok) in sub_sk for tok in ctx.claimed_tokens)
        if in_subdomain and not any(skeleton(tok) in label_sk for tok in ctx.claimed_tokens):
            return [_Issue(
                "link.claimed_name_in_subdomain", "link_lookalike", Severity.HIGH,
                "Sender's name used as a disguise in the link",
                f"The link starts with the '{claimed}' name, but the site really belongs to {parsed.registered_domain}.",
            )]
        if not any(skeleton(tok) in label_sk for tok in ctx.claimed_tokens) and parsed.registered_domain != ctx.sender_domain:
            return [_Issue(
                "link.sender_mismatch", "link_mismatch", Severity.MEDIUM,
                "Link does not belong to the claimed sender",
                f"The sender presents as '{claimed}', but the link opens {parsed.registered_domain}.",
            )]
        tokens = re.split(r"[-_]", parsed.reg_label)
        if len(tokens) > 1 and any(t in lx.SQUAT_KEYWORDS for t in tokens) and parsed.registered_domain != ctx.sender_domain:
            return [_Issue(
                "link.claimed_name_with_bait", "link_mismatch", Severity.MEDIUM,
                "Sender's name stitched together with 'secure'/'verify'-style words",
                f"'{parsed.registered_domain}' pairs the '{claimed}' name with bait words; official sites rarely look like this.",
            )]

    if (
        ctx.sender_domain
        and ctx.sender_domain not in lx.FREE_EMAIL_DOMAINS
        and parsed.registered_domain != ctx.sender_domain
        and parsed.registered_domain not in lx.URL_SHORTENERS
        and not (owner and owner.owns(ctx.sender_domain))
    ):
        return [_Issue(
            "link.sender_domain_mismatch", "link_mismatch", Severity.MEDIUM,
            "Link domain differs from the sender's email domain",
            f"The email came from {ctx.sender_domain}, but the link opens {parsed.registered_domain}.",
        )]

    if not already_impersonated:
        for brand in ctx.mentioned_brands:
            if not brand.owns(parsed.registered_domain) and owner is None:
                return [_Issue(
                    "link.brand_mention_mismatch", "link_mismatch", Severity.MEDIUM,
                    f"Mentions {brand.name}, but the link is not {brand.name}'s",
                    f"The text refers to {brand.name}, yet the link opens {parsed.registered_domain}.",
                    brand.name,
                )]
    return []


def analyze_url(url: ExtractedUrl, ctx: LinkContext) -> tuple[LinkFinding | None, list[RedFlag]]:
    parsed = parse_url(url.raw)
    if parsed is None:
        return None, []

    issues = _hygiene_issues(parsed)
    if ctx.sender_domain and parsed.registered_domain == ctx.sender_domain:
        # A login/reset link on the sender's own domain is expected, not a red flag.
        issues = [i for i in issues if not (i.category == "link_hygiene" and i.severity is Severity.LOW)]
    impersonation = lookalike_issues(parsed)
    issues += impersonation
    issues += _context_issues(parsed, ctx, already_impersonated=any(i.severity.rank >= Severity.HIGH.rank for i in impersonation))

    flags = [
        RedFlag(
            rule_id=i.rule_id,
            category=i.category,
            severity=i.severity,
            title=i.title,
            explanation=i.explanation,
            evidence=url.raw,
            start=url.start,
            end=url.end,
            source="links",
        )
        for i in issues
    ]
    brand = next((i.brand for i in sorted(issues, key=lambda i: -i.severity.rank) if i.brand and i.category == "link_lookalike"), None)
    finding = LinkFinding(
        url=url.raw,
        host=parsed.host,
        registered_domain=parsed.registered_domain,
        issues=[i.title for i in issues],
        severity=max((i.severity for i in issues), key=lambda s: s.rank, default=None),
        impersonated_brand=brand,
    )
    return finding, flags


def analyze_links(message: str, extra_urls: list[str], ctx: LinkContext, max_urls: int = 20) -> tuple[list[LinkFinding], list[RedFlag]]:
    urls = extract_urls(message)
    seen = {u.raw.lower() for u in urls}
    for raw in extra_urls:
        if raw.strip() and raw.strip().lower() not in seen:
            urls.append(ExtractedUrl(raw=raw.strip()))
            seen.add(raw.strip().lower())

    findings: list[LinkFinding] = []
    flags: list[RedFlag] = []
    for url in urls[:max_urls]:
        finding, url_flags = analyze_url(url, ctx)
        if finding is not None:
            findings.append(finding)
            flags.extend(url_flags)
    return findings, flags
