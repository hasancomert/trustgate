"""Static reference data for the rule engine and link analysis.

Real brand domains are listed here only as *detection references*: a link that
looks like `paypa1.com` is risky precisely because `paypal.com` is the real one.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Brand:
    name: str
    domains: tuple[str, ...]
    # Lower-case words that indicate the message claims to be from this brand.
    mentions: tuple[str, ...]
    # Extra registered domains the brand legitimately uses (CDNs, mail, regional).
    related_domains: tuple[str, ...] = field(default_factory=tuple)

    @property
    def labels(self) -> tuple[str, ...]:
        """Second-level labels used for lookalike comparison, e.g. 'paypal'."""
        return tuple(sorted({d.split(".")[0] for d in self.domains}))

    def owns(self, registered_domain: str) -> bool:
        return registered_domain in self.domains or registered_domain in self.related_domains


BRANDS: tuple[Brand, ...] = (
    Brand("PayPal", ("paypal.com", "paypal.me"), ("paypal",), ("paypalobjects.com", "venmo.com")),
    Brand("Apple", ("apple.com", "icloud.com"), ("apple id", "icloud", "apple pay"), ("me.com", "apple.news")),
    Brand("Microsoft", ("microsoft.com", "office.com", "outlook.com", "live.com"), ("microsoft", "office 365", "microsoft 365", "outlook account"), ("microsoftonline.com", "office365.com", "sharepoint.com", "windows.net", "hotmail.com")),
    Brand("Google", ("google.com", "gmail.com"), ("google",), ("googleusercontent.com", "gstatic.com", "googleapis.com", "googlevideo.com", "google-analytics.com", "googletagmanager.com", "youtube.com", "g.co", "goo.gl")),
    Brand("Amazon", ("amazon.com", "amazon.co.uk", "amazon.de", "amazon.com.tr", "amazon.fr", "amazon.es", "amazon.it"), ("amazon",), ("amazonaws.com", "amazontrust.com", "media-amazon.com", "amazon.jobs", "amzn.to", "a.co")),
    Brand("Netflix", ("netflix.com",), ("netflix",), ("nflxext.com", "nflxso.net")),
    Brand("Meta", ("facebook.com", "instagram.com", "whatsapp.com", "meta.com"), ("facebook", "instagram", "whatsapp support"), ("fb.com", "fbcdn.net", "wa.me")),
    Brand("DHL", ("dhl.com", "dhl.de"), ("dhl",)),
    Brand("FedEx", ("fedex.com",), ("fedex",)),
    Brand("UPS", ("ups.com",), ("ups",)),
    Brand("USPS", ("usps.com",), ("usps",)),
    Brand("Royal Mail", ("royalmail.com",), ("royal mail",)),
    Brand("HMRC", ("hmrc.gov.uk",), ("hmrc",), ("gov.uk",)),
    Brand("IRS", ("irs.gov",), ("irs",)),
    Brand("Chase", ("chase.com",), ("chase bank",)),
    Brand("Bank of America", ("bankofamerica.com",), ("bank of america",)),
    Brand("Wells Fargo", ("wellsfargo.com",), ("wells fargo",)),
    Brand("HSBC", ("hsbc.com", "hsbc.co.uk"), ("hsbc",)),
    Brand("Barclays", ("barclays.co.uk", "barclays.com"), ("barclays",)),
    Brand("Santander", ("santander.com", "santander.co.uk"), ("santander",)),
    Brand("Revolut", ("revolut.com",), ("revolut",)),
    Brand("Wise", ("wise.com",), ("wise transfer",)),
    Brand("Coinbase", ("coinbase.com",), ("coinbase",)),
    Brand("Binance", ("binance.com",), ("binance",)),
    Brand("eBay", ("ebay.com", "ebay.co.uk"), ("ebay",)),
    Brand("LinkedIn", ("linkedin.com",), ("linkedin",), ("lnkd.in",)),
    Brand("Dropbox", ("dropbox.com",), ("dropbox",)),
    Brand("DocuSign", ("docusign.com", "docusign.net"), ("docusign",)),
    Brand("Adobe", ("adobe.com",), ("adobe",)),
    Brand("Steam", ("steampowered.com", "steamcommunity.com"), ("steam account", "steam wallet", "steam gift")),
)

# Brand labels that are also everyday words: only flagged for exact visual
# lookalikes or when glued to phishing keywords ("outlook-verify.com").
GENERIC_BRAND_LABELS: frozenset[str] = frozenset({"office", "outlook", "icloud", "live", "apple", "steam", "chase", "wise"})

# Real words within one edit of a brand label; never treated as typosquats.
NOT_TYPOSQUATS: frozenset[str] = frozenset({"finance", "cloud", "revolt", "amazing", "people", "goggles", "facebooks"})

URL_SHORTENERS: frozenset[str] = frozenset({
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "s.id", "t.ly", "bit.do",
    "qrco.de", "shorte.st", "adf.ly", "v.gd", "tr.im", "x.co", "lnkd.in", "trib.al",
    "soo.gd", "clck.ru", "u.to", "short.io", "bl.ink", "tiny.one",
})

# TLDs heavily over-represented in abuse feeds. Still only a supporting signal.
SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "xyz", "top", "click", "icu", "buzz", "rest", "monster", "cyou", "sbs", "cfd", "loan",
    "win", "bid", "zip", "mov", "gq", "ml", "cf", "tk", "ga", "country", "kim", "men",
    "date", "review", "lol", "quest", "beauty", "hair", "autos", "boats", "bond",
})

# TLDs also popular with small legitimate businesses: weaker signal.
LOW_TRUST_TLDS: frozenset[str] = frozenset({
    "info", "online", "site", "store", "live", "support", "work", "shop", "vip", "app", "link",
})

# Country-code TLDs we accept as plausible regional brand domains (amazon.in, google.de...).
def is_cctld(suffix: str) -> bool:
    last = suffix.rsplit(".", 1)[-1]
    return len(last) == 2 and last.isalpha()

FREE_EMAIL_DOMAINS: frozenset[str] = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com",
    "yahoo.co.uk", "aol.com", "icloud.com", "me.com", "proton.me", "protonmail.com",
    "gmx.com", "gmx.de", "mail.com", "yandex.com", "yandex.ru", "zoho.com", "tutanota.com",
})

# Public suffixes with two labels. Enough to compute a registered domain for the
# common cases without shipping (or downloading) the full Public Suffix List.
TWO_LEVEL_SUFFIXES: frozenset[str] = frozenset({
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.tr", "gov.tr", "org.tr", "net.tr", "edu.tr",
    "com.au", "net.au", "org.au", "gov.au",
    "co.nz", "co.za", "co.jp", "co.in", "co.kr", "co.id", "com.br", "com.mx", "com.ar",
    "com.cn", "com.hk", "com.sg", "com.my", "com.ph", "com.ng", "com.pk", "com.sa", "com.eg",
})

# Words that sound official but say nothing about who owns a domain. Used when
# comparing a claimed organization name with a domain.
GENERIC_ORG_WORDS: frozenset[str] = frozenset({
    "bank", "banking", "the", "team", "security", "secure", "support", "service", "services",
    "customer", "care", "help", "desk", "department", "dept", "official", "online", "account",
    "accounts", "group", "inc", "ltd", "llc", "plc", "co", "corp", "company", "limited",
    "fraud", "prevention", "alerts", "alert", "notification", "notifications", "noreply",
    "no", "reply", "info", "mail", "admin", "billing", "payments", "payment", "finance",
    "delivery", "express", "post", "parcel", "parcels", "courier", "logistics", "uk", "us",
    "global", "international", "of", "and", "&", "verify", "verification",
})

# Tokens that, glued to a brand in a domain, suggest combosquatting
# (e.g. "paypal-secure-login.com").
SQUAT_KEYWORDS: frozenset[str] = frozenset({
    "secure", "security", "login", "signin", "verify", "verification", "account", "accounts",
    "update", "support", "help", "service", "billing", "payment", "pay", "refund", "unlock",
    "confirm", "auth", "wallet", "official", "online", "alert", "id", "web", "portal", "customer",
    "redelivery", "delivery", "tracking", "track", "parcel", "claim", "bonus", "gift", "promo",
})

# Path words common in credential-harvesting pages.
CREDENTIAL_PATH_WORDS: tuple[str, ...] = (
    "login", "log-in", "signin", "sign-in", "verify", "verification", "secure", "account",
    "update", "confirm", "unlock", "password", "wallet", "billing", "auth", "recover", "reset",
)

# Characters that render like ASCII letters. Mapped to their look-alike so that
# `pаypal` (Cyrillic а) and `paypa1` collapse to the same "skeleton" as `paypal`.
CONFUSABLES: dict[str, str] = {
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p",
    "с": "c", "т": "t", "у": "y", "х": "x", "ѕ": "s", "і": "i", "ї": "i", "ј": "j", "ԁ": "d",
    "ԛ": "q", "ԝ": "w", "ӏ": "l", "һ": "h", "ɡ": "g", "ո": "n", "ս": "u",
    # Greek
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t",
    "υ": "u", "χ": "x", "ω": "w",
    # Latin look-alikes and digits
    "ı": "i", "ł": "l", "ø": "o", "ß": "b",
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "|": "l",
}

# Multi-character visual tricks, applied after single-character mapping.
CONFUSABLE_SEQUENCES: tuple[tuple[str, str], ...] = (("rn", "m"), ("vv", "w"), ("cl", "d"))
