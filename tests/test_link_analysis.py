import socket

import pytest

from trustgate.rules.link_analysis import (
    LinkContext,
    analyze_links,
    edit_distance,
    extract_urls,
    parse_url,
    registered_domain,
    skeleton,
)
from trustgate.rules import lexicons as lx
from trustgate.schemas import Severity


def rule_ids(flags):
    return {f.rule_id for f in flags}


def analyze_one(url: str, ctx: LinkContext | None = None):
    findings, flags = analyze_links("", [url], ctx or LinkContext())
    assert len(findings) == 1
    return findings[0], flags


# ------------------------------------------------------------------ extraction


def test_extracts_scheme_www_and_bare_domains_with_spans():
    text = "Go to https://example.com/a?b=1, or www.test.org. Also paypa1.com/login now."
    urls = extract_urls(text)
    assert [u.raw for u in urls] == ["https://example.com/a?b=1", "www.test.org", "paypa1.com/login"]
    for u in urls:
        assert text[u.start:u.end] == u.raw


def test_does_not_extract_email_addresses_or_abbreviations():
    text = "Write to support@northwind.com, e.g. tomorrow. Mr.Smith said hi."
    assert extract_urls(text) == []


def test_strips_trailing_punctuation_but_keeps_balanced_parens():
    assert extract_urls("(see https://example.com/page)")[0].raw == "https://example.com/page"
    assert extract_urls("https://en.wiki.org/Foo_(bar).")[0].raw == "https://en.wiki.org/Foo_(bar)"


def test_extracts_unicode_and_defanged_hosts():
    urls = [u.raw for u in extract_urls("Login at pаypal.com or hxxps://bad.xyz/x")]
    assert "pаypal.com" in urls
    assert "hxxps://bad.xyz/x" in urls


# ------------------------------------------------------------------ parsing helpers


@pytest.mark.parametrize(
    "host,reg,suffix,subs",
    [
        ("login.paypal.com", "paypal.com", "com", ("login",)),
        ("secure.barclays.co.uk", "barclays.co.uk", "co.uk", ("secure",)),
        ("a.b.c.example.com.tr", "example.com.tr", "com.tr", ("a", "b", "c")),
        ("localhost", "localhost", "", ()),
    ],
)
def test_registered_domain(host, reg, suffix, subs):
    assert registered_domain(host) == (reg, suffix, subs)


def test_parse_url_handles_userinfo_ip_and_punycode():
    p = parse_url("http://paypal.com@203.0.113.7/login")
    assert p.userinfo == "paypal.com" and p.is_ip
    p = parse_url("https://xn--pypal-4ve.com/")
    assert p.is_idn and p.host == "pаypal.com"
    assert parse_url("http://[::1") is None


def test_skeleton_collapses_confusables():
    assert skeleton("paypa1") == skeleton("pаypal") == "paypal"  # digit one / Cyrillic a
    assert skeleton("rnicrosoft") == "microsoft"
    assert skeleton("g00gle") == "google"


def test_edit_distance():
    assert edit_distance("paypal", "paypal") == 0
    assert edit_distance("paypal", "paypla") == 1  # transposition
    assert edit_distance("amazon", "amazom") == 1
    assert edit_distance("kitten", "sitting") == 3


# ------------------------------------------------------------------ issues


def test_official_brand_domain_is_clean():
    finding, flags = analyze_one("https://www.paypal.com/signin")
    assert finding.impersonated_brand is None
    assert not any(f.category == "link_lookalike" for f in flags)


@pytest.mark.parametrize("url", ["https://paypa1.com", "https://pаypal.com/login", "https://rnicrosoft.com", "https://arnazon.com"])
def test_homoglyph_lookalikes_are_critical(url):
    finding, flags = analyze_one(url)
    assert "link.homoglyph_brand" in rule_ids(flags)
    assert finding.severity.value == "critical"
    assert finding.impersonated_brand is not None


def test_typosquat_detected_but_dictionary_words_are_not():
    _, flags = analyze_one("https://netflx.com")
    assert "link.typosquat_brand" in rule_ids(flags)
    _, flags = analyze_one("https://finance.com")
    assert "link.typosquat_brand" not in rule_ids(flags)


def test_combosquat_and_subdomain_abuse():
    _, flags = analyze_one("https://paypal-account-verify.com/login")
    assert "link.combosquat_brand" in rule_ids(flags)
    _, flags = analyze_one("https://paypal.com.secure-check.xyz/")
    ids = rule_ids(flags)
    assert "link.brand_in_subdomain" in ids
    assert "link.suspicious_tld" in ids
    assert any(f.rule_id == "link.brand_in_subdomain" and f.severity.value == "critical" for f in flags)


def test_generic_brand_words_need_bait_keywords():
    _, flags = analyze_one("https://market-outlook.com/report")
    assert not any(f.category == "link_lookalike" for f in flags)
    _, flags = analyze_one("https://outlook-verify.com")
    assert "link.combosquat_brand" in rule_ids(flags)


def test_regional_brand_domain_is_low_not_high():
    _, flags = analyze_one("https://amazon.in")
    sev = {f.rule_id: f.severity.value for f in flags}
    assert sev["link.brand_unofficial_domain"] == "low"
    _, flags = analyze_one("https://paypal.support")
    sev = {f.rule_id: f.severity.value for f in flags}
    assert sev["link.brand_unofficial_domain"] == "high"


def test_obfuscation_signals():
    assert "link.userinfo_trick" in rule_ids(analyze_one("http://paypal.com@evil.example/")[1])
    assert "link.ip_address" in rule_ids(analyze_one("http://192.168.10.5/bank")[1])
    assert "link.shortener" in rule_ids(analyze_one("https://bit.ly/3xYz")[1])
    assert "link.international_chars" in rule_ids(analyze_one("https://xn--80ak6aa92e.com")[1])


def test_sender_mismatch_against_claimed_organization():
    ctx = LinkContext(claimed_tokens=frozenset({"northwind"}))
    _, flags = analyze_one("https://secure-login-auth.com/verify", ctx)
    assert "link.sender_mismatch" in rule_ids(flags)
    _, flags = analyze_one("https://northwind.com/help", ctx)
    assert not any(f.category == "link_mismatch" for f in flags)
    _, flags = analyze_one("https://northwind-verify.com/", ctx)
    assert "link.claimed_name_with_bait" in rule_ids(flags)


def test_sender_domain_and_brand_mention_mismatch():
    ctx = LinkContext(sender_domain="northwind.com")
    assert "link.sender_domain_mismatch" in rule_ids(analyze_one("https://other-site.net", ctx)[1])
    paypal = next(b for b in lx.BRANDS if b.name == "PayPal")
    ctx = LinkContext(mentioned_brands=(paypal,))
    assert "link.brand_mention_mismatch" in rule_ids(analyze_one("https://pay-portal.net", ctx)[1])
    ctx = LinkContext(claimed_brands=(paypal,))
    assert "link.claimed_brand_mismatch" in rule_ids(analyze_one("https://pay-portal.net", ctx)[1])


def test_link_analysis_never_touches_the_network():
    # conftest blocks sockets; this would raise if any lookup or fetch happened.
    with pytest.raises(Exception):
        socket.create_connection(("example.com", 443))
    findings, _ = analyze_links("Visit https://paypa1.com and http://192.0.2.1/x and bit.ly/abc", [], LinkContext())
    assert len(findings) == 3


def test_url_limit_is_respected():
    text = " ".join(f"https://site{i}.com" for i in range(30))
    findings, _ = analyze_links(text, [], LinkContext(), max_urls=5)
    assert len(findings) == 5


def test_claimed_name_used_as_a_subdomain_disguise():
    ctx = LinkContext(claimed_tokens=frozenset({"driftfile"}))
    _, flags = analyze_one("https://driftfile.example.docview-share.net/s/q4", ctx)
    flag = next(f for f in flags if f.rule_id == "link.claimed_name_in_subdomain")
    assert flag.severity is Severity.HIGH and flag.category == "link_lookalike"
    _, flags = analyze_one("https://files.driftfile.com/s/q4", ctx)
    assert "link.claimed_name_in_subdomain" not in rule_ids(flags)
