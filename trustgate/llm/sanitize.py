"""Output hygiene for the LLM's free text.

A hijacked analyst could relay the scammer's "call this number to verify" or
"log in at this link" to the very person TrustGate is protecting. Its summary,
steps and reasons are therefore defanged: links and e-mail addresses are made
unclickable the way threat reports write them (hxxps://example[.]com), and phone
numbers and account numbers are removed. Quotes are not touched: they are
checked against the message itself.
"""

from __future__ import annotations

import re

_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){3,7}(?:\s?[A-Z0-9]{1,4})?\b")
_URL = re.compile(r"\b(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b(?:/[^\s<>\"']*)?", re.IGNORECASE)
_PHONE = re.compile(r"(?<![\w.])\+?\d[\d\s().-]{6,}\d(?![\w.])")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}|\d{1,2}[./-]\d{1,2}[./-]\d{2,4}")


def _phone(match: re.Match[str]) -> str:
    text = match.group()
    if _DATE.fullmatch(text.strip()) or sum(ch.isdigit() for ch in text) < 9:
        return text
    return "[phone number removed]"


def defang(text: str) -> str:
    text = _IBAN.sub("[account number removed]", text)
    text = _URL.sub(lambda m: re.sub(r"^http", "hxxp", m.group(), flags=re.IGNORECASE).replace(".", "[.]"), text)
    text = _EMAIL.sub(lambda m: m.group().replace("@", "[@]").replace(".", "[.]"), text)
    text = _DOMAIN.sub(lambda m: m.group().replace(".", "[.]"), text)
    return _PHONE.sub(_phone, text)
