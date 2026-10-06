"""Text a person does not see but an LLM reads.

Prompt injection against LLM-based phishing detectors hides its instructions
where the human reader will not notice them: invisible Unicode "tag"
characters that spell out ASCII ("ASCII smuggling"), text-direction controls,
HTML comments, text pushed far below the visible message, or an encoded
payload with a "decode and follow" note. Koide et al. (2026, "Clouding the
Mirror", arXiv:2602.05484) call this the perceptual asymmetry between LLMs and
humans. reveal() decodes all of it, so the rules can scan it and the LLM is told
explicitly that the text was hidden.
"""

from __future__ import annotations

import base64
import binascii
import html
import re
from dataclasses import dataclass
from typing import Literal
from urllib.parse import unquote

HiddenKind = Literal["unicode_tags", "direction_controls", "html_comment", "pushed_out_of_view", "encoded"]

TAG_START, TAG_END, TAG_CANCEL = 0xE0000, 0xE007F, 0xE007F
DIRECTION_CONTROLS = frozenset("‪‫‬‭‮⁦⁧⁨⁩‎‏؜")
BLACK_FLAG = "\U0001F3F4"  # England / Scotland / Wales flags are BLACK_FLAG + tag letters + cancel tag

MAX_TEXT = 500
_TAG_RUN = re.compile("[\U000E0000-\U000E007F]+")
_COMMENT = re.compile(r"<!--([\s\S]*?)-->")
_PUSHED = re.compile(r"(?:[ \t ]*\n){8,}|[ \t ]{300,}")
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/=_.:%-])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=_.%-])")
_ENTITIES = re.compile(r"(?:&#x?[0-9a-fA-F]{1,6};){6,}")
_PERCENT = re.compile(r"(?:%[0-9a-fA-F]{2}){8,}")
_WORDS = re.compile(r"[^\W\d_]{2,}")


@dataclass(frozen=True)
class HiddenText:
    kind: HiddenKind
    text: str  # revealed or decoded text, as an LLM would read it
    start: int | None = None  # span in the original message
    end: int | None = None


def _readable(text: str) -> bool:
    """Decoded bytes that form words, not binary noise or a random token."""
    if not text or len(text) < 12:
        return False
    printable = sum(ch.isprintable() or ch in "\n\t" for ch in text) / len(text)
    return printable > 0.95 and len(_WORDS.findall(text)) >= 3 and " " in text


def _decode_base64(token: str) -> str | None:
    try:
        raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError):
        return None
    return text.strip() if _readable(text) else None


def strip_invisible(text: str) -> str:
    """Remove tag characters and direction controls (reveal() reports what they carried)."""
    return "".join(ch for ch in text if not (TAG_START <= ord(ch) <= TAG_END or ch in DIRECTION_CONTROLS))


def reveal(message: str) -> list[HiddenText]:
    found: list[HiddenText] = []

    for m in _TAG_RUN.finditer(message):
        decoded = "".join(chr(ord(c) - TAG_START) for c in m.group() if ord(c) != TAG_CANCEL)
        is_flag_emoji = m.start() > 0 and message[m.start() - 1] == BLACK_FLAG and re.fullmatch(r"[a-z0-9]{2,7}", decoded)
        if decoded.strip() and not is_flag_emoji:
            found.append(HiddenText("unicode_tags", decoded.strip()[:MAX_TEXT], m.start(), m.end()))

    controls = sum(ch in DIRECTION_CONTROLS for ch in message)
    if controls:
        found.append(HiddenText("direction_controls", f"{controls} text-direction control character(s)"))

    for m in _COMMENT.finditer(message):
        inner = m.group(1).strip()
        if _WORDS.search(inner):
            found.append(HiddenText("html_comment", inner[:MAX_TEXT], m.start(), m.end()))

    pushed = _PUSHED.search(message)
    if pushed and message[pushed.end():].strip():
        found.append(HiddenText("pushed_out_of_view", message[pushed.end():].strip()[:MAX_TEXT], pushed.end(), len(message.rstrip())))

    for m in _BASE64.finditer(message):
        decoded = _decode_base64(m.group())
        if decoded:
            found.append(HiddenText("encoded", decoded[:MAX_TEXT], m.start(), m.end()))
    for pattern, decode in ((_ENTITIES, html.unescape), (_PERCENT, unquote)):
        for m in pattern.finditer(message):
            decoded = decode(m.group())
            if _readable(decoded):
                found.append(HiddenText("encoded", decoded.strip()[:MAX_TEXT], m.start(), m.end()))
    return found
