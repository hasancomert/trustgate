"""Load, normalize, de-duplicate and split the open training corpora.

Label 1 = spam / phishing, label 0 = legitimate. The two sources are:
  * UCI SMS Spam Collection (`ham` / `spam`)
  * zefang-liu/phishing-email-dataset (`Safe Email` / `Phishing Email`)
"""

from __future__ import annotations

import csv
import hashlib
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from trustgate.config import PROJECT_ROOT

RAW_DIR = PROJECT_ROOT / "data" / "raw"
SMS_PATH = RAW_DIR / "sms_spam_collection" / "SMSSpamCollection.tsv"
EMAIL_PATH = RAW_DIR / "phishing_email" / "Phishing_Email.csv"
MAX_CHARS = 5000

_URL = re.compile(r"(https?://\S+|www\.\S+|\b[a-z0-9-]+\.(com|net|org|co|uk|info|biz|ly|xyz|top)(/\S*)?\b)", re.IGNORECASE)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_MONEY = re.compile(r"[$€£₺]\s?\d[\d,.]*|\b\d[\d,.]*\s?(usd|eur|gbp|dollars?|euros?|pounds?)\b", re.IGNORECASE)
_PHONE = re.compile(r"\+?\d[\d\s-]{6,}\d")
_DIGITS = re.compile(r"\d+")
_SPACE_BEFORE_PUNCT = re.compile(r"\s+([,.!?;:'])")
_WS = re.compile(r"\s+")


def preprocess(text: str) -> str:
    """Shared train/inference normalization.

    URLs, emails, amounts and phone numbers become placeholder tokens: the rule
    layer inspects their details, the model only needs to know they are there.
    """
    text = text.lower()
    text = _EMAIL.sub(" emailtoken ", text)  # before URLs, or "a@b.com" would look like a link
    text = _URL.sub(" urltoken ", text)
    text = _MONEY.sub(" moneytoken ", text)
    text = _PHONE.sub(" phonetoken ", text)
    text = _DIGITS.sub("0", text)
    text = _SPACE_BEFORE_PUNCT.sub(r"\1", text)
    return _WS.sub(" ", text).strip()


@dataclass(frozen=True)
class Example:
    text: str
    label: int
    source: str


def load_sms(path: Path = SMS_PATH) -> list[Example]:
    examples = []
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            label, _, text = line.rstrip("\n").partition("\t")
            if label in ("ham", "spam") and text.strip():
                examples.append(Example(text.strip(), int(label == "spam"), "sms"))
    return examples


def load_email(path: Path = EMAIL_PATH) -> list[Example]:
    csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
    examples = []
    with path.open(encoding="utf-8", errors="replace", newline="") as fh:
        for row in csv.DictReader(fh):
            text = (row.get("Email Text") or "").strip()
            kind = row.get("Email Type")
            if not text or text.lower() == "empty" or kind not in ("Safe Email", "Phishing Email"):
                continue
            examples.append(Example(text[:MAX_CHARS], int(kind == "Phishing Email"), "email"))
    return examples


def deduplicate(examples: list[Example]) -> tuple[list[Example], int]:
    """Drop exact duplicates (after normalization) and texts with conflicting labels."""
    by_key: dict[str, list[Example]] = {}
    for ex in examples:
        key = hashlib.sha1(preprocess(ex.text).encode()).hexdigest()
        by_key.setdefault(key, []).append(ex)
    kept = []
    for group in by_key.values():
        if len({ex.label for ex in group}) == 1:
            kept.append(group[0])
    return kept, len(examples) - len(kept)


def load_corpus() -> tuple[list[Example], dict]:
    missing = [p for p in (SMS_PATH, EMAIL_PATH) if not p.exists()]
    if missing:
        raise FileNotFoundError(f"Missing datasets: {', '.join(str(p) for p in missing)}. Run `python scripts/download_data.py` first.")
    raw = load_sms() + load_email()
    corpus, dropped = deduplicate(raw)
    stats = {
        "raw_examples": len(raw),
        "after_dedup": len(corpus),
        "dropped_duplicates_or_conflicts": dropped,
        "by_source_label": {f"{s}:{l}": n for (s, l), n in sorted(Counter((e.source, e.label) for e in corpus).items())},
    }
    return corpus, stats
