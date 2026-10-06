"""Tiny language heuristic: is this message Turkish?

Used to keep the English-only text classifier from scoring Turkish messages.
It only needs to separate Turkish from English, so it looks for letters that
are specific to Turkish (ğ, ı, ş, İ) and for very common Turkish words, which
also catches messages typed without Turkish characters. Words are compared
after folding Turkish letters, so "KİMSEYE" and "kimseye" are the same word.
"""

from __future__ import annotations

import re

from trustgate.rules.lexicons import fold_turkish

_TR_LETTERS = frozenset("ğĞıİşŞ")
_TR_WORDS = frozenset({  # folded: ı/İ→i, ş→s, ğ→g, ç→c, ö→o, ü→u
    "ve", "bir", "bu", "icin", "ile", "cok", "ama", "degil", "mi", "mu", "misin", "musun", "da", "de", "ne", "gibi",
    "daha", "hemen", "lutfen", "sayin", "merhaba", "selam", "anne", "annecim", "baba", "tl", "iban", "hesabiniz",
    "kodu", "kodunuz", "kimseyle", "kimseye", "olarak", "sonra", "simdi", "bana", "sana", "beni", "seni", "acil",
    "musteri", "kargo", "gonderi", "odeme", "tarafindan", "edilmistir", "yapildi", "olan", "var", "yok", "icinde",
    # everyday / colloquial words, often typed without Turkish letters
    "ben", "sen", "biz", "siz", "bize", "size", "bende", "sende", "benim", "senin", "tamam", "evet", "hayir", "nasil",
    "neden", "nerede", "nereye", "yarin", "bugun", "aksam", "sabah", "gel", "geliyor", "geliyorum", "geldim",
    "gidiyorum", "napiyorsun", "naber", "kanka", "abi", "canim", "kuzum", "kardesim", "yani", "hadi", "artik",
    "zaten", "sadece", "herkes", "hep", "hic", "saat", "hala", "iyi", "kadar", "nerdesin", "nerdesiniz", "napiosun",
    "nasilsin", "gunaydin", "tesekkurler", "tesekkur", "ederim", "haber", "cevap", "olur", "oldu", "olabilir",
    "indirim", "hediye", "kampanya", "firsat", "firsati", "gecerli", "ozel", "tum",
})
_WORD = re.compile(r"[^\W\d_]+", re.UNICODE)
# Present-continuous verbs (geliyorum, bekliyor, oluyor) are distinctly Turkish.
_TR_VERB = re.compile(r"\w+[iu]yor\w*")


def is_turkish(text: str) -> bool:
    letters = sum(ch in _TR_LETTERS for ch in text)
    words = [fold_turkish(w).lower() for w in _WORD.findall(text)]
    if not words:
        return False
    hits = len({w for w in words if w in _TR_WORDS or _TR_VERB.fullmatch(w)})  # distinct words
    return letters >= 2 or (letters >= 1 and hits >= 1) or (hits >= 2 and hits / len(words) >= 0.12)
