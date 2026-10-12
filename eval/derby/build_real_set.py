"""Build the real-world part of the Derby test set from data/eval/ (run download_eval_data.py first).

Leakage control, in this order:
  1. Source level: neither source is, or derives from, the classifier's training data.
  2. Exact duplicates: a message whose normalized text (trustgate.ml.dataset.preprocess, the
     same normalization the classifier uses) equals any raw training text is dropped.
  3. Near duplicates: a message whose character-5-gram set has Jaccard similarity >= 0.8 with
     any raw training text, or with any message in our earlier evaluation scenarios, is dropped.
  4. Internal duplicates: only the first copy of a repeated message is kept.

TREC 2007 is sampled, not used whole: rows are shuffled with a fixed seed and taken in order
until 200 spam and 200 legitimate English e-mails have passed every filter. Every Turkish SMS
that passes the filters is used. Messages under 20 characters are skipped: they carry nothing
to verify (in the Turkish set all 99 of them are one-line legitimate replies), so dropping them
makes the false-alarm measurement stricter, not easier.

Writes data/eval/real_set.jsonl (texts, git-ignored) and eval/derby/real_set_index.json
(ids, labels and hashes only, committed).

    python eval/derby/build_real_set.py
"""

from __future__ import annotations

import csv
import hashlib
import json
import random
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from email.utils import parseaddr
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq
from sklearn.feature_extraction.text import HashingVectorizer

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from trustgate.ml.dataset import load_email, load_sms, preprocess  # noqa: E402

EVAL_DATA = ROOT / "data" / "eval"
OUT_TEXTS = EVAL_DATA / "real_set.jsonl"
OUT_INDEX = Path(__file__).resolve().parent / "real_set_index.json"
SEED = 20261012
TREC_PER_LABEL = 200
NEAR_DUP_JACCARD = 0.8
COMPARE_CHARS = 5000  # the classifier's training texts are truncated to 5,000 characters
MIN_CHARS = 20
_STOP = frozenset("the and to of you your is for in this that we with be are on it our have will not or at from".split())

_hasher = HashingVectorizer(analyzer="char", ngram_range=(5, 5), n_features=2**22, binary=True,
                            norm=None, alternate_sign=False, lowercase=False, dtype=np.float32)


def norm(text: str) -> str:
    return preprocess(text[:COMPARE_CHARS])


def key(text: str) -> str:
    return hashlib.sha1(norm(text).encode()).hexdigest()


class NearDupIndex:
    """Exact Jaccard over hashed character 5-gram sets, computed as one sparse product per batch."""

    def __init__(self, texts: list[str]):
        self.matrix = _hasher.transform([norm(t) for t in texts]).tocsr()
        self.sizes = np.asarray(self.matrix.sum(axis=1)).ravel()

    def max_jaccard(self, texts: list[str], batch: int = 200) -> np.ndarray:
        best = np.zeros(len(texts), dtype=np.float32)
        for start in range(0, len(texts), batch):
            query = _hasher.transform([norm(t) for t in texts[start:start + batch]]).tocsr()
            q_sizes = np.asarray(query.sum(axis=1)).ravel()
            inter = (query @ self.matrix.T).tocoo()
            if inter.nnz:
                union = q_sizes[inter.row] + self.sizes[inter.col] - inter.data
                jac = np.divide(inter.data, union, out=np.zeros_like(inter.data), where=union > 0)
                np.maximum.at(best, start + inter.row, jac)
        return best


def is_english(text: str) -> bool:
    letters = [c for c in text if c.isalpha()]
    if not letters or sum(c.isascii() for c in letters) / len(letters) < 0.9:
        return False
    words = re.findall(r"[a-z']+", text.lower())[:300]
    return sum(w in _STOP for w in words) >= max(2, 0.08 * len(words))


def load_turkish_sms() -> list[dict]:
    items = []
    for split in ("train", "validation"):
        for i, row in enumerate(pq.read_table(EVAL_DATA / "turkish_sms" / f"{split}.parquet").to_pylist()):
            items.append({"id": f"trsms-{split}-{i:03d}", "source": "turkish_sms", "lang": "tr", "channel": "sms",
                          "orig_label": row["label"], "message": (row["text"] or "").strip()})
    return items


def trec_rows() -> list[dict]:
    csv.field_size_limit(2**31 - 1)
    with (EVAL_DATA / "trec07" / "TREC_07.csv").open(encoding="utf-8", errors="replace", newline="") as fh:
        return list(csv.DictReader(fh))


def trec_item(index: int, row: dict) -> dict:
    name, address = parseaddr(row.get("sender") or "")
    subject = (row.get("subject") or "").strip()
    body = (row.get("body") or "").strip()
    return {"id": f"trec07-{index:05d}", "source": "trec07", "lang": "en", "channel": "email",
            "orig_label": "spam" if row["label"] == "1" else "legitimate",
            "message": f"Subject: {subject}\n\n{body}" if subject else body,
            "sender": {"display_name": name[:200] or None, "address": address[:320] or None}}


def main() -> int:
    stats: Counter = Counter()
    training = load_sms() + load_email()
    training_keys = {key(ex.text) for ex in training}
    print(f"training texts (raw, before the trainer's de-duplication): {len(training)}", flush=True)
    train_index = NearDupIndex([ex.text for ex in training])
    scenario_texts = []
    for path in sorted((ROOT / "eval").glob("scenarios*.jsonl")):
        scenario_texts += [json.loads(line)["request"]["message"] for line in path.read_text().split("\n") if line.strip()]
    scenario_index = NearDupIndex(scenario_texts)
    seen: set[str] = set()

    def admit(batch: list[dict], prefix: str) -> list[dict]:
        candidates = []
        for item in batch:
            if len(item["message"]) < MIN_CHARS:
                stats[f"{prefix}: dropped, shorter than {MIN_CHARS} characters"] += 1
            elif key(item["message"]) in training_keys:
                stats[f"{prefix}: dropped, exact duplicate of a training text"] += 1
            elif key(item["message"]) in seen:
                stats[f"{prefix}: dropped, duplicate inside the test set"] += 1
            else:
                candidates.append(item)
        if not candidates:
            return []
        texts = [c["message"] for c in candidates]
        near_train = train_index.max_jaccard(texts)
        near_scen = scenario_index.max_jaccard(texts)
        kept = []
        for item, jt, js in zip(candidates, near_train, near_scen):
            if jt >= NEAR_DUP_JACCARD:
                stats[f"{prefix}: dropped, near duplicate of a training text"] += 1
            elif js >= NEAR_DUP_JACCARD:
                stats[f"{prefix}: dropped, near duplicate of an earlier eval scenario"] += 1
            elif key(item["message"]) in seen:
                stats[f"{prefix}: dropped, duplicate inside the test set"] += 1
            else:
                seen.add(key(item["message"]))
                item["max_train_jaccard"] = round(float(jt), 3)
                kept.append(item)
        return kept

    tr_sms = load_turkish_sms()
    stats["turkish_sms: available"] = len(tr_sms)
    kept_tr = admit(tr_sms, "turkish_sms")

    rows = trec_rows()
    order = list(range(len(rows)))
    random.Random(SEED).shuffle(order)
    stats["trec07: available"] = len(rows)
    kept_trec: list[dict] = []
    quota = {"spam": TREC_PER_LABEL, "legitimate": TREC_PER_LABEL}
    cursor = 0
    while any(quota.values()) and cursor < len(order):
        batch = []
        while len(batch) < 300 and cursor < len(order):
            item = trec_item(order[cursor], rows[order[cursor]])
            cursor += 1
            stats["trec07: examined"] += 1
            if not quota[item["orig_label"]]:
                continue
            if not is_english(item["message"]):
                stats["trec07: dropped, not English"] += 1
                continue
            batch.append(item)
        for item in admit(batch, "trec07"):
            if quota[item["orig_label"]]:
                quota[item["orig_label"]] -= 1
                kept_trec.append(item)
            else:
                stats["trec07: passed the filters after its label's quota was full"] += 1

    items = kept_tr + sorted(kept_trec, key=lambda it: it["id"])
    stats["kept"] = len(items)
    OUT_TEXTS.write_text("".join(json.dumps(it, ensure_ascii=False) + "\n" for it in items))
    index = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "seed": SEED, "near_duplicate_jaccard": NEAR_DUP_JACCARD, "compare_chars": COMPARE_CHARS,
        "training_texts_compared": len(training), "scenario_texts_compared": len(scenario_texts),
        "filters": dict(sorted(stats.items())),
        "counts": {f"{s}:{l}": n for (s, l), n in sorted(Counter((it["source"], it["orig_label"]) for it in items).items())},
        "items": [{"id": it["id"], "source": it["source"], "lang": it["lang"], "channel": it["channel"],
                   "orig_label": it["orig_label"], "chars": len(it["message"]),
                   "sha256": hashlib.sha256(it["message"].encode()).hexdigest(),
                   "max_train_jaccard": it["max_train_jaccard"]} for it in items],
    }
    OUT_INDEX.write_text(json.dumps(index, indent=1, ensure_ascii=False) + "\n")
    for k, v in sorted(stats.items()):
        print(f"  {k}: {v}")
    print("counts:", index["counts"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
