"""Merge the independent labellers' outputs into eval/derby/labels_real.jsonl and score the spot check.

Each labeller saw one batch of real messages (no original dataset labels, no system output) and
returned one label per message. This script checks that every batch is complete and well formed,
writes the merged labels (ids and labels only, no message text), and compares a blind 10% spot
check by the author with the labellers' labels (agreement and Cohen's kappa).

    python eval/derby/merge_labels.py <labelling dir>
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
BATCHES = ("tr_sms_1", "tr_sms_2", "trec_1", "trec_2", "trec_3", "trec_4")
LABELS = ("dangerous", "suspicious", "safe")
REASONS = {"prize", "phishing_link", "advance_fee", "investment", "impersonation", "payment_change", "loan", "job",
           "goods_or_pharma", "gambling", "extortion", "marketing", "personal", "notification", "other"}


def kappa(a: list[str], b: list[str]) -> float:
    n = len(a)
    observed = sum(x == y for x, y in zip(a, b)) / n
    ca, cb = Counter(a), Counter(b)
    expected = sum(ca[k] * cb[k] for k in LABELS) / (n * n)
    return round((observed - expected) / (1 - expected), 3) if expected < 1 else 1.0


def main(lab_dir: Path) -> int:
    merged = []
    for batch in BATCHES:
        inputs = [json.loads(l)["id"] for l in (lab_dir / f"{batch}.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
        outputs = [json.loads(l) for l in (lab_dir / f"out_{batch}.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
        assert [o["id"] for o in outputs] == inputs, f"{batch}: ids missing, extra or out of order"
        for o in outputs:
            assert o["label"] in LABELS, f"{batch}: bad label {o['label']!r}"
            assert o.get("confidence") in ("high", "low"), f"{batch}: bad confidence for {o['id']}"
            assert o.get("reason") in REASONS, f"{batch}: bad reason {o.get('reason')!r}"
            merged.append({"id": o["id"], "label": o["label"], "confidence": o["confidence"], "reason": o["reason"], "batch": batch})
    merged.sort(key=lambda r: r["id"])
    (HERE / "labels_real.jsonl").write_text("".join(json.dumps(r) + "\n" for r in merged))
    print(f"{len(merged)} labels:", dict(Counter(r["label"] for r in merged)))
    for src in ("trsms", "trec07"):
        part = [r for r in merged if r["id"].startswith(src)]
        print(f"  {src}: {dict(Counter(r['label'] for r in part))}, low confidence {sum(r['confidence'] == 'low' for r in part)}")

    spot = json.loads((lab_dir / "spotcheck_mine.json").read_text())
    by_id = {r["id"]: r["label"] for r in merged}
    ids = sorted(spot)
    mine, theirs = [spot[i] for i in ids], [by_id[i] for i in ids]
    agree = sum(a == b for a, b in zip(mine, theirs))
    flag = lambda x: x != "safe"  # noqa: E731
    bin_agree = sum(flag(a) == flag(b) for a, b in zip(mine, theirs))
    report = {
        "spot_check_size": len(ids),
        "exact_agreement": round(agree / len(ids), 3),
        "cohen_kappa_3class": kappa(mine, theirs),
        "binary_agreement_flag_vs_safe": round(bin_agree / len(ids), 3),
        "cohen_kappa_binary": kappa(["safe" if not flag(x) else "dangerous" for x in mine], ["safe" if not flag(x) else "dangerous" for x in theirs]),
        "disagreements": [{"id": i, "author": a, "labeller": b} for i, a, b in zip(ids, mine, theirs) if a != b],
        "by_source": {},
    }
    for src in ("trsms", "trec07"):
        sel = [k for k, i in enumerate(ids) if i.startswith(src)]
        report["by_source"][src] = {"n": len(sel), "exact_agreement": round(sum(mine[k] == theirs[k] for k in sel) / len(sel), 3)}
    (HERE / "label_agreement.json").write_text(json.dumps(report, indent=1) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "disagreements"}, indent=1))
    print("disagreements:", len(report["disagreements"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1])))
