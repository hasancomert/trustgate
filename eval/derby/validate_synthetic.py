"""Mechanical checks on the blind synthetic set, then write eval/derby/synthetic_set.jsonl.

Only mechanical properties are checked, never the content or the labels:
  * every line parses and every request validates against the production schema
  * the requested distribution (language x label, channels, payment, bank-detail changes,
    links, AI-agent cases) is met
  * no real brand from TrustGate's reference list appears (all names must be fictional)
  * no case duplicates or nearly duplicates a training text or an earlier eval scenario

    python eval/derby/validate_synthetic.py <synthetic_en.jsonl> <synthetic_tr.jsonl>
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

from build_real_set import NEAR_DUP_JACCARD, NearDupIndex  # noqa: E402
from trustgate.ml.dataset import load_email, load_sms  # noqa: E402
from trustgate.rules.lexicons import BRANDS, fold_turkish  # noqa: E402
from trustgate.schemas import VerificationRequest  # noqa: E402

BANK_CHANGE = re.compile(r"(bank|iban|account|hesap)[_ a-z]*(change|new|update|degis|yeni)|(change|new|update|yeni|degis)[_ a-z]*(bank|iban|account|hesap)", re.I)


def brand_hits(text: str) -> list[str]:
    folded = fold_turkish(text.lower())
    hits = []
    for brand in BRANDS:
        name = fold_turkish(brand.name.lower())
        if re.search(rf"(?<![a-z0-9]){re.escape(name)}(?![a-z0-9])", folded):
            hits.append(brand.name)
        for domain in brand.domains:
            if domain.lower() in folded:
                hits.append(domain)
    return hits


def main(paths: list[str]) -> int:
    cases, problems = [], []
    for path in paths:
        for n, line in enumerate(Path(path).read_text(encoding="utf-8").split("\n"), 1):
            if not line.strip():
                continue
            try:
                case = json.loads(line)
                req = dict(case["request"])
                if req.get("initiator") in (None, "user"):
                    req["initiator"] = "human"
                VerificationRequest(**req)
            except Exception as exc:  # report every broken line, keep going
                problems.append(f"{Path(path).name}:{n}: {type(exc).__name__}: {str(exc)[:160]}")
                continue
            cases.append(case)
    ids = [c["id"] for c in cases]
    if len(ids) != len(set(ids)):
        problems.append("duplicate ids")
    for c in cases:
        r = c["request"]
        text = " ".join([r["message"], json.dumps(r.get("sender") or {}), json.dumps(r.get("payment") or {}), " ".join(r.get("urls") or [])])
        hits = brand_hits(text)
        if hits:
            problems.append(f"{c['id']}: real brand names {sorted(set(hits))}")
        if c.get("label") not in ("dangerous", "suspicious", "safe"):
            problems.append(f"{c['id']}: bad label {c.get('label')!r}")

    training = load_sms() + load_email()
    near_train = NearDupIndex([ex.text for ex in training]).max_jaccard([c["request"]["message"] for c in cases])
    scen = []
    for path in sorted((ROOT / "eval").glob("scenarios*.jsonl")):
        scen += [json.loads(l)["request"]["message"] for l in path.read_text().split("\n") if l.strip()]
    near_scen = NearDupIndex(scen).max_jaccard([c["request"]["message"] for c in cases])
    for c, jt, js in zip(cases, near_train, near_scen):
        if jt >= NEAR_DUP_JACCARD or js >= NEAR_DUP_JACCARD:
            problems.append(f"{c['id']}: near duplicate (training {jt:.2f}, earlier scenarios {js:.2f})")

    print(f"{len(cases)} cases")
    print("lang x label:", dict(Counter((c["lang"], c["label"]) for c in cases)))
    print("lang x channel:", dict(Counter((c["lang"], c["request"]["channel"]) for c in cases)))
    for lang in ("en", "tr"):
        part = [c for c in cases if c["lang"] == lang]
        pay = sum(1 for c in part if c["request"].get("payment"))
        links = sum(1 for c in part if c["request"].get("urls") or re.search(r"https?://|www\.", c["request"]["message"]))
        agent = sum(1 for c in part if c["request"].get("initiator") == "ai_agent")
        bank = Counter(c["label"] for c in part if BANK_CHANGE.search(c.get("scenario", "")))
        print(f"  {lang}: payment {pay}, links {links}, ai_agent {agent}, bank-detail scenarios by label {dict(bank)}")
    print(f"max Jaccard vs training {max(near_train):.2f}, vs earlier scenarios {max(near_scen):.2f}")
    if problems:
        print("PROBLEMS:")
        print("\n".join(f"  {p}" for p in problems))
        return 1
    order = sorted(cases, key=lambda c: c["id"])
    (HERE / "synthetic_set.jsonl").write_text("".join(json.dumps(c, ensure_ascii=False) + "\n" for c in order))
    print(f"wrote {len(order)} cases to eval/derby/synthetic_set.jsonl")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
