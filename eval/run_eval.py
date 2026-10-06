#!/usr/bin/env python3
"""Evaluate TrustGate layers on hand-written scenarios + summarize held-out ML metrics.

Usage:
    python eval/run_eval.py                 # all offline modes
    python eval/run_eval.py --modes rules,ml

Writes eval/results/scenarios.json and eval/results/SUMMARY.md.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from trustgate.config import PROJECT_ROOT, get_settings
from trustgate.ml import MLClassifier
from trustgate.rules import build_engine
from trustgate.schemas import ScamType, VerificationRequest

EVAL_DIR = PROJECT_ROOT / "eval"
SCENARIOS = EVAL_DIR / "scenarios.jsonl"
RESULTS_DIR = EVAL_DIR / "results"
HOLDOUT = RESULTS_DIR / "ml_holdout.json"


@dataclass(frozen=True)
class Scenario:
    id: str
    label: str
    scam_type: str
    acceptable_types: tuple[str, ...]
    difficulty: str
    notes: str
    request: VerificationRequest

    @property
    def is_scam(self) -> bool:
        return self.label == "scam"


@dataclass(frozen=True)
class Outcome:
    score: float
    flagged: bool
    scam_type: str | None = None


Runner = Callable[[VerificationRequest], Outcome]


def load_scenarios(path: Path = SCENARIOS) -> list[Scenario]:
    scenarios = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        raw = json.loads(line)
        scenarios.append(Scenario(
            id=raw["id"], label=raw["label"], scam_type=raw["scam_type"],
            acceptable_types=tuple(raw.get("acceptable_types", ())), difficulty=raw.get("difficulty", ""),
            notes=raw.get("notes", ""), request=VerificationRequest.model_validate(raw["request"]),
        ))
    return scenarios


def build_runners(modes: list[str]) -> dict[str, Runner]:
    settings = get_settings()
    threshold = settings.scoring.thresholds.suspicious
    runners: dict[str, Runner] = {}

    if "rules" in modes:
        engine = build_engine(settings)

        def rules(req: VerificationRequest) -> Outcome:
            r = engine.analyze(req)
            score = max(r.score, float(r.floor or 0))
            top = r.top_scam_type
            return Outcome(score, score >= threshold, top.value if top else None)

        runners["rules"] = rules

    if "ml" in modes:
        clf = MLClassifier.load(settings.ml.resolved_model_path())
        if clf is None:
            print("! ML model missing; skipping 'ml' mode (run `python -m trustgate.ml.train`).", file=sys.stderr)
        else:
            def ml(req: VerificationRequest) -> Outcome:
                p = clf.predict(req.message, explain=0)
                return Outcome(p.score, p.probability >= 0.5)

            runners["ml"] = ml
    return runners


def metrics(scenarios: list[Scenario], outcomes: list[Outcome]) -> dict:
    tp = sum(s.is_scam and o.flagged for s, o in zip(scenarios, outcomes))
    fp = sum((not s.is_scam) and o.flagged for s, o in zip(scenarios, outcomes))
    fn = sum(s.is_scam and not o.flagged for s, o in zip(scenarios, outcomes))
    tn = sum((not s.is_scam) and not o.flagged for s, o in zip(scenarios, outcomes))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    typed = [(s, o) for s, o in zip(scenarios, outcomes) if s.is_scam and o.scam_type is not None]
    type_hits = sum(o.scam_type in (s.scam_type, *s.acceptable_types) for s, o in typed)
    result = {
        "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
        "accuracy": round((tp + tn) / len(scenarios), 3),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
    }
    if any(o.scam_type is not None for o in outcomes):
        n_scams = sum(s.is_scam for s in scenarios)
        result["scam_type_accuracy"] = round(type_hits / n_scams, 3) if n_scams else None
    return result


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.3f}"


def write_summary(results: dict, scenarios: list[Scenario]) -> str:
    lines = ["# Evaluation summary", "", f"_Generated {results['generated_at']}_", ""]

    holdout = results.get("ml_holdout")
    if holdout:
        lines += [
            "## ML layer: held-out test split", "",
            f"TF-IDF + Logistic Regression (C={holdout['C']}), trained on {holdout['data']['after_dedup']:,} de-duplicated examples, "
            f"{int(holdout['test_size'] * 100)}% stratified hold-out.", "",
            "| Split | n | Precision | Recall | F1 | ROC-AUC | TN | FP | FN | TP |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
        for split in ("overall", "sms", "email"):
            m = holdout["holdout"].get(split)
            if m:
                cm = m["confusion_matrix"]
                lines.append(f"| {split} | {m['n']:,} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m.get('roc_auc', 0):.3f} | {cm['tn']} | {cm['fp']} | {cm['fn']} | {cm['tp']} |")
        lines.append("")

    n_scam = sum(s.is_scam for s in scenarios)
    lines += [
        f"## Hand-written modern scenarios ({n_scam} scams, {len(scenarios) - n_scam} legitimate)", "",
        "A message counts as flagged when its score reaches the `suspicious` threshold "
        f"({results['threshold']}) for rule/fused modes, or P(spam) >= 0.5 for the ML-only mode.", "",
        "| Mode | Precision | Recall | F1 | Accuracy | TN | FP | FN | TP | Scam-type accuracy |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for mode, data in results["modes"].items():
        m = data["metrics"]
        cm = m["confusion_matrix"]
        lines.append(f"| {mode} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m['accuracy']:.3f} | {cm['tn']} | {cm['fp']} | {cm['fn']} | {cm['tp']} | {_pct(m.get('scam_type_accuracy'))} |")

    modes = list(results["modes"])
    lines += ["", "### Per-scenario scores", "", "| ID | Label | Expected type | " + " | ".join(modes) + " |", "|---|---|---|" + "---:|" * len(modes)]
    for i, s in enumerate(scenarios):
        cells = []
        for mode in modes:
            o = results["modes"][mode]["per_scenario"][i]
            mark = "⚠" if o["flagged"] != s.is_scam else ""
            cells.append(f"{o['score']:.0f}{mark}")
        lines.append(f"| {s.id} | {s.label} | {s.scam_type} | " + " | ".join(cells) + " |")
    lines += ["", "⚠ = misclassified at the flagging threshold.", ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--modes", default="rules,ml", help="comma-separated modes")
    args = parser.parse_args(argv)

    scenarios = load_scenarios()
    runners = build_runners([m.strip() for m in args.modes.split(",") if m.strip()])
    results: dict = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "threshold": get_settings().scoring.thresholds.suspicious,
        "modes": {},
    }
    if HOLDOUT.exists():
        results["ml_holdout"] = json.loads(HOLDOUT.read_text())

    for mode, runner in runners.items():
        outcomes = [runner(s.request) for s in scenarios]
        results["modes"][mode] = {
            "metrics": metrics(scenarios, outcomes),
            "per_scenario": [
                {"id": s.id, "label": s.label, "expected_type": s.scam_type, "score": round(o.score, 1), "flagged": o.flagged, "predicted_type": o.scam_type}
                for s, o in zip(scenarios, outcomes)
            ],
        }
        m = results["modes"][mode]["metrics"]
        print(f"{mode:>12}: P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f} CM={m['confusion_matrix']} type_acc={m.get('scam_type_accuracy')}")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "scenarios.json").write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n")
    (RESULTS_DIR / "SUMMARY.md").write_text(write_summary(results, scenarios))
    print(f"wrote {RESULTS_DIR.relative_to(PROJECT_ROOT)}/scenarios.json and SUMMARY.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
