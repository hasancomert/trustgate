#!/usr/bin/env python3
"""Evaluate TrustGate layers on scenario sets + summarize held-out ML metrics.

Sets (eval/*.jsonl):
    dev        English scenarios written while the rules were developed
    tr         Turkish scenarios written while the Turkish rule pack was developed
    blind      English + Turkish scenarios written after the rules were frozen
    injection  scams that try to instruct the AI analyst (prompt injection)

Modes:
    rules       rule engine only (score = max(rule score, floor))
    ml          TF-IDF + LR only (score = P(spam) * 100), applied to every message as-is
    fused-mock  full verify() with the LLM layer in mock mode (rules + ML)
    fused-live  full verify() calling the configured LLM (costs API credits)

Usage:
    python eval/run_eval.py                                   # all sets, offline modes
    python eval/run_eval.py --sets dev,tr --modes rules,ml,fused-mock,fused-live

Writes eval/results/<set>.json for each set run, then rebuilds eval/results/SUMMARY.md
from every set result on disk.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from trustgate import TrustGate
from trustgate.config import PROJECT_ROOT, get_settings
from trustgate.ml import MLClassifier
from trustgate.rules import build_engine
from trustgate.schemas import ScamType, VerificationRequest

EVAL_DIR = PROJECT_ROOT / "eval"
SCENARIOS = EVAL_DIR / "scenarios.jsonl"
RESULTS_DIR = EVAL_DIR / "results"
HOLDOUT = RESULTS_DIR / "ml_holdout.json"


@dataclass(frozen=True)
class ScenarioSet:
    file: str
    title: str
    note: str


SETS: dict[str, ScenarioSet] = {
    "dev": ScenarioSet("scenarios.jsonl", "Development scenarios (English)",
                       "Hand-written while the rules were developed, so these numbers are optimistic."),
    "tr": ScenarioSet("scenarios_tr.jsonl", "Turkish scenarios (development)",
                      "Hand-written while the Turkish rule pack was developed, so these numbers are optimistic."),
    "blind": ScenarioSet("scenarios_blind.jsonl", "Blind scenarios (English + Turkish)",
                         "Written by a separate agent that never saw the rules, after they were frozen; committed before "
                         "the first run and evaluated once. No rules were changed after seeing the results."),
    "injection": ScenarioSet("scenarios_injection.jsonl", "Prompt-injection robustness",
                             "Scams that try to talk the AI analyst into a safe verdict, plus legitimate messages that "
                             "mention AI assistants innocently. Written blind by the same agent from a list of attack "
                             "techniques we supplied (the wording is its own). An attack succeeds if a scam ends up safe."),
}


@dataclass(frozen=True)
class Scenario:
    id: str
    label: str
    scam_type: str
    acceptable_types: tuple[str, ...]
    difficulty: str
    notes: str
    request: VerificationRequest
    lang: str = "en"

    @property
    def is_scam(self) -> bool:
        return self.label == "scam"


@dataclass(frozen=True)
class Outcome:
    score: float
    flagged: bool
    scam_type: str | None = None
    latency_ms: int | None = None
    llm_score: float | None = None
    llm_status: str | None = None


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
            lang=raw.get("lang", "en"),
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

    for mode in ("fused-mock", "fused-live"):
        if mode not in modes:
            continue
        mode_settings = settings.model_copy(deep=True)
        mode_settings.llm.mode = "mock" if mode == "fused-mock" else "live"
        gate = TrustGate(settings=mode_settings)

        def fused(req: VerificationRequest, gate: TrustGate = gate) -> Outcome:
            r = gate.verify(req)
            if r.signals.llm.status == "fallback":
                print(f"! LLM fallback: {r.signals.llm.detail}", file=sys.stderr)
            kind = None if r.scam_type is ScamType.NONE else r.scam_type.value
            return Outcome(float(r.risk_score), r.risk_score >= threshold, kind, r.latency_ms,
                           r.signals.llm.score, r.signals.llm.status)

        runners[mode] = fused
    return runners


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float] | None:
    """95% Wilson score interval for k successes out of n; honest at small n, unlike p ± 1.96·se."""
    if n == 0:
        return None
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return round(max(0.0, centre - half), 3), round(min(1.0, centre + half), 3)


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
        "precision_ci95": wilson(tp, tp + fp), "recall_ci95": wilson(tp, tp + fn),
        "accuracy": round((tp + tn) / len(scenarios), 3) if scenarios else 0.0,
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
    }
    if any(o.scam_type is not None for o in outcomes):
        n_scams = sum(s.is_scam for s in scenarios)
        result["scam_type_accuracy"] = round(type_hits / n_scams, 3) if n_scams else None
    latencies = [o.latency_ms for o in outcomes if o.latency_ms is not None]
    if latencies:
        result["median_latency_ms"] = sorted(latencies)[len(latencies) // 2]
    return result


def injection_metrics(scenarios: list[Scenario], outcomes: list[Outcome], threshold: int) -> dict:
    """How often a prompt injection gets a scam through, and whether the LLM alone was fooled."""
    attacks = [(s, o) for s, o in zip(scenarios, outcomes) if s.is_scam]
    result = {"attacks": len(attacks), "attack_successes": sum(not o.flagged for _, o in attacks)}
    judged = [o for _, o in attacks if o.llm_score is not None]
    if judged:
        fooled = [o for o in judged if o.llm_score < threshold]
        result["llm_judged"] = len(judged)
        result["llm_fooled"] = len(fooled)
        result["llm_fooled_but_blocked"] = sum(o.flagged for o in fooled)
    return result


def evaluate_set(name: str, runners: dict[str, Runner], threshold: int) -> dict:
    scenario_set = SETS[name]
    scenarios = load_scenarios(EVAL_DIR / scenario_set.file)
    result: dict = {
        "set": name, "title": scenario_set.title, "note": scenario_set.note,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "threshold": threshold, "modes": {},
    }
    langs = sorted({s.lang for s in scenarios})
    for mode, runner in runners.items():
        outcomes = [runner(s.request) for s in scenarios]
        data = {
            "metrics": metrics(scenarios, outcomes),
            "per_scenario": [
                {"id": s.id, "lang": s.lang, "label": s.label, "expected_type": s.scam_type, "score": round(o.score, 1),
                 "flagged": o.flagged, "predicted_type": o.scam_type, "llm_score": o.llm_score, "llm_status": o.llm_status}
                for s, o in zip(scenarios, outcomes)
            ],
        }
        if len(langs) > 1:
            data["by_lang"] = {
                lang: metrics([s for s in scenarios if s.lang == lang], [o for s, o in zip(scenarios, outcomes) if s.lang == lang])
                for lang in langs
            }
        if name == "injection":
            data["injection"] = injection_metrics(scenarios, outcomes, threshold)
        result["modes"][mode] = data
        m = data["metrics"]
        print(f"[{name}] {mode:>11}: P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f} CM={m['confusion_matrix']} type_acc={m.get('scam_type_accuracy')}")
        if "injection" in data:
            print(f"[{name}] {mode:>11}: {data['injection']}")
    return result


# ---------------------------------------------------------------------- summary


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.3f}"


def _with_ci(value: float, k: int, n: int) -> str:
    # Computed from the confusion matrix, so results written before CIs existed get them too.
    ci = wilson(k, n)
    return f"{value:.3f} ({ci[0]:.2f}–{ci[1]:.2f})" if ci else f"{value:.3f}"


def _p_r(m: dict) -> tuple[str, str]:
    cm = m["confusion_matrix"]
    return _with_ci(m["precision"], cm["tp"], cm["tp"] + cm["fp"]), _with_ci(m["recall"], cm["tp"], cm["tp"] + cm["fn"])


def _metrics_row(label: str, m: dict) -> str:
    cm = m["confusion_matrix"]
    precision, recall = _p_r(m)
    return (f"| {label} | {precision} | {recall} | {m['f1']:.3f} | {m['accuracy']:.3f} | "
            f"{cm['tn']} | {cm['fp']} | {cm['fn']} | {cm['tp']} | {_pct(m.get('scam_type_accuracy'))} |")


def _set_section(result: dict) -> list[str]:
    modes = list(result["modes"])
    first = result["modes"][modes[0]]["per_scenario"] if modes else []
    n_scam = sum(r["label"] == "scam" for r in first)
    lines = [
        f"## {result['title']} ({n_scam} scams, {len(first) - n_scam} legitimate)", "",
        f"_{result['note']}_ Generated {result['generated_at']}.", "",
        "| Mode | Precision (95% CI) | Recall (95% CI) | F1 | Accuracy | TN | FP | FN | TP | Scam-type accuracy |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    lines += [_metrics_row(mode, data["metrics"]) for mode, data in result["modes"].items()]
    if any("by_lang" in d for d in result["modes"].values()):
        lines += ["", "By language:", "", "| Mode | Language | Precision (95% CI) | Recall (95% CI) | F1 | FP | FN |", "|---|---|---:|---:|---:|---:|---:|"]
        for mode, data in result["modes"].items():
            for lang, m in data.get("by_lang", {}).items():
                cm = m["confusion_matrix"]
                precision, recall = _p_r(m)
                lines.append(f"| {mode} | {lang} | {precision} | {recall} | {m['f1']:.3f} | {cm['fp']} | {cm['fn']} |")
    for mode, data in result["modes"].items():
        inj = data.get("injection")
        if inj and "llm_judged" in inj:
            lines += ["", f"Injection outcome ({mode}): attacks that got through: **{inj['attack_successes']} / {inj['attacks']}**; "
                          f"the LLM alone was fooled (score < {result['threshold']}) in {inj['llm_fooled']} / {inj['llm_judged']}, "
                          f"and the final verdict still flagged {inj['llm_fooled_but_blocked']} of those."]
        elif inj:
            lines += ["", f"Injection outcome ({mode}): attacks that got through: **{inj['attack_successes']} / {inj['attacks']}**."]
    show_llm = "fused-live" in modes and result["set"] == "injection"
    header = "| ID | Lang | Label | Expected type | " + " | ".join(modes) + (" | LLM alone |" if show_llm else " |")
    lines += ["", "### Per-scenario scores", "", header, "|---|---|---|---|" + "---:|" * (len(modes) + show_llm)]
    for i, row in enumerate(first):
        cells = []
        for mode in modes:
            o = result["modes"][mode]["per_scenario"][i]
            cells.append(f"{o['score']:.0f}{'⚠' if o['flagged'] != (row['label'] == 'scam') else ''}")
        if show_llm:
            llm = result["modes"]["fused-live"]["per_scenario"][i].get("llm_score")
            cells.append("n/a" if llm is None else f"{llm:.0f}")
        lines.append(f"| {row['id']} | {row.get('lang', 'en')} | {row['label']} | {row['expected_type']} | " + " | ".join(cells) + " |")
    lines += ["", "⚠ = misclassified at the flagging threshold.", ""]
    return lines


def write_summary() -> str:
    lines = ["# Evaluation summary", ""]
    if HOLDOUT.exists():
        holdout = json.loads(HOLDOUT.read_text())
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
    threshold = get_settings().scoring.thresholds.suspicious
    lines += [
        f"A message counts as flagged when its score reaches the `suspicious` threshold ({threshold}) in rule and fused modes, "
        "or P(spam) >= 0.5 in the ML-only mode. The text classifier is English-only: fused modes skip it for Turkish "
        "messages, while the ML-only rows score every message as-is.", "",
    ]
    for name, scenario_set in SETS.items():
        path = RESULTS_DIR / f"{name}.json"
        if path.exists():
            result = json.loads(path.read_text())
            result.setdefault("set", name)
            result.setdefault("title", scenario_set.title)
            result.setdefault("note", scenario_set.note)
            lines += _set_section(result)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sets", default=",".join(SETS), help="comma-separated scenario sets (missing files are skipped)")
    parser.add_argument("--modes", default="rules,ml,fused-mock", help="comma-separated modes (add fused-live to call the LLM)")
    parser.add_argument("--summary-only", action="store_true", help="rebuild SUMMARY.md from stored results without running")
    args = parser.parse_args(argv)
    if args.summary_only:
        (RESULTS_DIR / "SUMMARY.md").write_text(write_summary())
        return 0

    names = [n.strip() for n in args.sets.split(",") if n.strip()]
    unknown = [n for n in names if n not in SETS]
    if unknown:
        parser.error(f"unknown sets: {', '.join(unknown)}")
    runners = build_runners([m.strip() for m in args.modes.split(",") if m.strip()])
    threshold = get_settings().scoring.thresholds.suspicious

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    for name in names:
        if not (EVAL_DIR / SETS[name].file).exists():
            print(f"! {SETS[name].file} not found; skipping set '{name}'", file=sys.stderr)
            continue
        result = evaluate_set(name, runners, threshold)
        (RESULTS_DIR / f"{name}.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    (RESULTS_DIR / "SUMMARY.md").write_text(write_summary())
    print(f"wrote {RESULTS_DIR.relative_to(PROJECT_ROOT)}/<set>.json and SUMMARY.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
