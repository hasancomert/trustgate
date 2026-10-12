"""Metrics, tables and charts for the Derby evaluation (reads results/raw_results.jsonl).

Ground truth has three classes: dangerous, suspicious, safe. "Binary" metrics treat a message
as positive when it needs a warning (dangerous or suspicious) and count a layer as flagging it
when that layer's verdict is suspicious or dangerous. Every layer uses the product's thresholds.

    python eval/derby/analyze.py
"""

from __future__ import annotations

import json
import math
import statistics
import sys
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

HERE = Path(__file__).resolve().parent
RESULTS = HERE / "results"
FIGURES = HERE / "figures"
CLASSES = ("dangerous", "suspicious", "safe")
LAYERS = (
    ("rules", "Rules"),
    ("ml", "Text classifier"),
    ("llm_blind", "AI analyst, alone"),
    ("llm", "AI analyst, in the system"),
    ("quick", "Rules + classifier (instant)"),
    ("full", "Full system"),
)
# Reference palette (dataviz skill), validated with scripts/validate_palette.js.
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"
INK, INK2, MUTED, GRID, BASE, SURFACE = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7", "#fcfcfb"
SEQ = ["#f0efec", "#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#104281"]


def verdict_of(row: dict, layer: str) -> str | None:
    if layer == "llm":
        return row["full"]["llm_verdict"] if row["full"]["llm_status"] == "ok" else None
    if layer == "llm_blind":
        return row["llm_blind"].get("verdict") if row["llm_blind"]["status"] == "ok" else None
    return row[layer]["verdict"]


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float] | None:
    if n == 0:
        return None
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return round(max(0.0, centre - half), 3), round(min(1.0, centre + half), 3)


def safe_div(a: float, b: float) -> float | None:
    return round(a / b, 3) if b else None


def layer_metrics(rows: list[dict], layer: str) -> dict:
    pairs = [(r["label"], verdict_of(r, layer)) for r in rows]
    covered = [(t, p) for t, p in pairs if p is not None]
    tp = sum(1 for t, p in covered if t != "safe" and p != "safe")
    fp = sum(1 for t, p in covered if t == "safe" and p != "safe")
    fn = sum(1 for t, p in covered if t != "safe" and p == "safe")
    tn = sum(1 for t, p in covered if t == "safe" and p == "safe")
    precision, recall = safe_div(tp, tp + fp), safe_div(tp, tp + fn)
    f1 = round(2 * precision * recall / (precision + recall), 3) if precision and recall else 0.0 if precision is not None and recall is not None else None
    cm = {t: {p: sum(1 for tt, pp in covered if tt == t and pp == p) for p in CLASSES} for t in CLASSES}
    per_class = {}
    for c in CLASSES:
        ctp = cm[c][c]
        cpred = sum(cm[t][c] for t in CLASSES)
        ctrue = sum(cm[c].values())
        cp, cr = safe_div(ctp, cpred), safe_div(ctp, ctrue)
        per_class[c] = {"precision": cp, "recall": cr, "f1": round(2 * cp * cr / (cp + cr), 3) if cp and cr else 0.0, "support": ctrue}
    present = [c for c in CLASSES if per_class[c]["support"]]
    return {
        "n": len(rows), "covered": len(covered),
        "binary": {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision, "recall": recall, "f1": f1,
                   "false_alarm_rate": safe_div(fp, fp + tn), "precision_ci95": wilson(tp, tp + fp), "recall_ci95": wilson(tp, tp + fn)},
        "three_class": {"confusion": cm, "per_class": per_class,
                        "macro_f1": round(statistics.mean(per_class[c]["f1"] for c in present), 3) if present else None,
                        "exact_accuracy": safe_div(sum(cm[c][c] for c in CLASSES), len(covered))},
    }


def pct(values: list[float], q: float) -> float:
    s = sorted(values)
    return s[min(len(s) - 1, max(0, math.ceil(q * len(s)) - 1))]


def timing(rows: list[dict]) -> dict:
    quick = [r["quick"]["ms"] for r in rows]
    full = [r["full"]["ms"] for r in rows if r["full"]["llm_status"] == "ok"]
    calls = [r["full_call"]["seconds"] * 1000 for r in rows if r.get("full_call") and "seconds" in r["full_call"]]
    def stats(xs: list[float]) -> dict:
        return {"n": len(xs), "mean": round(statistics.mean(xs)), "median": round(statistics.median(xs)), "p95": round(pct(xs, 0.95))} if xs else {"n": 0}
    return {"quick_ms": stats(quick), "full_ms": stats(full), "llm_call_ms": stats(calls)}


def tokens(rows: list[dict]) -> dict:
    out = {}
    for name, getter in (("full", lambda r: r.get("full_call")), ("blind", lambda r: r["llm_blind"].get("call"))):
        calls = [c for c in map(getter, rows) if c and c.get("prompt_tokens") is not None]
        if calls:
            out[name] = {"calls": len(calls), "prompt_mean": round(statistics.mean(c["prompt_tokens"] for c in calls)),
                         "completion_mean": round(statistics.mean(c["completion_tokens"] for c in calls)),
                         "prompt_total": sum(c["prompt_tokens"] for c in calls), "completion_total": sum(c["completion_tokens"] for c in calls)}
    return out


def complementarity(rows: list[dict]) -> dict:
    """How the layers cover each other on messages that need a warning, and on safe ones."""
    pos = [r for r in rows if r["label"] != "safe" and r["full"]["llm_status"] == "ok"]
    neg = [r for r in rows if r["label"] == "safe" and r["full"]["llm_status"] == "ok"]
    flag = lambda r, layer: verdict_of(r, layer) not in (None, "safe")  # noqa: E731
    who = Counter()
    for r in pos:
        rules, ai = flag(r, "rules"), flag(r, "llm")
        who["both" if rules and ai else "rules only" if rules else "AI only" if ai else "neither"] += 1
    return {
        "positives": len(pos), "caught_by": dict(who),
        "ai_rescued": sorted(r["id"] for r in pos if not flag(r, "rules") and flag(r, "full")),
        "rules_held_when_ai_missed": sorted(r["id"] for r in pos if not flag(r, "llm") and flag(r, "full")),
        "classifier_rescued": sorted(r["id"] for r in pos if not flag(r, "rules") and flag(r, "ml") and flag(r, "quick")),
        "full_missed": sorted(r["id"] for r in pos if not flag(r, "full")),
        "false_alarms_full": sorted(r["id"] for r in neg if flag(r, "full")),
        "rule_false_alarms_cleared": sorted(r["id"] for r in neg if flag(r, "rules") and not flag(r, "full")),
    }


SUBSETS = {
    "real": lambda r: r["set"] == "real",
    "real_tr_sms": lambda r: r["set"] == "real" and r["lang"] == "tr",
    "real_en_email": lambda r: r["set"] == "real" and r["lang"] == "en",
    "synthetic": lambda r: r["set"] == "synthetic",
    "synthetic_en": lambda r: r["set"] == "synthetic" and r["lang"] == "en",
    "synthetic_tr": lambda r: r["set"] == "synthetic" and r["lang"] == "tr",
    "synthetic_sms": lambda r: r["set"] == "synthetic" and r["channel"] == "sms",
    "synthetic_whatsapp": lambda r: r["set"] == "synthetic" and r["channel"] == "whatsapp",
    "synthetic_email": lambda r: r["set"] == "synthetic" and r["channel"] == "email",
    "synthetic_payment": lambda r: r["set"] == "synthetic" and r["has_payment"],
    "synthetic_ai_agent": lambda r: r["set"] == "synthetic" and r["initiator"] == "ai_agent",
}


def original_label_view(rows: list[dict]) -> dict:
    """Real data only: how often each layer flags the source dataset's spam vs legitimate messages."""
    out = {}
    for src in ("turkish_sms", "trec07"):
        part = [r for r in rows if r["set"] == "real" and r["source"] == src]
        out[src] = {}
        for orig in ("spam", "legitimate"):
            group = [r for r in part if r["orig_label"] == orig]
            out[src][orig] = {"n": len(group), **{layer: safe_div(sum(1 for r in group if verdict_of(r, layer) not in (None, "safe")),
                                                                  sum(1 for r in group if verdict_of(r, layer) is not None))
                                                  for layer, _ in LAYERS}}
    return out


# ---------------------------------------------------------------------------------------- charts

def _style(ax) -> None:
    ax.set_facecolor(SURFACE)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(BASE)
        ax.spines[side].set_linewidth(0.8)
    ax.tick_params(colors=INK2, labelsize=9, length=0)
    ax.grid(axis="x", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def chart_layers(metrics: dict, path: Path) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.6), sharey=True, facecolor=SURFACE)
    names = [label for _, label in LAYERS]
    for ax, subset, title in zip(axes, ("real", "synthetic"), ("Real messages", "Synthetic messages")):
        _style(ax)
        y = list(range(len(LAYERS)))[::-1]
        for offset, key, color, legend in ((0.19, "precision", BLUE, "Precision"), (-0.19, "recall", ORANGE, "Recall")):
            vals, lo, hi = [], [], []
            for layer, _ in LAYERS:
                b = metrics[subset]["layers"][layer]["binary"]
                v = b[key] or 0.0
                ci = b[f"{key}_ci95"] or (v, v)
                vals.append(v); lo.append(v - ci[0]); hi.append(ci[1] - v)
            ys = [yy + offset for yy in y]
            ax.barh(ys, vals, height=0.34, color=color, label=legend, zorder=2)
            ax.errorbar(vals, ys, xerr=[lo, hi], fmt="none", ecolor=INK2, elinewidth=0.8, capsize=0, zorder=3)
            for v, yy in zip(vals, ys):
                ax.text(min(v, 1.0) + 0.012, yy, f"{v:.2f}", va="center", fontsize=8, color=INK2)
        ax.set_yticks(y, names)
        ax.set_xlim(0, 1.12)
        ax.set_title(f"{title} (n = {metrics[subset]['n']})", loc="left", fontsize=11, color=INK, pad=8)
    axes[0].legend(loc="lower right", frameon=False, fontsize=9)
    fig.suptitle("Precision and recall of each layer: does it flag the messages that need a warning?", x=0.01, ha="left", fontsize=12, color=INK)
    fig.text(0.01, 0.005, "Flag = verdict suspicious or dangerous (score >= 35). Whiskers: 95% Wilson intervals.", fontsize=8, color=MUTED)
    fig.tight_layout(rect=(0, 0.03, 1, 0.94))
    fig.savefig(path, dpi=200, facecolor=SURFACE)
    plt.close(fig)


def chart_confusion(metrics: dict, path: Path) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(10, 4.4), facecolor=SURFACE)
    for ax, subset, title in zip(axes, ("real", "synthetic"), ("Real messages", "Synthetic messages")):
        cm = metrics[subset]["layers"]["full"]["three_class"]["confusion"]
        rows = [c for c in CLASSES if sum(cm[c].values())]
        ax.set_facecolor(SURFACE)
        for i, t in enumerate(rows):
            total = sum(cm[t].values())
            for j, p in enumerate(CLASSES):
                share = cm[t][p] / total if total else 0
                color = SEQ[min(len(SEQ) - 1, int(round(share * (len(SEQ) - 1))))]
                ax.add_patch(plt.Rectangle((j, len(rows) - 1 - i), 0.96, 0.96, color=color))
                ink = SURFACE if share >= 0.55 else INK
                ax.text(j + 0.48, len(rows) - 1 - i + 0.55, f"{cm[t][p]}", ha="center", va="center", fontsize=12, color=ink, weight="bold")
                ax.text(j + 0.48, len(rows) - 1 - i + 0.28, f"{share:.0%} of row", ha="center", va="center", fontsize=7.5, color=ink)
        ax.set_xlim(0, 3); ax.set_ylim(0, len(rows))
        ax.set_xticks([j + 0.48 for j in range(3)], CLASSES, fontsize=9, color=INK2)
        ax.set_yticks([len(rows) - 1 - i + 0.48 for i in range(len(rows))], rows, fontsize=9, color=INK2)
        ax.tick_params(length=0)
        for side in ax.spines.values():
            side.set_visible(False)
        ax.set_xlabel("TrustGate verdict (full system)", fontsize=9, color=INK2)
        ax.set_ylabel("Label", fontsize=9, color=INK2)
        ax.set_title(title, loc="left", fontsize=11, color=INK, pad=8)
    fig.suptitle("Full system, three classes: label vs. verdict", x=0.01, ha="left", fontsize=12, color=INK)
    fig.tight_layout(rect=(0, 0, 1, 0.94))
    fig.savefig(path, dpi=200, facecolor=SURFACE)
    plt.close(fig)


def chart_language(metrics: dict, path: Path) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.6), sharey=True, facecolor=SURFACE)
    names = [label for _, label in LAYERS]
    pairs = (("real", ("real_en_email", "real_tr_sms"), ("English e-mail", "Turkish SMS"), "Real messages"),
             ("synthetic", ("synthetic_en", "synthetic_tr"), ("English", "Turkish"), "Synthetic messages"))
    for ax, (_, subsets, legends, title) in zip(axes, pairs):
        _style(ax)
        y = list(range(len(LAYERS)))[::-1]
        for offset, subset, color, legend in ((0.19, subsets[0], BLUE, legends[0]), (-0.19, subsets[1], ORANGE, legends[1])):
            vals = [metrics[subset]["layers"][layer]["binary"]["f1"] or 0.0 for layer, _ in LAYERS]
            ys = [yy + offset for yy in y]
            ax.barh(ys, vals, height=0.34, color=color, label=legend, zorder=2)
            for v, yy in zip(vals, ys):
                ax.text(v + 0.012, yy, f"{v:.2f}", va="center", fontsize=8, color=INK2)
        ax.set_yticks(y, names)
        ax.set_xlim(0, 1.12)
        ax.set_title(title, loc="left", fontsize=11, color=INK, pad=8)
        ax.legend(loc="lower right", frameon=False, fontsize=9)
    fig.suptitle("F1 by language (flag vs. no flag)", x=0.01, ha="left", fontsize=12, color=INK)
    fig.text(0.01, 0.005, "The text classifier is English-only; in production it is skipped for Turkish messages.", fontsize=8, color=MUTED)
    fig.tight_layout(rect=(0, 0.03, 1, 0.94))
    fig.savefig(path, dpi=200, facecolor=SURFACE)
    plt.close(fig)


def chart_latency(rows: list[dict], path: Path) -> None:
    quick = [r["quick"]["ms"] for r in rows]
    full = [r["full"]["ms"] / 1000 for r in rows if r["full"]["llm_status"] == "ok"]
    fig, axes = plt.subplots(1, 2, figsize=(10, 3.2), facecolor=SURFACE)
    for ax, values, title, unit, color in ((axes[0], quick, "Instant answer (rules + classifier)", "ms", BLUE),
                                           (axes[1], full, "Full answer (with the AI analyst)", "s", ORANGE)):
        _style(ax)
        med, p95 = statistics.median(values), pct(values, 0.95)
        ax.boxplot(values, orientation="horizontal", widths=0.45, showfliers=False, patch_artist=True,
                   boxprops={"facecolor": color, "edgecolor": color, "alpha": 0.85},
                   medianprops={"color": SURFACE, "linewidth": 2}, whiskerprops={"color": INK2}, capprops={"color": INK2})
        ax.set_yticks([])
        ax.set_xlabel(unit, fontsize=9, color=INK2)
        ax.set_title(f"{title}\nmedian {med:,.0f} {unit} · p95 {p95:,.0f} {unit}" if unit == "ms" else
                     f"{title}\nmedian {med:.1f} {unit} · p95 {p95:.1f} {unit}", loc="left", fontsize=10, color=INK)
    fig.text(0.01, 0.005, "Measured from the evaluation machine against the hosted LLM; box = middle half, whiskers = 1.5 IQR.", fontsize=8, color=MUTED)
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    fig.savefig(path, dpi=200, facecolor=SURFACE)
    plt.close(fig)


def chart_complementarity(metrics: dict, path: Path) -> None:
    order = (("both", "Rules and AI", BLUE), ("rules only", "Rules only", ORANGE), ("AI only", "AI analyst only", AQUA), ("neither", "Neither", BASE))
    fig, ax = plt.subplots(figsize=(10, 2.6), facecolor=SURFACE)
    _style(ax)
    ax.grid(False)
    for i, (subset, title) in enumerate((("synthetic", "Synthetic"), ("real", "Real"))):
        comp = metrics[subset]["complementarity"]
        total = comp["positives"] or 1
        left = 0.0
        for key, label, color in order:
            share = comp["caught_by"].get(key, 0) / total
            ax.barh(i, share, left=left, height=0.5, color=color, edgecolor=SURFACE, linewidth=2, label=label if i == 0 else None)
            if share >= 0.06:
                ax.text(left + share / 2, i, f"{comp['caught_by'].get(key, 0)}", ha="center", va="center", fontsize=9,
                        color=SURFACE if color in (BLUE, ORANGE) else INK)
            left += share
        ax.text(1.01, i, f"{title}: {comp['positives']} messages", va="center", fontsize=9, color=INK2)
    ax.set_yticks([])
    ax.set_xlim(0, 1.25)
    ax.set_xticks([0, 0.25, 0.5, 0.75, 1.0], ["0%", "25%", "50%", "75%", "100%"])
    ax.legend(loc="upper center", bbox_to_anchor=(0.42, -0.25), ncol=4, frameon=False, fontsize=9)
    ax.set_title("Messages that need a warning: which layer flagged them?", loc="left", fontsize=12, color=INK, pad=8)
    fig.tight_layout()
    fig.savefig(path, dpi=200, facecolor=SURFACE)
    plt.close(fig)


# ---------------------------------------------------------------------------------------- report

def fmt(v: float | None) -> str:
    return "n/a" if v is None else f"{v:.2f}"


def ci(v: float | None, interval: tuple[float, float] | None) -> str:
    return "n/a" if v is None else f"{v:.2f} ({interval[0]:.2f}–{interval[1]:.2f})" if interval else f"{v:.2f}"


def tables(metrics: dict) -> str:
    out = []
    for subset in SUBSETS:
        m = metrics[subset]
        if not m["n"]:
            continue
        out.append(f"\n### {subset} (n = {m['n']}; labels {m['labels']})\n")
        out.append("| Layer | Precision (95% CI) | Recall (95% CI) | F1 | False-alarm rate | TP | FP | FN | TN | 3-class macro F1 | Exact 3-class accuracy | Covered |")
        out.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
        for layer, label in LAYERS:
            b, t = m["layers"][layer]["binary"], m["layers"][layer]["three_class"]
            out.append(f"| {label} | {ci(b['precision'], b['precision_ci95'])} | {ci(b['recall'], b['recall_ci95'])} | {fmt(b['f1'])} | "
                       f"{fmt(b['false_alarm_rate'])} | {b['tp']} | {b['fp']} | {b['fn']} | {b['tn']} | {fmt(t['macro_f1'])} | {fmt(t['exact_accuracy'])} | "
                       f"{m['layers'][layer]['covered']}/{m['n']} |")
    return "\n".join(out) + "\n"


def confusion_tables(metrics: dict) -> str:
    out = []
    for subset in ("real", "synthetic", "real_tr_sms", "real_en_email", "synthetic_en", "synthetic_tr"):
        for layer, label in LAYERS:
            cm = metrics[subset]["layers"][layer]["three_class"]["confusion"]
            out.append(f"\n**{subset}, {label}** (rows: label, columns: verdict)\n")
            out.append("| | dangerous | suspicious | safe |")
            out.append("|---|---:|---:|---:|")
            for t in CLASSES:
                if sum(cm[t].values()):
                    out.append(f"| {t} | {cm[t]['dangerous']} | {cm[t]['suspicious']} | {cm[t]['safe']} |")
    return "\n".join(out) + "\n"


def main() -> int:
    raw = RESULTS / "raw_results.jsonl"
    if len(sys.argv) > 1:
        raw = Path(sys.argv[1])
    rows = [json.loads(line) for line in raw.read_text(encoding="utf-8").split("\n") if line.strip()]
    metrics: dict = {}
    for name, keep in SUBSETS.items():
        part = [r for r in rows if keep(r)]
        metrics[name] = {"n": len(part), "labels": dict(Counter(r["label"] for r in part)),
                         "layers": {layer: layer_metrics(part, layer) for layer, _ in LAYERS},
                         "complementarity": complementarity(part), "timing": timing(part) if part else {}, "tokens": tokens(part)}
    metrics["all"] = {"n": len(rows), "timing": timing(rows), "tokens": tokens(rows),
                      "retries": sum(r.get("retries", 0) for r in rows),
                      "llm_status": dict(Counter(r["full"]["llm_status"] for r in rows)),
                      "llm_blind_status": dict(Counter(r["llm_blind"]["status"] for r in rows))}
    metrics["original_labels"] = original_label_view(rows)
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "metrics.json").write_text(json.dumps(metrics, indent=1) + "\n")
    (RESULTS / "tables.md").write_text("# Derby evaluation: generated tables\n" + tables(metrics) + "\n## Confusion matrices\n" + confusion_tables(metrics))
    FIGURES.mkdir(exist_ok=True)
    if metrics["real"]["n"] and metrics["synthetic"]["n"]:
        chart_layers(metrics, FIGURES / "layers_precision_recall.png")
        chart_confusion(metrics, FIGURES / "confusion_full_system.png")
        chart_language(metrics, FIGURES / "f1_by_language.png")
        chart_complementarity(metrics, FIGURES / "layer_complementarity.png")
    chart_latency(rows, FIGURES / "latency.png")
    print(json.dumps({k: metrics[k]["layers"]["full"]["binary"] for k in ("real", "synthetic") if metrics[k]["n"]}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
