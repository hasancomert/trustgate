"""Train the TF-IDF + Logistic Regression baseline and report held-out metrics.

Usage:
    python -m trustgate.ml.train            # train with the default C
    python -m trustgate.ml.train --tune     # pick C on a validation split first
"""

from __future__ import annotations

import argparse
import json
import platform
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline

from trustgate.config import PROJECT_ROOT, get_settings
from trustgate.ml.dataset import Example, load_corpus, preprocess

SEED = 42
TEST_SIZE = 0.2
DEFAULT_C = 16.0  # best validation F1 in the --tune grid
C_GRID = (1.0, 4.0, 8.0, 16.0)
HOLDOUT_REPORT = PROJECT_ROOT / "eval" / "results" / "ml_holdout.json"


def build_pipeline(c: float = DEFAULT_C) -> Pipeline:
    word = TfidfVectorizer(
        preprocessor=preprocess, ngram_range=(1, 2), min_df=2, max_df=0.95,
        sublinear_tf=True, max_features=60_000, token_pattern=r"(?u)\b\w\w+\b",
    )
    char = TfidfVectorizer(
        preprocessor=preprocess, analyzer="char_wb", ngram_range=(3, 5), min_df=3,
        sublinear_tf=True, max_features=60_000,
    )
    return Pipeline([
        ("features", FeatureUnion([("word", word), ("char", char)])),
        ("clf", LogisticRegression(C=c, class_weight="balanced", max_iter=3000, solver="liblinear", random_state=SEED)),
    ])


def binary_metrics(y_true: list[int], y_pred: list[int], y_score: list[float] | None = None) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    out = {
        "n": len(y_true),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }
    if y_score is not None and len(set(y_true)) == 2:
        out["roc_auc"] = round(float(roc_auc_score(y_true, y_score)), 4)
    return out


def evaluate(pipeline: Pipeline, examples: list[Example]) -> dict:
    texts = [e.text for e in examples]
    y = [e.label for e in examples]
    proba = pipeline.predict_proba(texts)[:, 1]
    pred = [int(p >= 0.5) for p in proba]
    report = {"overall": binary_metrics(y, pred, list(proba))}
    for source in sorted({e.source for e in examples}):
        idx = [i for i, e in enumerate(examples) if e.source == source]
        report[source] = binary_metrics([y[i] for i in idx], [pred[i] for i in idx], [float(proba[i]) for i in idx])
    return report


def split(examples: list[Example], test_size: float, seed: int) -> tuple[list[Example], list[Example]]:
    strata = [f"{e.source}:{e.label}" for e in examples]
    train, test = train_test_split(examples, test_size=test_size, random_state=seed, stratify=strata)
    return list(train), list(test)


def tune_c(train: list[Example]) -> tuple[float, dict]:
    fit_part, val_part = split(train, test_size=0.15, seed=SEED + 1)
    scores = {}
    for c in C_GRID:
        pipe = build_pipeline(c).fit([e.text for e in fit_part], [e.label for e in fit_part])
        scores[c] = evaluate(pipe, val_part)["overall"]["f1"]
        print(f"  C={c:<5} val F1={scores[c]:.4f}")
    best = max(scores, key=lambda c: scores[c])
    return best, {str(k): v for k, v in scores.items()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train the TrustGate ML baseline.")
    parser.add_argument("--tune", action="store_true", help="choose C on a validation split")
    parser.add_argument("--out", type=Path, default=None, help="model path (default: config ml.model_path)")
    args = parser.parse_args(argv)

    out_path = args.out or get_settings().ml.resolved_model_path()
    started = time.time()
    corpus, stats = load_corpus()
    train, test = split(corpus, TEST_SIZE, SEED)
    print(f"corpus: {stats['after_dedup']} examples ({stats['dropped_duplicates_or_conflicts']} duplicates dropped); train={len(train)} test={len(test)}")

    c, tuning = (tune_c(train) if args.tune else (DEFAULT_C, None))
    pipeline = build_pipeline(c).fit([e.text for e in train], [e.label for e in train])
    report = evaluate(pipeline, test)
    o = report["overall"]
    print(f"held-out: precision={o['precision']} recall={o['recall']} f1={o['f1']} auc={o.get('roc_auc')}")

    meta = {
        "model": "tfidf(word 1-2 + char_wb 3-5) + logistic_regression",
        "C": c,
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "train_seconds": round(time.time() - started, 1),
        "sklearn": sklearn.__version__,
        "python": platform.python_version(),
        "seed": SEED,
        "test_size": TEST_SIZE,
        "data": stats,
        "tuning": tuning,
        "holdout": report,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"pipeline": pipeline, "meta": meta}, out_path, compress=3)
    HOLDOUT_REPORT.parent.mkdir(parents=True, exist_ok=True)
    HOLDOUT_REPORT.write_text(json.dumps({k: v for k, v in meta.items() if k not in ("train_seconds",)}, indent=2) + "\n")
    print(f"saved model -> {out_path} ({out_path.stat().st_size / 1e6:.1f} MB); report -> {HOLDOUT_REPORT.relative_to(PROJECT_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
