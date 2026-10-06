"""Layer 2: statistical text classifier (TF-IDF + Logistic Regression).

It answers a narrow question, "does this read like known spam/phishing?", and
is deliberately only one of three signals. If the model file is missing the
layer reports itself unavailable instead of failing the whole verification.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import joblib
import numpy as np

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MLPrediction:
    probability: float  # P(spam/phishing)
    top_terms: list[str] = field(default_factory=list)

    @property
    def score(self) -> float:
        return round(self.probability * 100.0, 1)


class MLClassifier:
    def __init__(self, pipeline, meta: dict | None = None):
        self.pipeline = pipeline
        self.meta = meta or {}

    @classmethod
    def load(cls, path: Path) -> "MLClassifier | None":
        if not path.exists():
            logger.warning("ML model not found at %s; ML layer disabled. Run `python -m trustgate.ml.train`.", path)
            return None
        try:
            bundle = joblib.load(path)
            return cls(bundle["pipeline"], bundle.get("meta"))
        except Exception:  # corrupted file or incompatible sklearn version
            logger.exception("Could not load ML model from %s; ML layer disabled.", path)
            return None

    def predict(self, text: str, explain: int = 5) -> MLPrediction:
        probability = float(self.pipeline.predict_proba([text])[0, 1])
        return MLPrediction(probability=probability, top_terms=self._top_terms(text, explain) if explain else [])

    def _top_terms(self, text: str, k: int) -> list[str]:
        """Word n-grams in this text that pushed the score up the most."""
        try:
            union = self.pipeline.named_steps["features"]
            word_vec = dict(union.transformer_list)["word"]
            coef = self.pipeline.named_steps["clf"].coef_[0][: len(word_vec.vocabulary_)]
            row = word_vec.transform([text]).tocoo()
            contributions = row.data * coef[row.col]
            order = np.argsort(contributions)[::-1]
            names = word_vec.get_feature_names_out()
            return [str(names[row.col[i]]) for i in order[:k] if contributions[i] > 0]
        except Exception:
            return []
