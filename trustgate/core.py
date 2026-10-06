"""The single entry point: `verify(request) -> RiskReport`.

Pure Python, no web framework. The HTTP API, the web UI and future payment
flows (e.g. holding a checkout until verification passes) all call this.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid

from trustgate import __version__
from trustgate.config import Settings, get_settings
from trustgate.llm import LLMAnalyst
from trustgate.ml import MLClassifier
from trustgate.rules import build_engine
from trustgate.schemas import RiskReport, VerificationRequest
from trustgate.scoring import ACTIONS, fuse, merge_flags, resolve_scam_type, safe_steps, template_summary, verdict_for

logger = logging.getLogger(__name__)

DISCLAIMER = (
    "TrustGate estimates risk from manipulation tactics, link structure and language patterns. It can be wrong in "
    "both directions and does not try to tell whether a text was written by AI. Always verify payment requests "
    "through a channel you already trust."
)


class TrustGate:
    def __init__(self, settings: Settings | None = None, ml: MLClassifier | None | bool = True, analyst: LLMAnalyst | None = None):
        self.settings = settings or get_settings()
        self.engine = build_engine(self.settings)
        if ml is True:
            ml = MLClassifier.load(self.settings.ml.resolved_model_path())
        self.ml: MLClassifier | None = ml or None
        self.analyst = analyst or LLMAnalyst(self.settings.llm, self.settings.limits.max_message_chars)

    def status(self) -> dict:
        return {
            "rules": "ok",
            "ml": "ok" if self.ml else "unavailable",
            "llm": self.analyst.mode,
            "llm_model": self.settings.llm.model if self.analyst.mode == "live" else None,
        }

    def verify(self, request: VerificationRequest) -> RiskReport:
        started = time.perf_counter()
        limit = self.settings.limits.max_message_chars
        if len(request.message) > limit:
            request = request.model_copy(update={"message": request.message[:limit]})

        rule_result = self.engine.analyze(request)
        ml_prediction = self.ml.predict(request.message) if self.ml else None
        llm = self.analyst.analyze(request, rule_result, ml_prediction)

        score, signals = fuse(self.settings.scoring.weights, rule_result, ml_prediction.score if ml_prediction else None, llm)
        if ml_prediction and ml_prediction.top_terms and ml_prediction.probability >= 0.5:
            signals.ml.detail = "Spam-like terms: " + ", ".join(ml_prediction.top_terms)
        verdict = verdict_for(score, self.settings.scoring.thresholds)
        scam_type = resolve_scam_type(verdict, rule_result, llm)
        flags = merge_flags(rule_result.red_flags, llm.grounded_flags)
        summary = llm.analysis.summary if llm.status == "ok" and llm.analysis else template_summary(verdict, scam_type, flags)

        return RiskReport(
            request_id=uuid.uuid4().hex,
            risk_score=score,
            verdict=verdict,
            recommended_action=ACTIONS[verdict],
            scam_type=scam_type,
            scam_type_label=scam_type.label,
            summary=summary,
            red_flags=flags,
            link_findings=rule_result.link_findings,
            safe_steps=safe_steps(verdict, scam_type, request, llm),
            signals=signals,
            disclaimer=DISCLAIMER,
            engine_version=__version__,
            latency_ms=int((time.perf_counter() - started) * 1000),
        )


_default_gate: TrustGate | None = None
_lock = threading.Lock()


def get_gate() -> TrustGate:
    global _default_gate
    if _default_gate is None:
        with _lock:
            if _default_gate is None:
                _default_gate = TrustGate()
    return _default_gate


def verify(request: VerificationRequest) -> RiskReport:
    """Analyze a message / payment request / link and return a risk report."""
    return get_gate().verify(request)
