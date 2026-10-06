"""Layer 3: LLM analyst that weighs all signals and explains them in plain language.

Live mode calls an OpenAI-compatible endpoint and validates the reply against a
schema. Without an API key (or on any error) the layer degrades to `mock` /
`fallback`: the verification still completes from rules + ML, and the report
says which mode produced it.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from trustgate.config import LLMSettings
from trustgate.llm.client import ChatClient, LLMError, OpenAICompatibleClient
from trustgate.llm.prompts import SYSTEM_PROMPT, build_user_prompt
from trustgate.ml import MLPrediction
from trustgate.rules import RuleResult
from trustgate.schemas import RedFlag, ScamType, Severity, VerificationRequest

logger = logging.getLogger(__name__)

CACHE_SIZE = 256


class LLMFlag(BaseModel):
    quote: str = ""
    tactic: str = ""
    why: str = ""


class LLMAnalysis(BaseModel):
    """Schema the model must follow. Lenient on types, strict on ranges."""

    risk_score: int = Field(ge=0, le=100)
    scam_type: ScamType = ScamType.OTHER
    confidence: float = Field(default=0.5, ge=0, le=1)
    summary: str = Field(min_length=1)
    red_flags: list[LLMFlag] = Field(default_factory=list)
    safe_steps: list[str] = Field(default_factory=list)

    @field_validator("risk_score", mode="before")
    @classmethod
    def _clamp_score(cls, v: Any) -> int:
        return max(0, min(100, round(float(v))))

    @field_validator("confidence", mode="before")
    @classmethod
    def _clamp_confidence(cls, v: Any) -> float:
        try:
            return max(0.0, min(1.0, float(v)))
        except (TypeError, ValueError):
            return 0.5

    @field_validator("scam_type", mode="before")
    @classmethod
    def _known_type(cls, v: Any) -> ScamType:
        try:
            return ScamType(str(v).strip().lower())
        except ValueError:
            return ScamType.OTHER

    @field_validator("summary", mode="before")
    @classmethod
    def _trim_summary(cls, v: Any) -> str:
        return str(v).strip()[:700]

    @field_validator("red_flags", mode="before")
    @classmethod
    def _limit_flags(cls, v: Any) -> list:
        return [f for f in (v or []) if isinstance(f, dict)][:6]

    @field_validator("safe_steps", mode="before")
    @classmethod
    def _limit_steps(cls, v: Any) -> list[str]:
        return [str(s).strip()[:240] for s in (v or []) if str(s).strip()][:5]


LLMStatus = Literal["ok", "mock", "fallback"]


@dataclass
class LLMOutcome:
    status: LLMStatus
    model: str | None = None
    analysis: LLMAnalysis | None = None
    grounded_flags: list[RedFlag] = field(default_factory=list)
    detail: str | None = None
    latency_ms: int = 0

    @property
    def score(self) -> float | None:
        return float(self.analysis.risk_score) if self.status == "ok" and self.analysis else None


def ground_flags(message: str, flags: list[LLMFlag]) -> list[RedFlag]:
    """Keep only LLM red flags whose quote really occurs in the message."""
    lowered = message.lower()
    grounded = []
    for flag in flags:
        quote = flag.quote.strip().strip("\"'“”‘’").strip()
        if len(quote) < 4:
            continue
        start = lowered.find(quote.lower())
        if start == -1:
            continue
        tactic = flag.tactic.replace("_", " ").strip()
        grounded.append(RedFlag(
            rule_id="llm.insight", category="llm_insight", severity=Severity.MEDIUM,
            title=(tactic[:1].upper() + tactic[1:] if tactic else "Flagged by AI analyst")[:80],
            explanation=(flag.why.strip() or "The AI analyst considers this phrase manipulative.")[:300],
            evidence=message[start:start + len(quote)], start=start, end=start + len(quote), source="llm",
        ))
    return grounded


class LLMAnalyst:
    def __init__(self, settings: LLMSettings, max_message_chars: int = 6000, client: ChatClient | None = None):
        self.settings = settings
        self.max_message_chars = max_message_chars
        self._client = client
        self._cache: OrderedDict[str, tuple[LLMAnalysis, str]] = OrderedDict()
        self._lock = threading.Lock()

    @property
    def mode(self) -> Literal["live", "mock"]:
        return "live" if (self._client is not None or self.settings.live_enabled) else "mock"

    def _get_client(self) -> ChatClient:
        if self._client is None:
            self._client = OpenAICompatibleClient(self.settings)
        return self._client

    def analyze(self, request: VerificationRequest, rule_result: RuleResult, ml: MLPrediction | None) -> LLMOutcome:
        if self.mode == "mock":
            return LLMOutcome(status="mock", detail="No LLM API key configured; explanation generated from rule signals.")

        user_prompt = build_user_prompt(request, rule_result, ml, self.max_message_chars)
        key = hashlib.sha256(f"{self.settings.model}\n{SYSTEM_PROMPT}\n{user_prompt}".encode()).hexdigest()
        started = time.perf_counter()
        with self._lock:
            cached = self._cache.get(key)
            if cached:
                self._cache.move_to_end(key)
        if cached:
            analysis, model = cached
            return LLMOutcome(status="ok", model=model, analysis=analysis, grounded_flags=ground_flags(request.message, analysis.red_flags), detail="cached")

        try:
            client = self._get_client()
            raw = client.complete_json(SYSTEM_PROMPT, user_prompt)
            analysis = LLMAnalysis.model_validate(raw)
        except (LLMError, ValueError) as exc:
            logger.warning("LLM analysis failed (%s); falling back to rule-based explanation.", type(exc).__name__)
            return LLMOutcome(status="fallback", detail=f"LLM unavailable ({type(exc).__name__}); explanation generated from rule signals.",
                              latency_ms=int((time.perf_counter() - started) * 1000))

        with self._lock:
            self._cache[key] = (analysis, client.model)
            while len(self._cache) > CACHE_SIZE:
                self._cache.popitem(last=False)
        return LLMOutcome(
            status="ok", model=client.model, analysis=analysis,
            grounded_flags=ground_flags(request.message, analysis.red_flags),
            latency_ms=int((time.perf_counter() - started) * 1000),
        )
