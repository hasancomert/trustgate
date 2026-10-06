"""Settings loader: config/settings.toml + environment overrides (.env supported)."""

from __future__ import annotations

import os
import tomllib
from functools import lru_cache
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from pydantic import BaseModel, Field, model_validator

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "settings.toml"


class Weights(BaseModel):
    rules: float = Field(ge=0)
    ml: float = Field(ge=0)
    llm: float = Field(ge=0)

    @model_validator(mode="after")
    def _non_zero(self) -> "Weights":
        if self.rules + self.ml + self.llm <= 0:
            raise ValueError("at least one scoring weight must be positive")
        return self


class Thresholds(BaseModel):
    suspicious: int = Field(ge=0, le=100)
    dangerous: int = Field(ge=0, le=100)

    @model_validator(mode="after")
    def _ordered(self) -> "Thresholds":
        if self.suspicious >= self.dangerous:
            raise ValueError("thresholds.suspicious must be below thresholds.dangerous")
        return self


class ScoringSettings(BaseModel):
    weights: Weights
    thresholds: Thresholds


class RuleFloors(BaseModel):
    high_flag: int = Field(default=0, ge=0, le=100)
    critical_flag: int = Field(ge=0, le=100)
    critical_combo: int = Field(ge=0, le=100)


class RuleSettings(BaseModel):
    severity_points: dict[str, float]
    floors: RuleFloors


class MLSettings(BaseModel):
    model_path: Path

    def resolved_model_path(self) -> Path:
        return self.model_path if self.model_path.is_absolute() else PROJECT_ROOT / self.model_path


LLMMode = Literal["auto", "live", "mock"]


class LLMSettings(BaseModel):
    base_url: str
    model: str
    timeout_seconds: float = Field(gt=0)
    max_tokens: int = Field(gt=0)
    temperature: float = Field(ge=0, le=2)
    api_key: str | None = None
    mode: LLMMode = "auto"
    # Process-wide caps on live calls (0 disables); past them the analyst falls back to rule-based text.
    max_calls_per_minute: int = Field(default=30, ge=0)
    max_calls_per_day: int = Field(default=3000, ge=0)

    @property
    def live_enabled(self) -> bool:
        """`auto` goes live only when a key is configured; otherwise the mock analyst is used."""
        if self.mode == "mock":
            return False
        if self.mode == "live":
            return True
        return bool(self.api_key)


class LimitSettings(BaseModel):
    max_message_chars: int = Field(gt=0)
    max_urls: int = Field(gt=0)
    rate_limit_per_minute: int = Field(default=20, ge=0, description="0 disables rate limiting.")
    quick_rate_limit_per_minute: int = Field(default=60, ge=0, description="Limit for LLM-free quick checks.")


class Settings(BaseModel):
    scoring: ScoringSettings
    rules: RuleSettings
    ml: MLSettings
    llm: LLMSettings
    limits: LimitSettings


def load_settings(path: Path | None = None, env: dict[str, str] | None = None) -> Settings:
    """Read the TOML config and apply environment overrides for the LLM connection."""
    config_path = Path(path or os.environ.get("TRUSTGATE_CONFIG") or DEFAULT_CONFIG_PATH)
    with config_path.open("rb") as fh:
        raw = tomllib.load(fh)

    env = dict(os.environ) if env is None else env
    llm = raw.setdefault("llm", {})
    for env_key, field in (("LLM_BASE_URL", "base_url"), ("LLM_MODEL", "model"), ("LLM_API_KEY", "api_key"), ("LLM_MODE", "mode")):
        value = env.get(env_key, "").strip()
        if value:
            llm[field] = value.lower() if field == "mode" else value
    timeout = env.get("LLM_TIMEOUT_SECONDS", "").strip()
    if timeout:
        llm["timeout_seconds"] = float(timeout)

    return Settings.model_validate(raw)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    load_dotenv(PROJECT_ROOT / ".env", override=False)
    return load_settings()
