"""Provider-agnostic, OpenAI-compatible chat client returning parsed JSON."""

from __future__ import annotations

import json
import re
from typing import Protocol

from trustgate.config import LLMSettings

# Some deployments put credentials on an egress proxy instead of the app; the
# OpenAI SDK still requires a non-empty key, so a placeholder is sent then.
PLACEHOLDER_API_KEY = "sk-placeholder-injected-upstream"

_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE)


class LLMError(RuntimeError):
    pass


class ChatClient(Protocol):
    model: str

    def complete_json(self, system: str, user: str) -> dict: ...


def extract_json(text: str) -> dict:
    """Parse a JSON object from a model reply, tolerating code fences and chatter."""
    cleaned = _FENCE.sub("", text.strip())
    try:
        value = json.loads(cleaned)
    except json.JSONDecodeError:
        start, end = cleaned.find("{"), cleaned.rfind("}")
        if start == -1 or end <= start:
            raise LLMError("model reply contained no JSON object") from None
        try:
            value = json.loads(cleaned[start:end + 1])
        except json.JSONDecodeError as exc:
            raise LLMError(f"model reply was not valid JSON: {exc}") from None
    if not isinstance(value, dict):
        raise LLMError("model reply JSON was not an object")
    return value


class OpenAICompatibleClient:
    def __init__(self, settings: LLMSettings):
        from openai import OpenAI

        self.model = settings.model
        self.settings = settings
        self._client = OpenAI(
            base_url=settings.base_url,
            api_key=settings.api_key or PLACEHOLDER_API_KEY,
            timeout=settings.timeout_seconds,
            max_retries=1,
        )

    def complete_json(self, system: str, user: str) -> dict:
        try:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
                temperature=self.settings.temperature,
                max_tokens=self.settings.max_tokens,
                response_format={"type": "json_object"},
            )
        except Exception as exc:  # network, auth, rate limit, timeout...
            raise LLMError(f"{type(exc).__name__}: {exc}") from exc
        if not response.choices:
            raise LLMError("empty completion")
        return extract_json(response.choices[0].message.content or "")
