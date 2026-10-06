"""Process-wide cap on live LLM calls.

The demo is public, and the per-client rate limit does not stop a script that
spreads its requests over many addresses from burning the provider's quota or
its concurrency. Past the cap the analyst falls back to the rule-based
explanation, so every check still completes.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable
from typing import Literal

Limit = Literal["minute", "day"]


class CallBudget:
    def __init__(self, per_minute: int, per_day: int, clock: Callable[[], float] = time.time):
        self.per_minute = per_minute  # 0 disables
        self.per_day = per_day  # 0 disables; days are UTC
        self._clock = clock
        self._recent: deque[float] = deque()
        self._day = -1
        self._today = 0
        self._lock = threading.Lock()

    def try_acquire(self) -> Limit | None:
        """Reserve one call. Returns None when allowed, otherwise the limit that was hit."""
        with self._lock:
            now = self._clock()
            while self._recent and now - self._recent[0] >= 60:
                self._recent.popleft()
            day = int(now // 86400)
            if day != self._day:
                self._day, self._today = day, 0
            if self.per_day and self._today >= self.per_day:
                return "day"
            if self.per_minute and len(self._recent) >= self.per_minute:
                return "minute"
            self._recent.append(now)
            self._today += 1
            return None
