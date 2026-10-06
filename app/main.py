"""HTTP API and single-page UI for TrustGate.

    uvicorn app.main:app --reload

Message contents are never logged; only verdicts, scores and timings are.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from collections.abc import Callable
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.examples import EXAMPLES
from trustgate import TrustGate, __version__
from trustgate.config import Settings, get_settings
from trustgate.schemas import RiskReport, VerificationRequest

logger = logging.getLogger("trustgate.api")
STATIC_DIR = Path(__file__).resolve().parent / "static"

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'",
}


class RateLimiter:
    """Sliding one-minute window per client key, in memory (single instance)."""

    def __init__(self, per_minute: int):
        self.per_minute = per_minute
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str, now: float | None = None) -> int:
        """Return 0 if allowed, otherwise seconds to wait."""
        if self.per_minute <= 0:
            return 0
        now = time.monotonic() if now is None else now
        with self._lock:
            window = self._hits.setdefault(key, deque())
            while window and now - window[0] >= 60:
                window.popleft()
            if len(window) >= self.per_minute:
                return max(1, int(60 - (now - window[0])) + 1)
            window.append(now)
            if len(self._hits) > 10_000:  # drop idle clients
                for k in [k for k, w in self._hits.items() if not w or now - w[-1] >= 60]:
                    del self._hits[k]
            return 0


def client_key(request: Request) -> str:
    # Behind Render's proxy the right-most X-Forwarded-For entry is the address
    # the proxy saw; left-most entries are client-controlled.
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


def create_app(settings: Settings | None = None, gate_factory: Callable[[], TrustGate] | None = None) -> FastAPI:
    settings = settings or get_settings()
    gate_factory = gate_factory or (lambda: TrustGate(settings))
    limiter = RateLimiter(settings.limits.rate_limit_per_minute)
    quick_limiter = RateLimiter(settings.limits.quick_rate_limit_per_minute)
    state: dict[str, TrustGate] = {}

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        state["gate"] = gate_factory()  # load the model once, not on the first request
        logger.info("TrustGate %s ready: %s", __version__, state["gate"].status())
        yield

    app = FastAPI(
        title="TrustGate API",
        version=__version__,
        description="Verify messages, payment requests and links for scam / impersonation risk before money moves.",
        lifespan=lifespan,
    )

    def gate() -> TrustGate:
        if "gate" not in state:  # e.g. used without lifespan
            state["gate"] = gate_factory()
        return state["gate"]

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        if not request.url.path.startswith(("/docs", "/redoc", "/openapi.json")):
            response.headers.update(SECURITY_HEADERS)
        return response

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__, "layers": gate().status()}

    @app.get("/api/examples")
    def examples() -> list[dict]:
        return EXAMPLES

    @app.post("/api/verify", response_model=RiskReport)
    def verify_endpoint(payload: VerificationRequest, request: Request, llm: bool = True) -> RiskReport:
        """Full check. `?llm=false` returns an instant rules + classifier result without the LLM."""
        limits = gate().settings.limits
        if len(payload.message) > limits.max_message_chars:
            raise HTTPException(status_code=413, detail=f"Message is longer than {limits.max_message_chars} characters.")
        if len(payload.urls) > limits.max_urls:
            raise HTTPException(status_code=422, detail=f"At most {limits.max_urls} URLs can be checked at once.")
        retry_after = (limiter if llm else quick_limiter).check(client_key(request))
        if retry_after:
            raise HTTPException(status_code=429, detail="Too many requests, please wait a moment.", headers={"Retry-After": str(retry_after)})

        report = gate().verify(payload, use_llm=llm)
        logger.info(
            "verify id=%s mode=%s verdict=%s score=%d type=%s llm=%s latency_ms=%d",
            report.request_id, "full" if llm else "quick", report.verdict.value, report.risk_score,
            report.scam_type.value, report.signals.llm.status, report.latency_ms,
        )
        return report

    @app.exception_handler(Exception)
    async def unhandled(_: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled error: %s", type(exc).__name__)
        return JSONResponse(status_code=500, content={"detail": "Internal error while verifying. Please try again."})

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

        @app.get("/", include_in_schema=False)
        def index() -> FileResponse:
            return FileResponse(STATIC_DIR / "index.html")

    return app


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
app = create_app()
