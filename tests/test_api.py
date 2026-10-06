import pytest
from fastapi.testclient import TestClient

from app.main import RateLimiter, create_app
from trustgate import TrustGate
from trustgate.llm import LLMAnalyst


def make_client(settings, **limit_overrides) -> TestClient:
    s = settings.model_copy(deep=True)
    for k, v in limit_overrides.items():
        setattr(s.limits, k, v)
    app = create_app(settings=s, gate_factory=lambda: TrustGate(settings=s, ml=None, analyst=LLMAnalyst(s.llm)))
    return TestClient(app)


@pytest.fixture()
def client(settings):
    with make_client(settings) as c:
        yield c


def test_health(client):
    body = client.get("/api/health").json()
    assert body["status"] == "ok"
    assert body["layers"] == {"rules": "ok", "ml": "unavailable", "llm": "mock", "llm_model": None}


def test_verify_roundtrip(client):
    r = client.post("/api/verify", json={
        "message": "Your account will be suspended. Verify your account at http://paypa1.com/login now.",
        "channel": "sms",
        "payment": {"amount": 20, "currency": "usd"},
    })
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "dangerous" and body["recommended_action"] == "block"
    assert body["link_findings"][0]["impersonated_brand"] == "PayPal"
    assert {"rules", "ml", "llm"} <= body["signals"].keys()
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]


@pytest.mark.parametrize("payload", [{}, {"message": ""}, {"message": "x", "channel": "fax"}, {"message": "x", "payment": {"amount": -5}}])
def test_validation_errors(client, payload):
    assert client.post("/api/verify", json=payload).status_code == 422


def test_message_too_long(settings):
    with make_client(settings, max_message_chars=50) as c:
        assert c.post("/api/verify", json={"message": "a" * 51}).status_code == 413


def test_rate_limit(settings):
    with make_client(settings, rate_limit_per_minute=2) as c:
        codes = [c.post("/api/verify", json={"message": "hello"}).status_code for _ in range(3)]
        assert codes == [200, 200, 429]
        assert c.post("/api/verify", json={"message": "hello"}, headers={"X-Forwarded-For": "1.2.3.4"}).status_code == 200


def test_rate_limiter_window():
    limiter = RateLimiter(per_minute=1)
    assert limiter.check("a", now=0) == 0
    assert limiter.check("a", now=10) > 0
    assert limiter.check("a", now=61) == 0
    assert RateLimiter(per_minute=0).check("a") == 0


def test_docs_are_served(client):
    assert client.get("/openapi.json").status_code == 200


def test_examples_are_valid_requests(client):
    from trustgate.schemas import VerificationRequest
    items = client.get("/api/examples").json()
    assert [i["id"] for i in items] == ["dangerous", "suspicious", "safe", "agent", "turkish"]
    assert next(i for i in items if i["id"] == "agent")["request"]["initiator"] == "ai_agent"
    for item in items:
        VerificationRequest.model_validate(item["request"])


def test_demo_examples_produce_their_verdicts_offline(client):
    for item in client.get("/api/examples").json():
        body = client.post("/api/verify", json=item["request"]).json()
        assert body["verdict"] == item["expected"], (item["id"], body["risk_score"])


def test_index_and_static_assets(client):
    r = client.get("/")
    assert r.status_code == 200 and "TrustGate" in r.text
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    for asset in ("/static/app.js", "/static/styles.css", "/static/favicon.svg"):
        assert client.get(asset).status_code == 200


def test_page_and_assets_are_revalidated_after_a_deploy(client):
    for path in ("/", "/static/app.js", "/static/styles.css"):
        assert client.get(path).headers["Cache-Control"] == "no-cache"
    assert "Cache-Control" not in client.get("/api/health").headers


def test_quick_mode_skips_llm_and_has_its_own_rate_limit(settings):
    with make_client(settings, rate_limit_per_minute=1, quick_rate_limit_per_minute=2) as c:
        body = c.post("/api/verify?llm=false", json={"message": "Buy gift cards now and send me the codes."}).json()
        assert body["signals"]["llm"]["status"] == "skipped"
        assert body["verdict"] == "dangerous"
        assert c.post("/api/verify?llm=false", json={"message": "hello"}).status_code == 200
        assert c.post("/api/verify?llm=false", json={"message": "hello"}).status_code == 429
        # Full checks are limited separately.
        assert [c.post("/api/verify", json={"message": "hello"}).status_code for _ in range(2)] == [200, 429]


def test_invalid_requests_are_rejected_without_echoing_the_text(client):
    secret = "my private message to mum"
    r = client.post("/api/verify", json={"message": secret * 1000})  # over the schema's 20,000 characters
    assert r.status_code == 422 and secret not in r.text
    r = client.post("/api/verify", content='{"message": "pay now \\ud800 send the code"}', headers={"content-type": "application/json"})
    assert r.status_code == 422 and r.json()["detail"][0]["loc"] == ["body", "message"]


def test_oversized_bodies_and_urls_are_refused(client):
    r = client.post("/api/verify", content="x" * (200 * 1024), headers={"content-type": "application/json"})
    assert r.status_code == 413
    r = client.post("/api/verify", json={"message": "check this", "urls": ["https://e.example/" + "a" * 3000]})
    assert r.status_code == 422
