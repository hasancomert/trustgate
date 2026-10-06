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
    assert [i["id"] for i in items] == ["dangerous", "suspicious", "safe"]
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
