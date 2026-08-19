import pytest

from app.rate_limit import RateLimiter


@pytest.fixture(autouse=True)
def _mock_external_network(external_network):
    """Endpoint-level tests inherit RDAD and blanket HEAD mocks via this."""


class TestRateLimiter:
    def test_allows_up_to_limit(self) -> None:
        limiter = RateLimiter(limit=3, window_seconds=60)
        assert limiter.check("1.2.3.4", now=0.0) is None
        assert limiter.check("1.2.3.4", now=1.0) is None
        assert limiter.check("1.2.3.4", now=2.0) is None

    def test_rejects_over_limit_with_retry_after(self) -> None:
        limiter = RateLimiter(limit=2, window_seconds=60)
        limiter.check("1.2.3.4", now=0.0)
        limiter.check("1.2.3.4", now=10.0)
        retry_after = limiter.check("1.2.3.4", now=20.0)
        assert retry_after is not None
        assert retry_after == 40.0  # oldest expires at t=60; current=20 → 40s remaining

    def test_window_slides(self) -> None:
        limiter = RateLimiter(limit=2, window_seconds=60)
        limiter.check("1.2.3.4", now=0.0)
        limiter.check("1.2.3.4", now=1.0)
        assert limiter.check("1.2.3.4", now=61.0) is None

    def test_ips_are_independent(self) -> None:
        limiter = RateLimiter(limit=1, window_seconds=60)
        assert limiter.check("1.2.3.4", now=0.0) is None
        assert limiter.check("5.6.7.8", now=0.0) is None

    def test_tracked_ip_count_is_bounded(self) -> None:
        limiter = RateLimiter(limit=100, window_seconds=60, max_ips=2)
        limiter.check("a", now=0.0)
        limiter.check("b", now=0.0)
        limiter.check("c", now=0.0)  # evicts longest-idle entry
        assert set(limiter._hits) == {"b", "c"}

    def test_reset_clears_history(self) -> None:
        limiter = RateLimiter(limit=3, window_seconds=60)
        limiter.check("y")
        assert limiter.peek("y") is not None
        limiter.reset("y")
        assert limiter.peek("y") is None


class TestRateLimitEndpoint:
    def test_429_after_burst(self, client, public_dns) -> None:
        responses = [
            client.post("/api/v1/check", json={"url": "https://example.com/"})
            for _ in range(11)
        ]
        assert all(r.status_code == 200 for r in responses[:10])
        assert responses[10].status_code == 429
        assert "retry-after" in responses[10].headers

    def test_healthz_is_never_rate_limited(self, client) -> None:
        for _ in range(30):
            assert client.get("/healthz").status_code == 200

    def test_rate_limit_headers_present(self, client, public_dns) -> None:
        resp = client.post("/api/v1/check", json={"url": "https://example.com/"})
        assert resp.status_code == 200
        assert "x-ratelimit-limit" in resp.headers
        assert "x-ratelimit-remaining" in resp.headers
        assert "x-ratelimit-reset" in resp.headers


class TestCors:
    def test_allowed_origin_gets_cors_headers(self, client, public_dns) -> None:
        response = client.post(
            "/api/v1/check",
            json={"url": "https://example.com/"},
            headers={"Origin": "http://localhost:8000"},
        )
        assert response.headers.get("access-control-allow-origin") == "http://localhost:8000"

    def test_unknown_origin_gets_no_cors_headers(self, client, public_dns) -> None:
        response = client.post(
            "/api/v1/check",
            json={"url": "https://example.com/"},
            headers={"Origin": "https://attacker.example"},
        )
        assert "access-control-allow-origin" not in response.headers
