import socket

import pytest

from app.checks.reputation import GSB_ENDPOINT


@pytest.fixture(autouse=True)
def _mock_external_network(external_network):
    """Every test in this module talks to mocked RDAP/redirect endpoints."""


RESPONSE_KEYS = {
    "submitted_url",
    "normalized_url",
    "analyzed_at",
    "duration_ms",
    "score",
    "verdict",
    "confidence",
    "safe_browsing",
    "checks",
}


class TestCheckEndpoint:
    async def test_benign_https_url_is_safe(self, client, public_dns) -> None:
        response = await client.post("/api/v1/check", json={"url": "https://github.com/"})
        assert response.status_code == 200
        data = response.json()
        assert set(data) == RESPONSE_KEYS
        assert data["verdict"] == "safe"
        assert data["score"] == 0
        assert all(c["status"] != "triggered" for c in data["checks"])

    async def test_every_check_appears_in_report(self, client, public_dns) -> None:
        response = await client.post("/api/v1/check", json={"url": "https://github.com/"})
        ids = {c["id"] for c in response.json()["checks"]}
        assert {
            "https_scheme",
            "userinfo_trick",
            "ip_address_host",
            "nonstandard_port",
            "excessive_subdomains",
            "url_length_entropy",
            "domain_lexical",
            "punycode_homoglyph",
            "typosquatting",
            "suspicious_tld",
            "url_shortener",
            "keyword_bait",
        } <= ids

    async def test_phishy_url_scores_high(self, client, public_dns) -> None:
        response = await client.post(
            "/api/v1/check",
            json={"url": "http://paypal.com.evil-verify.tk/secure/login"},
        )
        data = response.json()
        assert data["verdict"] in ("suspicious", "dangerous")
        triggered = {c["id"] for c in data["checks"] if c["status"] == "triggered"}
        assert "typosquatting" in triggered
        assert "https_scheme" in triggered
        assert "suspicious_tld" in triggered
        assert "keyword_bait" in triggered

    async def test_private_host_rejected_with_400(self, client) -> None:
        response = await client.post("/api/v1/check", json={"url": "http://localhost:8000/"})
        assert response.status_code == 400
        assert response.json()["detail"]["code"] == "PRIVATE_HOST"

    async def test_bad_scheme_rejected_with_400(self, client) -> None:
        response = await client.post("/api/v1/check", json={"url": "file:///etc/passwd"})
        assert response.status_code == 400
        assert response.json()["detail"]["code"] == "INVALID_SCHEME"

    async def test_unresolvable_host_rejected_with_400(self, client, monkeypatch) -> None:
        def nxdomain(*args, **kwargs):
            raise socket.gaierror("NXDOMAIN")

        monkeypatch.setattr("app.validation.socket.getaddrinfo", nxdomain)
        response = await client.post("/api/v1/check", json={"url": "https://no-such.example/"})
        assert response.status_code == 400
        assert response.json()["detail"]["code"] == "UNRESOLVABLE_HOST"

    async def test_missing_body_rejected_with_422(self, client) -> None:
        assert (await client.post("/api/v1/check", json={})).status_code == 422


class TestSafeBrowsingIntegration:
    async def test_gsb_hit_forces_dangerous_verdict(
        self, external_network, gsb_key, client, public_dns
    ) -> None:
        external_network.post(GSB_ENDPOINT).respond(
            json={"matches": [{"threatType": "SOCIAL_ENGINEERING"}]}
        )
        response = await client.post("/api/v1/check", json={"url": "https://phish-site.com/"})
        data = response.json()
        assert data["verdict"] == "dangerous"
        assert data["score"] >= 95
        assert data["safe_browsing"]["status"] == "hit"
        assert data["confidence"] == "full"

    async def test_gsb_clear_leaves_heuristic_verdict(
        self, external_network, gsb_key, client, public_dns
    ) -> None:
        external_network.post(GSB_ENDPOINT).respond(json={})
        response = await client.post("/api/v1/check", json={"url": "https://github.com/"})
        data = response.json()
        assert data["verdict"] == "safe"
        assert data["safe_browsing"]["status"] == "clear"
        assert data["confidence"] == "full"

    async def test_network_checks_appear_in_report(
        self, external_network, gsb_key, client, public_dns
    ) -> None:
        external_network.post(GSB_ENDPOINT).respond(json={})
        response = await client.post("/api/v1/check", json={"url": "https://github.com/"})
        ids = {c["id"] for c in response.json()["checks"]}
        assert {"safe_browsing", "domain_age", "redirect_chain"} <= ids


class TestHardening:
    async def test_security_headers_on_all_responses(self, client, public_dns) -> None:
        response = await client.post("/api/v1/check", json={"url": "https://github.com/"})
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert response.headers["cache-control"] == "no-store"
        assert (await client.get("/healthz")).headers["cache-control"] == "no-store"

    async def test_oversized_body_rejected_before_parsing(self, client) -> None:
        body = b'{"url":"https://example.com/","pad":"' + b"y" * 5000 + b'"}'
        response = await client.post("/api/v1/check", content=body)
        assert response.status_code == 413
        assert response.json()["detail"]["code"] == "BODY_TOO_LARGE"

    async def test_api_docs_hidden_by_default(self, client) -> None:
        assert (await client.get("/docs")).status_code == 404
        assert (await client.get("/redoc")).status_code == 404
        assert (await client.get("/openapi.json")).status_code == 404

    async def test_api_docs_optional_via_env(self, fresh_app_client) -> None:
        exposed = await fresh_app_client({"EXPOSE_API_DOCS": "true"})
        assert (await exposed.get("/docs")).status_code == 200
        assert (await exposed.get("/openapi.json")).status_code == 200

    async def test_forged_xff_ignored_without_proxy_signal(self, fresh_app_client) -> None:
        app_client = await fresh_app_client({"RATE_LIMIT_PER_MINUTE": "1"})
        first = await app_client.post(
            "/api/v1/check",
            json={"url": "https://a.com/"},
            headers={"X-Forwarded-For": "1.2.3.4"},
        )
        second = await app_client.post(
            "/api/v1/check",
            json={"url": "https://b.com/"},
            headers={"X-Forwarded-For": "5.6.7.8"},
        )
        assert first.status_code == 200
        # no proxy https signal -> both map to the same peer IP -> 429
        assert second.status_code == 429

    async def test_forwarded_ip_used_behind_proxy(self, fresh_app_client) -> None:
        app_client = await fresh_app_client({"RATE_LIMIT_PER_MINUTE": "1"})
        first = await app_client.post(
            "/api/v1/check",
            json={"url": "https://c.com/"},
            headers={"X-Forwarded-For": "9.9.9.9", "X-Forwarded-Proto": "https"},
        )
        second = await app_client.post(
            "/api/v1/check",
            json={"url": "https://d.com/"},
            headers={"X-Forwarded-For": "8.8.8.8", "X-Forwarded-Proto": "https"},
        )
        assert first.status_code == 200
        assert second.status_code == 200  # distinct forwarded IPs, distinct buckets
