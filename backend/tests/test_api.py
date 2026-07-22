import socket

import respx

from app.checks.reputation import GSB_ENDPOINT

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
    def test_benign_https_url_is_safe(self, client, public_dns) -> None:
        response = client.post("/api/v1/check", json={"url": "https://github.com/"})
        assert response.status_code == 200
        data = response.json()
        assert set(data) == RESPONSE_KEYS
        assert data["verdict"] == "safe"
        assert data["score"] == 0
        assert all(c["status"] != "triggered" for c in data["checks"])

    def test_every_check_appears_in_report(self, client, public_dns) -> None:
        response = client.post("/api/v1/check", json={"url": "https://github.com/"})
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

    def test_phishy_url_scores_high(self, client, public_dns) -> None:
        response = client.post(
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

    def test_private_host_rejected_with_400(self, client) -> None:
        response = client.post("/api/v1/check", json={"url": "http://localhost:8000/"})
        assert response.status_code == 400
        assert response.json()["detail"]["code"] == "PRIVATE_HOST"

    def test_bad_scheme_rejected_with_400(self, client) -> None:
        response = client.post("/api/v1/check", json={"url": "file:///etc/passwd"})
        assert response.status_code == 400
        assert response.json()["detail"]["code"] == "INVALID_SCHEME"

    def test_unresolvable_host_rejected_with_400(self, client, monkeypatch) -> None:
        def nxdomain(*args, **kwargs):
            raise socket.gaierror("NXDOMAIN")

        monkeypatch.setattr("app.validation.socket.getaddrinfo", nxdomain)
        response = client.post("/api/v1/check", json={"url": "https://no-such.example/"})
        assert response.status_code == 400
        assert response.json()["detail"]["code"] == "UNRESOLVABLE_HOST"

    def test_missing_body_rejected_with_422(self, client) -> None:
        assert client.post("/api/v1/check", json={}).status_code == 422


class TestSafeBrowsingIntegration:
    @respx.mock
    def test_gsb_hit_forces_dangerous_verdict(self, gsb_key, client, public_dns) -> None:
        respx.post(GSB_ENDPOINT).respond(
            json={"matches": [{"threatType": "SOCIAL_ENGINEERING"}]}
        )
        response = client.post("/api/v1/check", json={"url": "https://phish.example/"})
        data = response.json()
        assert data["verdict"] == "dangerous"
        assert data["score"] >= 95
        assert data["safe_browsing"]["status"] == "hit"
        assert data["confidence"] == "full"

    @respx.mock
    def test_gsb_clear_leaves_heuristic_verdict(self, gsb_key, client, public_dns) -> None:
        respx.post(GSB_ENDPOINT).respond(json={})
        response = client.post("/api/v1/check", json={"url": "https://github.com/"})
        data = response.json()
        assert data["verdict"] == "safe"
        assert data["safe_browsing"]["status"] == "clear"
        assert data["confidence"] == "full"
