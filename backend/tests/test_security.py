"""Security-focused regression tests."""

import socket as _socket_mod

import httpx
import pytest
import respx

from app.checks.redirects import check_redirect_chain
from app.validation import validate_url_syntax


@pytest.mark.asyncio
async def test_redirect_downgrade_is_blocked():
    """HTTPS-to-HTTP redirects must be rejected by default.

    Uses the global respx router. Patches DNS so hostname resolution
    returns a public IP.
    """
    import app.validation as val
    original = val.socket.getaddrinfo
    val.socket.getaddrinfo = lambda *a, **kw: [(
        _socket_mod.AF_INET, _socket_mod.SOCK_STREAM, 6, "",
        ("93.184.216.34", 80),
    )]
    try:
        with respx.mock:  # Global router
            respx.head("https://secure.example.com/").respond(
                302, headers={"location": "http://insecure.example.com/"}
            )
            async with httpx.AsyncClient(follow_redirects=False) as http:
                result = await check_redirect_chain(
                    validate_url_syntax("https://secure.example.com/"),
                    http=http,
                )
        assert result.status.value == "triggered"
        assert "downgrade" in (result.evidence or "").lower()
    finally:
        val.socket.getaddrinfo = original


@pytest.mark.asyncio
async def test_https_to_https_redirect_allowed():
    """HTTPS-to-HTTPS redirects should pass through normally."""
    import app.validation as val
    original = val.socket.getaddrinfo
    val.socket.getaddrinfo = lambda *a, **kw: [(
        _socket_mod.AF_INET, _socket_mod.SOCK_STREAM, 6, "",
        ("93.184.216.34", 80),
    )]
    try:
        with respx.mock:  # Global router
            respx.head("https://a.com/").respond(
                301, headers={"location": "https://b.com/"}
            )
            respx.head("https://b.com/").respond(200)
            async with httpx.AsyncClient(follow_redirects=False) as http:
                result = await check_redirect_chain(
                    validate_url_syntax("https://a.com/"),
                    http=http,
                )
        assert result.status.value == "passed"
    finally:
        val.socket.getaddrinfo = original


class TestErrorSanitization:
    def test_400_does_not_leak_traceback(self, strict_client):
        """Validation errors must not include stack traces or file paths."""
        resp = strict_client.post(
            "/api/v1/check", json={"url": "ftp:///etc/passwd"}
        )
        body = resp.json()
        detail = str(body.get("detail", {}))
        assert "traceback" not in detail.lower()
        assert "/app/" not in detail
        assert "File " not in detail
        assert resp.status_code == 400

    def test_500_message_is_sanitized(self, strict_client, monkeypatch):
        """Unexpected errors must hide internal details."""
        def always_nxdomain(*args, **kwargs):
            raise _socket_mod.gaierror("BOOM")

        monkeypatch.setattr("app.validation.socket.getaddrinfo", always_nxdomain)
        resp = strict_client.post(
            "/api/v1/check", json={"url": "https://will-crash.example/"}
        )
        body = resp.json()
        detail = str(body.get("detail", {}))
        assert "traceback" not in detail.lower()
        assert "/app/" not in detail
        assert "File " not in detail
