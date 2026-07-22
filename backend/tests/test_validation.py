import socket

import pytest

from app.validation import URLValidationError, ensure_host_resolves_public, validate_url_syntax


@pytest.mark.parametrize(
    ("url", "code"),
    [
        # scheme abuse
        ("file:///etc/passwd", "INVALID_SCHEME"),
        ("javascript:alert(1)", "INVALID_SCHEME"),
        ("ftp://example.com/file", "INVALID_SCHEME"),
        # local / internal hostnames
        ("http://localhost:8000/", "PRIVATE_HOST"),
        ("http://foo.localhost/", "PRIVATE_HOST"),
        ("http://localhost./", "PRIVATE_HOST"),
        ("http://router.local/", "PRIVATE_HOST"),
        ("http://db.internal/admin", "PRIVATE_HOST"),
        ("http://market.onion/", "PRIVATE_HOST"),
        # literal private / reserved IPs
        ("http://127.0.0.1/", "PRIVATE_HOST"),
        ("http://10.0.0.1/", "PRIVATE_HOST"),
        ("http://192.168.1.1/", "PRIVATE_HOST"),
        ("http://172.16.0.1/", "PRIVATE_HOST"),
        ("http://169.254.169.254/latest/meta-data/", "PRIVATE_HOST"),
        ("http://100.64.0.1/", "PRIVATE_HOST"),
        ("http://[::1]/", "PRIVATE_HOST"),
        ("http://[fe80::1]/", "PRIVATE_HOST"),
        # integer-encoded IPv4 (2130706433 == 127.0.0.1)
        ("http://2130706433/", "PRIVATE_HOST"),
        # malformed
        ("not a url", "INVALID_URL"),
        ("http://", "INVALID_URL"),
        ("http://example.com:99999/", "INVALID_URL"),
    ],
)
def test_rejected_urls(url: str, code: str) -> None:
    with pytest.raises(URLValidationError) as exc_info:
        validate_url_syntax(url)
    assert exc_info.value.code == code


def test_overlong_url_rejected() -> None:
    with pytest.raises(URLValidationError) as exc_info:
        validate_url_syntax("https://example.com/" + "a" * 2100)
    assert exc_info.value.code == "URL_TOO_LONG"


def test_valid_url_accepted() -> None:
    validated = validate_url_syntax("https://Example.COM:443/path?q=1")
    assert validated.scheme == "https"
    assert validated.host == "example.com"
    assert validated.has_userinfo is False


def test_userinfo_flagged_and_stripped_from_outbound() -> None:
    validated = validate_url_syntax("https://paypal.com@evil.example/login")
    assert validated.has_userinfo is True
    assert validated.host == "evil.example"
    assert "paypal.com@" not in validated.outbound_url
    assert validated.outbound_url == "https://evil.example/login"


async def test_dns_rebinding_to_private_ip_rejected(monkeypatch) -> None:
    def fake_getaddrinfo(host, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80))]

    monkeypatch.setattr("app.validation.socket.getaddrinfo", fake_getaddrinfo)
    with pytest.raises(URLValidationError) as exc_info:
        await ensure_host_resolves_public("evil.example")
    assert exc_info.value.code == "PRIVATE_HOST"


async def test_public_resolution_accepted(monkeypatch) -> None:
    def fake_getaddrinfo(host, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]

    monkeypatch.setattr("app.validation.socket.getaddrinfo", fake_getaddrinfo)
    await ensure_host_resolves_public("example.com")  # must not raise


async def test_unresolvable_host_rejected(monkeypatch) -> None:
    def fake_getaddrinfo(host, *args, **kwargs):
        raise socket.gaierror("NXDOMAIN")

    monkeypatch.setattr("app.validation.socket.getaddrinfo", fake_getaddrinfo)
    with pytest.raises(URLValidationError) as exc_info:
        await ensure_host_resolves_public("no-such-host.example")
    assert exc_info.value.code == "UNRESOLVABLE_HOST"
