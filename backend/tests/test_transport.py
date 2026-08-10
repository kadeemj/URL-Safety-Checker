"""Tests for the IP-pinned transport.

The pinned transport resolves + screens a host and connects to the
screened address. Networking is faked at two seams: DNS via the usual
``app.validation.socket.getaddrinfo`` monkeypatch, and the socket hand-off
via ``app.transport._connect_tcp``, which returns a fake socket that http.client
can read a canned HTTP/1.1 response from.
"""

import io
import socket

import httpx
import pytest

import app.transport as transport
from app.transport import MAX_RESPONSE_BODY_BYTES, PinnedTransport
from app.validation import URLValidationError

PUBLIC_IP = "93.184.216.34"
PLAIN = (
    b"HTTP/1.1 200 OK\r\n"
    b"content-type: text/plain\r\n"
    b"transfer-encoding: chunked\r\n"
    b"\r\n"
    b"4\r\nbody\r\n0\r\n\r\n"
)
TLS = (
    b"HTTP/1.1 301 Moved Permanently\r\n"
    b"location: https://elsewhere.example/\r\n"
    b"content-length: 0\r\n"
    b"\r\n"
)
BIG = b"HTTP/1.1 200 OK\r\ncontent-length: %d\r\n\r\n" % (MAX_RESPONSE_BODY_BYTES + 500) + (
    b"x" * (MAX_RESPONSE_BODY_BYTES + 500)
)


class FakeSocket:
    """Minimal socket stand-in: http.client needs sendall, makefile, close."""

    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def sendall(self, data: bytes) -> None:
        pass

    def makefile(self, mode: str):
        return io.BytesIO(self.payload)

    def settimeout(self, timeout: float | None) -> None:
        pass

    def close(self) -> None:
        pass


@pytest.fixture()
def public_dns(monkeypatch):
    def fake_getaddrinfo(host, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_IP, 80))]

    monkeypatch.setattr("app.validation.socket.getaddrinfo", fake_getaddrinfo)


def request(method: str, url: str) -> httpx.Request:
    req = httpx.Request(method, url)
    req.headers.setdefault("host", req.url.netloc)
    return req


async def test_rebinding_resolution_to_private_ip_rejected(monkeypatch) -> None:
    def fake_getaddrinfo(host, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80))]

    monkeypatch.setattr("app.validation.socket.getaddrinfo", fake_getaddrinfo)
    with pytest.raises(URLValidationError):
        await PinnedTransport().handle_async_request(request("HEAD", "https://evil.example/"))


async def test_https_connects_to_pinned_ip_with_server_hostname(public_dns, monkeypatch) -> None:
    seen: list[tuple] = []

    def fake_connect(ip, port, ssl_context, server_hostname, timeout):
        seen.append((ip, port, ssl_context, server_hostname))
        return FakeSocket(TLS)

    monkeypatch.setattr(transport, "_connect_tcp", fake_connect)
    response = await PinnedTransport().handle_async_request(
        request("HEAD", "https://example.com/start")
    )
    assert seen[0][0] == PUBLIC_IP  # connects to the pinned address, not a re-resolve
    assert seen[0][1] == 443
    assert seen[0][2] is not None  # TLS context built for https
    assert seen[0][3] == "example.com"  # cert verified against the real hostname
    assert response.status_code == 301
    assert response.headers["location"] == "https://elsewhere.example/"


async def test_http_connects_plaintext(public_dns, monkeypatch) -> None:
    seen: list[tuple] = []

    def fake_connect(ip, port, ssl_context, server_hostname, timeout):
        seen.append((ip, port, ssl_context, server_hostname))
        return FakeSocket(PLAIN)

    monkeypatch.setattr(transport, "_connect_tcp", fake_connect)
    response = await PinnedTransport().handle_async_request(request("GET", "http://example.com/"))
    assert seen[0][1] == 80
    assert seen[0][2] is None
    assert response.status_code == 200
    assert response.content == b"body"
    # wire framing was decoded; content-length is the true byte count
    assert "transfer-encoding" not in response.headers
    assert response.headers["content-length"] == "4"


async def test_response_body_truncated_at_cap(public_dns, monkeypatch) -> None:
    monkeypatch.setattr(transport, "_connect_tcp", lambda *a, **kw: FakeSocket(BIG))
    response = await PinnedTransport().handle_async_request(request("GET", "http://example.com/"))
    assert len(response.content) == MAX_RESPONSE_BODY_BYTES


async def test_resolution_cached_per_transport(public_dns, monkeypatch) -> None:
    calls = []

    def counting(host, *args, **kwargs):
        calls.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_IP, 80))]

    monkeypatch.setattr("app.validation.socket.getaddrinfo", counting)
    monkeypatch.setattr(transport, "_connect_tcp", lambda *a, **kw: FakeSocket(PLAIN))
    pinned = PinnedTransport()
    await pinned.handle_async_request(request("GET", "http://one.example/"))
    await pinned.handle_async_request(request("GET", "http://one.example/again"))
    assert calls == ["one.example"]
    await pinned.handle_async_request(request("GET", "http://two.example/"))
    assert calls == ["one.example", "two.example"]