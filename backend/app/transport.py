"""IP-pinned httpx transport — closes the DNS-rebinding window.

A naive "validate-then-fetch" SSRF guard resolves a hostname, verifies every
answer is public, and then lets httpx *re-resolve the hostname* at connect
time. A hostile DNS server can answer the second resolution differently and
land the fetch inside private address space anyway.

This transport resolves the hostname ONCE through the same public-IP
screening (see ``validation.resolve_public_addresses``), pins the validated
address, and connects to the pinned IP directly while keeping the real
hostname for TLS verification and the ``Host`` header. The window an
attacker can exploit shrinks to the life of one redirect walk (plus a short
per-walk cache TTL), and a rebinding attempt surfaces as a
``URLValidationError`` on the hop instead of a connection into private space.

Fetching is done with :mod:`http.client` over a pre-connected socket in a
worker thread, so the event loop is never blocked; response bodies are read
with a hard cap.
"""

import asyncio
import http.client
import logging
import socket
import ssl
import time

import httpx

from app.validation import resolve_public_addresses

logger = logging.getLogger(__name__)

PIN_TTL_SECONDS = 60.0
MAX_RESPONSE_BODY_BYTES = 1024 * 1024  # 1 MiB; redirect probes are tiny


def _connect_tcp(
    ip: str,
    port: int,
    ssl_context: ssl.SSLContext | None,
    server_hostname: str | None,
    timeout: float,
) -> socket.socket:
    """Open a (optionally TLS-wrapped) socket to a pinned IP.

    TLS verification still uses ``server_hostname``, so the certificate is
    validated against the real domain even though the connection goes to a
    validated IP address.
    """
    sock = socket.create_connection((ip, port), timeout=timeout)
    try:
        if ssl_context is not None:
            return ssl_context.wrap_socket(sock, server_hostname=server_hostname)
        return sock
    except Exception:
        sock.close()
        raise


def _build_response(
    request: httpx.Request,
    status: int,
    reason: str,
    headers: list[tuple[str, str]],
    body: bytes,
) -> httpx.Response:
    """Reassemble an httpx Response from raw wire data.

    Content framing is handled by http.client (chunked decoding), so the
    wire-level framing headers are dropped and ``content-length`` is set to
    the actual byte count we read.
    """
    cleaned: dict[str, str] = {}
    for name, value in headers:
        lowered = name.lower()
        if lowered in {"transfer-encoding", "content-encoding", "content-length"}:
            continue
        cleaned[lowered] = value
    cleaned["content-length"] = str(len(body))
    return httpx.Response(
        status_code=status,
        headers=cleaned,
        content=body,
        request=request,
        extensions={"reason_phrase": reason},
    )


async def _exchange(
    request: httpx.Request,
    ip: str,
    host: str,
    port: int,
    ssl_context: ssl.SSLContext | None,
    timeout: float,
) -> httpx.Response:
    body = await request.aread()

    def run() -> tuple[int, str, list[tuple[str, str]], bytes]:
        sock = _connect_tcp(ip, port, ssl_context, host if ssl_context else None, timeout)
        connection: http.client.HTTPConnection | None = None
        try:
            if ssl_context is not None:
                connection = http.client.HTTPSConnection(host, port, timeout=timeout)
            else:
                connection = http.client.HTTPConnection(host, port, timeout=timeout)
            # hand the pre-connected (and TLS-wrapped) socket to the
            # connection object; http.client skips connect() then
            connection.sock = sock
            headers = dict(request.headers.items())
            connection.request(
                request.method,
                request.url.raw_path.decode("ascii"),
                body=body,
                headers=headers,
            )
            response = connection.getresponse()
            data = response.read(MAX_RESPONSE_BODY_BYTES + 1)
            return (
                response.status,
                response.reason,
                [(key, value) for key, value in response.getheaders()],
                data[:MAX_RESPONSE_BODY_BYTES],
            )
        finally:
            if connection is not None:
                connection.close()
            sock.close()

    status, reason, headers, data = await asyncio.to_thread(run)
    return _build_response(request, status, reason, headers, data)


class PinnedTransport(httpx.AsyncBaseTransport):
    """Resolves each host through the public-IP screen and pins the result.

    A fresh transport is created per redirect walk, so its per-host IP cache
    lives only as long as that walk (plus ``ttl`` for repeated hops).
    """

    def __init__(self, timeout: float = 5.0, ttl: float = PIN_TTL_SECONDS) -> None:
        self.timeout = timeout
        self.ttl = ttl
        self._cache: dict[str, tuple[list[str], float]] = {}

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        scheme = request.url.scheme
        port = request.url.port or (443 if scheme == "https" else 80)
        ip = await self._pinned_ip(host)
        ssl_context = ssl.create_default_context() if scheme == "https" else None
        return await _exchange(request, ip, host, port, ssl_context, self.timeout)

    async def _pinned_ip(self, host: str) -> str:
        cached = self._cache.get(host)
        now = time.monotonic()
        if cached and cached[1] > now:
            return cached[0][0]
        addresses = await resolve_public_addresses(host)
        self._cache[host] = (addresses, now + self.ttl)
        return addresses[0]