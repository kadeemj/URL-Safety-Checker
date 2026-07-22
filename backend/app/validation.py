"""URL validation and SSRF guard.

Threat model: this service fetches attacker-supplied URLs (redirect following,
reputation lookups), so a submitted URL is a potential Server-Side Request
Forgery vector. A hostile URL could point the backend at cloud metadata
(169.254.169.254), localhost services, or RFC 1918 space — directly, via an
integer-encoded IP (http://2130706433/), or via a DNS name that resolves to a
private address (rebinding-style). Defenses, in order:

1. ``validate_url_syntax`` — pure syntactic gate: http(s) only, length cap,
   blocked hostname suffixes, literal-IP screening (including integer forms).
2. ``ensure_host_resolves_public`` — resolves the hostname and rejects it if
   *any* returned address is non-global.

Both are re-run on every redirect hop, not just the submitted URL.
"""

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit, urlunsplit

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = {"http", "https"}
BLOCKED_HOST_SUFFIXES = (".localhost", ".local", ".internal", ".onion")
BLOCKED_HOSTS = {"localhost"}


class URLValidationError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ValidatedURL:
    original: str
    scheme: str
    host: str
    port: int | None
    has_userinfo: bool
    outbound_url: str  # credentials stripped — safe to fetch
    parts: SplitResult


def _as_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse a host as a literal IP, including bare-integer IPv4 forms."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    # inet_aton accepts decimal/octal/hex single-integer hosts (http://2130706433/)
    # and browsers resolve them, so screen those too.
    if host.isdigit():
        try:
            return ipaddress.ip_address(int(host))
        except ValueError:
            return None
    return None


def _reject_non_global_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, host: str) -> None:
    if not ip.is_global:
        raise URLValidationError(
            "PRIVATE_HOST",
            f"Host '{host}' points at a private, loopback, or reserved address.",
        )


def validate_url_syntax(url: str) -> ValidatedURL:
    """Syntactic gate. Raises URLValidationError; never touches the network."""
    if len(url) > MAX_URL_LENGTH:
        raise URLValidationError("URL_TOO_LONG", f"URL exceeds {MAX_URL_LENGTH} characters.")

    try:
        parts = urlsplit(url)
        port = parts.port  # raises ValueError when out of range
    except ValueError as exc:
        raise URLValidationError("INVALID_URL", f"URL could not be parsed: {exc}") from exc

    if not parts.scheme:
        raise URLValidationError("INVALID_URL", "URL has no scheme; expected http or https.")
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise URLValidationError(
            "INVALID_SCHEME", f"Scheme '{parts.scheme}' is not allowed; only http and https."
        )

    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise URLValidationError("INVALID_URL", "URL has no host.")

    if host in BLOCKED_HOSTS or host.endswith(BLOCKED_HOST_SUFFIXES):
        raise URLValidationError("PRIVATE_HOST", f"Host '{host}' is a local or internal name.")

    ip = _as_ip(host)
    if ip is not None:
        _reject_non_global_ip(ip, host)

    has_userinfo = parts.username is not None or parts.password is not None
    netloc = host if port is None else f"{host}:{port}"
    outbound_url = urlunsplit((parts.scheme.lower(), netloc, parts.path, parts.query, ""))

    return ValidatedURL(
        original=url,
        scheme=parts.scheme.lower(),
        host=host,
        port=port,
        has_userinfo=has_userinfo,
        outbound_url=outbound_url,
        parts=parts,
    )


async def ensure_host_resolves_public(host: str) -> None:
    """Resolve ``host`` and reject it if any address is non-global.

    Defends against names that resolve into private space (DNS-rebinding
    style). Literal IPs pass through the same screening. Runs getaddrinfo in
    a thread so the event loop is never blocked.
    """
    ip = _as_ip(host)
    if ip is not None:
        _reject_non_global_ip(ip, host)
        return

    try:
        infos = await asyncio.to_thread(
            socket.getaddrinfo, host, None, type=socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        raise URLValidationError(
            "UNRESOLVABLE_HOST", f"Host '{host}' did not resolve."
        ) from exc

    for _family, _type, _proto, _canon, sockaddr in infos:
        resolved = ipaddress.ip_address(sockaddr[0])
        _reject_non_global_ip(resolved, host)
