"""Redirect-chain follower.

Walks up to MAX_HOPS redirects by hand (HEAD first, GET on 405) instead of
letting httpx follow them, because every hop must pass the SSRF guard: a
public URL that redirects into 169.254.0.0/16 or RFC 1918 space is exactly
the attack the validation module exists to stop.

Hops are fetched over an IP-pinned transport by default, so each hop is
resolved, screened, and connected *to the screened address* — no second,
unchecked resolution can slip past the guard (see app.transport). An
external client can be injected instead for tests (respx mocks at the
httpcore layer, which the pinned transport intentionally bypasses).
"""

import logging
from urllib.parse import urljoin

import httpx

from app.checks.base import CheckCategory, CheckResult, CheckStatus
from app.data.shorteners import SHORTENER_DOMAINS
from app.domains import registrable_domain
from app.transport import PinnedTransport
from app.validation import (
    URLValidationError,
    ValidatedURL,
    ensure_host_resolves_public,
    validate_url_syntax,
)

logger = logging.getLogger(__name__)

MAX_HOPS = 5
HOP_TIMEOUT_SECONDS = 3.0

EXPLANATION = (
    "Long or cross-domain redirect chains hide the real destination from "
    "both users and scanners. Legitimate links rarely bounce more than once."
)


def _result(status: CheckStatus, points: int, evidence: str | None) -> CheckResult:
    return CheckResult(
        id="redirect_chain",
        name="Redirect chain",
        category=CheckCategory.INFRASTRUCTURE,
        status=status,
        points=min(points, 15),
        max_points=15,
        evidence=evidence,
        explanation=EXPLANATION,
    )


async def _fetch_once(http: httpx.AsyncClient, url: str) -> httpx.Response:
    response = await http.head(url)
    if response.status_code == 405:
        response = await http.get(url)
    return response


async def check_redirect_chain(
    url: ValidatedURL, http: httpx.AsyncClient | None = None
) -> CheckResult:
    """Walk the redirect chain. ``http`` is injectable for tests; when omitted,
    a client over the IP-pinned transport is created for the walk."""
    owned_client = http is None
    if http is None:
        http = httpx.AsyncClient(
            transport=PinnedTransport(timeout=HOP_TIMEOUT_SECONDS),
            follow_redirects=False,
            timeout=HOP_TIMEOUT_SECONDS,
        )

    current = url.outbound_url
    hosts = [url.host]
    redirects = 0

    try:
        for _hop in range(MAX_HOPS):
            try:
                response = await _fetch_once(http, current)
            except URLValidationError as exc:
                # the pinned transport re-screened the host and caught a
                # rebinding-style evasion — treat it like a blocked hop
                return _result(
                    CheckStatus.TRIGGERED,
                    15,
                    f"Hop target {current} failed the private-address guard "
                    f"({exc.message}) — a hallmark of server-side request forgery bait",
                )
            except httpx.HTTPError as exc:
                if redirects == 0:
                    logger.warning("Redirect probe for %s failed: %s", url.host, exc)
                    return _result(CheckStatus.UNAVAILABLE, 0, "The URL could not be reached")
                break  # score what we saw before the chain died

            if not response.is_redirect or "location" not in response.headers:
                break

            next_url = urljoin(current, response.headers["location"])
            try:
                validated = validate_url_syntax(next_url)
                await ensure_host_resolves_public(validated.host)
            except URLValidationError:
                return _result(
                    CheckStatus.TRIGGERED,
                    15,
                    f"Redirect hop {redirects + 1} points into blocked address space "
                    f"({next_url}) — a hallmark of server-side request forgery bait",
                )

            redirects += 1
            hosts.append(validated.host)
            current = validated.outbound_url
    finally:
        if owned_client:
            await http.aclose()

    points = 0
    notes: list[str] = []

    if redirects >= 4:
        points += 10
        notes.append(f"{redirects} redirects before reaching the final page")
    elif redirects >= 2:
        points += 5
        notes.append(f"{redirects} redirects before reaching the final page")

    shortener_hops = sorted(
        {h for h in hosts[1:] if registrable_domain(h) in SHORTENER_DOMAINS}
    )
    if shortener_hops:
        points += 5
        notes.append(f"chain passes through shortener {', '.join(shortener_hops)}")

    if redirects and registrable_domain(hosts[-1]) != registrable_domain(hosts[0]):
        notes.append(f"final destination is {hosts[-1]}, not {hosts[0]}")

    if points > 0:
        return _result(CheckStatus.TRIGGERED, points, "; ".join(notes))
    return _result(CheckStatus.PASSED, 0, "; ".join(notes) or None)
