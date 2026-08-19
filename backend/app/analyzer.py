"""Analysis orchestrator: validation -> checks -> aggregate -> report."""

import asyncio
import time
from datetime import UTC, datetime

import httpx

from app.checks.domain_age import check_domain_age
from app.checks.lexical import LEXICAL_CHECKS
from app.checks.redirects import check_redirect_chain
from app.checks.reputation import lookup_safe_browsing
from app.checks.structure import STRUCTURE_CHECKS
from app.models import AnalysisResponse
from app.scoring import aggregate
from app.validation import ensure_host_resolves_public, validate_url_syntax

LOCAL_CHECKS = STRUCTURE_CHECKS + LEXICAL_CHECKS


async def analyze(
    url: str,
    http: httpx.AsyncClient,
    gsb_api_key: str,
    redirect_http: httpx.AsyncClient | None = None,
    rdap_http: httpx.AsyncClient | None = None,
    allow_http_redirect_from_https: bool = False,
) -> AnalysisResponse:
    """Run the full pipeline. Raises URLValidationError on unacceptable input.

    ``redirect_http`` selects the client used to walk redirect chains:
    ``None`` (default) means a dedicated client over the IP-pinned transport;
    a shared/mocked client can be injected when resolvers are stubbed.

    ``rdap_http`` selects the client used for the RDAP domain-age lookup:
    ``None`` (default) means a dedicated client over the IP-pinned transport;
    a shared/mocked client can be injected in tests.

    ``allow_http_redirect_from_https`` controls whether redirects from
    HTTPS to HTTP are permitted during chain walking. Defaults to False
    to block downgrade attacks.
    """
    started = time.perf_counter()

    validated = validate_url_syntax(url)
    await ensure_host_resolves_public(validated.host)

    checks = [check(validated) for check in LOCAL_CHECKS]

    # Network checks run concurrently; each degrades to 'unavailable' on its
    # own rather than raising. Credentials are stripped from outbound_url.
    (safe_browsing, sb_check), age_check, redirect_check = await asyncio.gather(
        lookup_safe_browsing(validated.outbound_url, http, gsb_api_key),
        check_domain_age(validated.host, rdap_http),
        check_redirect_chain(validated, redirect_http, allow_http_redirect_from_https),
    )
    checks.extend([sb_check, age_check, redirect_check])

    summary = aggregate(checks, safe_browsing)

    return AnalysisResponse(
        submitted_url=url,
        normalized_url=validated.outbound_url,
        analyzed_at=datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        duration_ms=int((time.perf_counter() - started) * 1000),
        score=summary.score,
        verdict=summary.verdict,
        confidence=summary.confidence,
        safe_browsing=safe_browsing,
        checks=checks,
    )
