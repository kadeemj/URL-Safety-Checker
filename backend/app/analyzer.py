"""Analysis orchestrator: validation -> checks -> aggregate -> report."""

import time
from datetime import UTC, datetime

from app.checks.lexical import LEXICAL_CHECKS
from app.checks.structure import STRUCTURE_CHECKS
from app.models import AnalysisResponse, SafeBrowsingResult
from app.scoring import aggregate
from app.validation import ensure_host_resolves_public, validate_url_syntax

LOCAL_CHECKS = STRUCTURE_CHECKS + LEXICAL_CHECKS


async def analyze(url: str) -> AnalysisResponse:
    """Run the full pipeline. Raises URLValidationError on unacceptable input."""
    started = time.perf_counter()

    validated = validate_url_syntax(url)
    await ensure_host_resolves_public(validated.host)

    checks = [check(validated) for check in LOCAL_CHECKS]

    # Reputation lookup lands in a later step; report it honestly as absent.
    safe_browsing = SafeBrowsingResult(status="unavailable", threats=[])

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
