"""Google Safe Browsing v4 lookup.

The one external threat-intelligence source in v1. A listing here is
treated as ground truth (verdict override in scoring); anything that stops
the lookup — missing key, timeout, quota — degrades to 'unavailable' so the
heuristics still produce a scored report.
"""

import logging

import httpx

from app.checks.base import CheckCategory, CheckResult, CheckStatus
from app.models import SafeBrowsingResult

logger = logging.getLogger(__name__)

GSB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
GSB_TIMEOUT_SECONDS = 4.0

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]

EXPLANATION = (
    "Google Safe Browsing is the blocklist Chrome and Firefox use. A listing "
    "means Google has confirmed active abuse at this URL, so it overrides "
    "every heuristic. A clear result is weaker: brand-new threats haven't "
    "been catalogued yet."
)


def _check(status: CheckStatus, evidence: str | None) -> CheckResult:
    return CheckResult(
        id="safe_browsing",
        name="Google Safe Browsing",
        category=CheckCategory.REPUTATION,
        status=status,
        points=0,  # a hit overrides the verdict in scoring; no double count here
        max_points=0,
        evidence=evidence,
        explanation=EXPLANATION,
    )


async def lookup_safe_browsing(
    url: str, http: httpx.AsyncClient, api_key: str
) -> tuple[SafeBrowsingResult, CheckResult]:
    if not api_key:
        return (
            SafeBrowsingResult(status="unavailable", threats=[]),
            _check(CheckStatus.UNAVAILABLE, "No API key configured on this deployment"),
        )

    payload = {
        "client": {"clientId": "url-safety-checker", "clientVersion": "0.1.0"},
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = await http.post(
            GSB_ENDPOINT,
            params={"key": api_key},
            json=payload,
            timeout=GSB_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        matches = response.json().get("matches", [])
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("Safe Browsing lookup failed: %s", exc)
        return (
            SafeBrowsingResult(status="unavailable", threats=[]),
            _check(CheckStatus.UNAVAILABLE, "Lookup failed or timed out"),
        )

    if matches:
        threats = sorted({m.get("threatType", "UNKNOWN") for m in matches})
        return (
            SafeBrowsingResult(status="hit", threats=threats),
            _check(
                CheckStatus.TRIGGERED,
                f"Confirmed threat — listed as {', '.join(threats)}",
            ),
        )

    return (
        SafeBrowsingResult(status="clear", threats=[]),
        _check(CheckStatus.PASSED, None),
    )
