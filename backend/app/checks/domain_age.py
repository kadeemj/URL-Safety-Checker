"""Domain age via RDAP (the structured successor to WHOIS).

rdap.org is a free bootstrap redirector: it 302s to the authoritative
registry's RDAP server, so this request opts into following redirects.
Phishing domains are overwhelmingly young — most are used within days of
registration, before blocklists catch up.
"""

import logging
from datetime import UTC, datetime

import httpx

from app.checks.base import CheckCategory, CheckResult, CheckStatus
from app.domains import registrable_domain

logger = logging.getLogger(__name__)

RDAP_URL = "https://rdap.org/domain/{domain}"
RDAP_TIMEOUT_SECONDS = 4.0
BRAND_NEW_DAYS = 30
RECENT_DAYS = 180

EXPLANATION = (
    "Most phishing domains are only days old when they go live — attackers "
    "burn and replace them faster than blocklists update. An established "
    "registration date is one of the stronger trust signals a domain has."
)


def _result(status: CheckStatus, points: int, evidence: str | None) -> CheckResult:
    return CheckResult(
        id="domain_age",
        name="Domain age",
        category=CheckCategory.INFRASTRUCTURE,
        status=status,
        points=points,
        max_points=20,
        evidence=evidence,
        explanation=EXPLANATION,
    )


async def check_domain_age(host: str, http: httpx.AsyncClient) -> CheckResult:
    domain = registrable_domain(host)
    if not domain:
        return _result(
            CheckStatus.UNAVAILABLE, 0, "Host has no registrable domain (IP address?)"
        )

    try:
        response = await http.get(
            RDAP_URL.format(domain=domain),
            timeout=RDAP_TIMEOUT_SECONDS,
            follow_redirects=True,
        )
        response.raise_for_status()
        events = response.json().get("events", [])
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("RDAP lookup for %s failed: %s", domain, exc)
        return _result(CheckStatus.UNAVAILABLE, 0, "Registration data could not be retrieved")

    registered_raw = next(
        (e.get("eventDate") for e in events if e.get("eventAction") == "registration"),
        None,
    )
    if not registered_raw:
        return _result(CheckStatus.UNAVAILABLE, 0, "Registry did not report a registration date")

    try:
        registered = datetime.fromisoformat(registered_raw.replace("Z", "+00:00"))
    except ValueError:
        return _result(CheckStatus.UNAVAILABLE, 0, "Registration date was unreadable")

    age_days = (datetime.now(UTC) - registered).days
    registered_on = registered.date().isoformat()

    if age_days < BRAND_NEW_DAYS:
        return _result(
            CheckStatus.TRIGGERED,
            20,
            f"'{domain}' was registered {age_days} days ago ({registered_on})",
        )
    if age_days < RECENT_DAYS:
        return _result(
            CheckStatus.TRIGGERED,
            10,
            f"'{domain}' was registered {age_days} days ago ({registered_on})",
        )
    return _result(
        CheckStatus.PASSED,
        0,
        f"'{domain}' has been registered since {registered_on}",
    )
