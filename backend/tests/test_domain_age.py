from datetime import UTC, datetime, timedelta

import httpx
import pytest
import respx

from app.checks.base import CheckStatus
from app.checks.domain_age import check_domain_age


@pytest.fixture()
async def http():
    async with httpx.AsyncClient() as client:
        yield client


def rdap_body(days_old: int) -> dict:
    registered = datetime.now(UTC) - timedelta(days=days_old)
    return {
        "events": [
            {"eventAction": "registration", "eventDate": registered.isoformat()},
            {"eventAction": "last changed", "eventDate": registered.isoformat()},
        ]
    }


@respx.mock
async def test_brand_new_domain_scores_20(http) -> None:
    respx.get("https://rdap.org/domain/fresh-phish.com").respond(json=rdap_body(10))
    result = await check_domain_age("fresh-phish.com", http)
    assert result.status == CheckStatus.TRIGGERED
    assert result.points == 20


@respx.mock
async def test_recent_domain_scores_10(http) -> None:
    respx.get("https://rdap.org/domain/newish.com").respond(json=rdap_body(90))
    result = await check_domain_age("newish.com", http)
    assert result.status == CheckStatus.TRIGGERED
    assert result.points == 10


@respx.mock
async def test_established_domain_passes(http) -> None:
    respx.get("https://rdap.org/domain/github.com").respond(json=rdap_body(5000))
    result = await check_domain_age("github.com", http)
    assert result.status == CheckStatus.PASSED
    assert result.points == 0


@respx.mock
async def test_subdomain_is_looked_up_by_registrable_domain(http) -> None:
    route = respx.get("https://rdap.org/domain/example.com").respond(json=rdap_body(5000))
    await check_domain_age("deep.sub.example.com", http)
    assert route.called


@respx.mock
async def test_rdap_404_reports_unavailable(http) -> None:
    respx.get("https://rdap.org/domain/unknown.com").respond(status_code=404)
    result = await check_domain_age("unknown.com", http)
    assert result.status == CheckStatus.UNAVAILABLE
    assert result.points == 0


@respx.mock
async def test_rdap_timeout_reports_unavailable(http) -> None:
    respx.get("https://rdap.org/domain/slow.com").mock(
        side_effect=httpx.ConnectTimeout("slow")
    )
    result = await check_domain_age("slow.com", http)
    assert result.status == CheckStatus.UNAVAILABLE


@respx.mock
async def test_missing_registration_event_reports_unavailable(http) -> None:
    respx.get("https://rdap.org/domain/odd.com").respond(json={"events": []})
    result = await check_domain_age("odd.com", http)
    assert result.status == CheckStatus.UNAVAILABLE


async def test_ip_host_reports_unavailable(http) -> None:
    result = await check_domain_age("8.8.8.8", http)
    assert result.status == CheckStatus.UNAVAILABLE
