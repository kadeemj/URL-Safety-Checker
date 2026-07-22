import httpx
import pytest
import respx

from app.checks.base import CheckStatus
from app.checks.reputation import GSB_ENDPOINT, lookup_safe_browsing

MATCH_RESPONSE = {
    "matches": [
        {
            "threatType": "SOCIAL_ENGINEERING",
            "platformType": "ANY_PLATFORM",
            "threat": {"url": "http://phish.example/"},
        }
    ]
}


@pytest.fixture()
async def http():
    async with httpx.AsyncClient() as client:
        yield client


@respx.mock
async def test_listed_url_is_a_hit(http) -> None:
    respx.post(GSB_ENDPOINT).respond(json=MATCH_RESPONSE)
    sb, check = await lookup_safe_browsing("http://phish.example/", http, api_key="k")
    assert sb.status == "hit"
    assert sb.threats == ["SOCIAL_ENGINEERING"]
    assert check.status == CheckStatus.TRIGGERED
    assert "SOCIAL_ENGINEERING" in (check.evidence or "")


@respx.mock
async def test_unlisted_url_is_clear(http) -> None:
    respx.post(GSB_ENDPOINT).respond(json={})
    sb, check = await lookup_safe_browsing("https://example.com/", http, api_key="k")
    assert sb.status == "clear"
    assert check.status == CheckStatus.PASSED


@respx.mock
async def test_timeout_reports_unavailable(http) -> None:
    respx.post(GSB_ENDPOINT).mock(side_effect=httpx.ConnectTimeout("slow"))
    sb, check = await lookup_safe_browsing("https://example.com/", http, api_key="k")
    assert sb.status == "unavailable"
    assert check.status == CheckStatus.UNAVAILABLE


@respx.mock
async def test_quota_error_reports_unavailable(http) -> None:
    respx.post(GSB_ENDPOINT).respond(status_code=429, json={"error": "quota"})
    sb, check = await lookup_safe_browsing("https://example.com/", http, api_key="k")
    assert sb.status == "unavailable"


@respx.mock
async def test_missing_key_is_unavailable_without_calling_google(http) -> None:
    route = respx.post(GSB_ENDPOINT).respond(json={})
    sb, check = await lookup_safe_browsing("https://example.com/", http, api_key="")
    assert sb.status == "unavailable"
    assert check.status == CheckStatus.UNAVAILABLE
    assert not route.called
