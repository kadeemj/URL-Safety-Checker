import httpx
import pytest
import respx

from app.checks.base import CheckStatus
from app.checks.redirects import check_redirect_chain
from app.validation import validate_url_syntax


@pytest.fixture()
async def http():
    async with httpx.AsyncClient() as client:
        yield client


def v(url: str):
    return validate_url_syntax(url)


@respx.mock
async def test_no_redirect_passes(http, public_dns) -> None:
    respx.head("https://example.com/").respond(200)
    result = await check_redirect_chain(v("https://example.com/"), http)
    assert result.status == CheckStatus.PASSED
    assert result.points == 0


@respx.mock
async def test_single_redirect_passes(http, public_dns) -> None:
    respx.head("https://a.com/").respond(301, headers={"location": "https://b.com/"})
    respx.head("https://b.com/").respond(200)
    result = await check_redirect_chain(v("https://a.com/"), http)
    assert result.status == CheckStatus.PASSED


@respx.mock
async def test_three_redirects_score_5(http, public_dns) -> None:
    respx.head("https://a.com/").respond(301, headers={"location": "https://b.com/"})
    respx.head("https://b.com/").respond(301, headers={"location": "https://c.com/"})
    respx.head("https://c.com/").respond(301, headers={"location": "https://d.com/"})
    respx.head("https://d.com/").respond(200)
    result = await check_redirect_chain(v("https://a.com/"), http)
    assert result.status == CheckStatus.TRIGGERED
    assert result.points == 5


@respx.mock
async def test_long_chain_scores_10(http, public_dns) -> None:
    for host, nxt in [("a", "b"), ("b", "c"), ("c", "d"), ("d", "e")]:
        respx.head(f"https://{host}.com/").respond(
            301, headers={"location": f"https://{nxt}.com/"}
        )
    respx.head("https://e.com/").respond(200)
    result = await check_redirect_chain(v("https://a.com/"), http)
    assert result.points == 10


@respx.mock
async def test_head_405_falls_back_to_get(http, public_dns) -> None:
    respx.head("https://picky.com/").respond(405)
    respx.get("https://picky.com/").respond(200)
    result = await check_redirect_chain(v("https://picky.com/"), http)
    assert result.status == CheckStatus.PASSED


@respx.mock
async def test_redirect_into_private_space_scores_max(http, public_dns) -> None:
    respx.head("https://tricky.com/").respond(
        302, headers={"location": "http://169.254.169.254/latest/meta-data/"}
    )
    result = await check_redirect_chain(v("https://tricky.com/"), http)
    assert result.status == CheckStatus.TRIGGERED
    assert result.points == 15
    assert "blocked" in (result.evidence or "").lower()


@respx.mock
async def test_shortener_hop_adds_5(http, public_dns) -> None:
    respx.head("https://start.com/").respond(302, headers={"location": "https://bit.ly/x"})
    respx.head("https://bit.ly/x").respond(302, headers={"location": "https://final.com/"})
    respx.head("https://final.com/").respond(200)
    result = await check_redirect_chain(v("https://start.com/"), http)
    # 2 redirects (+5) passing through a shortener (+5)
    assert result.points == 10
    assert "bit.ly" in (result.evidence or "")


@respx.mock
async def test_downgrade_after_upgrade_triggers_10(http, public_dns) -> None:
    # http -> https -> http: the re-downgrade is compared against the previous
    # hop's scheme, not the original one.
    respx.head("http://a.com/").respond(301, headers={"location": "https://b.com/"})
    respx.head("https://b.com/").respond(301, headers={"location": "http://c.com/"})
    result = await check_redirect_chain(v("http://a.com/"), http)
    assert result.status == CheckStatus.TRIGGERED
    assert result.points == 10
    assert "downgrade" in (result.evidence or "").lower()


@respx.mock
async def test_connection_error_reports_unavailable(http, public_dns) -> None:
    respx.head("https://down.com/").mock(side_effect=httpx.ConnectError("refused"))
    result = await check_redirect_chain(v("https://down.com/"), http)
    assert result.status == CheckStatus.UNAVAILABLE
    assert result.points == 0