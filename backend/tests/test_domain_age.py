import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import respx

import app.transport as transport
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


class FakeSocket:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def sendall(self, data: bytes) -> None:
        pass

    def makefile(self, mode: str):
        import io

        return io.BytesIO(self.payload)

    def settimeout(self, timeout: float | None) -> None:
        pass

    def close(self) -> None:
        pass


async def test_default_transport_is_pinned(monkeypatch) -> None:
    body = json.dumps(rdap_body(10)).encode()
    raw = (
        b"HTTP/1.1 200 OK\r\n"
        b"content-type: application/json\r\n"
        b"content-length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )
    monkeypatch.setattr(
        "app.validation.socket.getaddrinfo",
        lambda *a, **kw: [(2, 1, 6, "", ("93.184.216.34", 80))],
    )
    seen = []

    def fake_connect(ip, port, ssl_context, server_hostname, timeout):
        seen.append((ip, port, ssl_context, server_hostname))
        return FakeSocket(raw)

    monkeypatch.setattr(transport, "_connect_tcp", fake_connect)
    result = await check_domain_age("fresh-phish.com")
    assert result.status == CheckStatus.TRIGGERED
    assert result.points == 20
    assert seen[0][0] == "93.184.216.34"
    assert seen[0][3] == "rdap.org"
