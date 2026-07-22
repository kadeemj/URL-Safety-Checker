import socket

import pytest
import respx
from fastapi.testclient import TestClient

from app.main import create_app

OLD_DOMAIN_RDAP = {
    "events": [{"eventAction": "registration", "eventDate": "2013-01-01T00:00:00Z"}]
}


@pytest.fixture()
def external_network():
    """Default happy-path mocks for RDAP and redirect probes; GSB added per-test."""
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        router.get(host="rdap.org").respond(json=OLD_DOMAIN_RDAP)
        router.head().respond(200)
        yield router

PUBLIC_ADDRINFO = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]


@pytest.fixture()
def public_dns(monkeypatch):
    """Make every hostname resolve to a public IP — keeps tests offline."""
    monkeypatch.setattr(
        "app.validation.socket.getaddrinfo", lambda *a, **kw: PUBLIC_ADDRINFO
    )


@pytest.fixture()
def client():
    with TestClient(create_app()) as test_client:
        yield test_client


@pytest.fixture()
def gsb_key(monkeypatch):
    from app.config import get_settings

    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "test-key")
    get_settings.cache_clear()
    yield "test-key"
    get_settings.cache_clear()
