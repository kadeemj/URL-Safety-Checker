import socket

import pytest
import respx
from fastapi.testclient import TestClient

from app.main import create_app

OLD_DOMAIN_RDAP = {
    "events": [{"eventAction": "registration", "eventDate": "2013-01-01T00:00:00Z"}]
}


@pytest.fixture()
def external_network(monkeypatch):
    """Default happy-path mocks for RDAP and redirect probes; GSB added per-test."""
    monkeypatch.setenv("PIN_REDIRECT_FETCHES", "false")
    from app.config import get_settings
    get_settings.cache_clear()
    with respx.mock(assert_all_called=False, assert_all_mocked=True) as router:
        router.get(host="rdap.org").respond(json=OLD_DOMAIN_RDAP)
        router.head().respond(200)
        yield router


# -- Default CORS + env settings ------------------------------------------

DEFAULT_ENV = {
    "ALLOWED_ORIGINS": "http://localhost:8000",  # Allow localhost for dev/testing
    "EXPOSE_API_DOCS": "false",                   # Hide docs by default
    "PIN_REDIRECT_FETCHES": "false",              # Use shared client for tests
}


@pytest.fixture(autouse=True)
def _default_test_env(monkeypatch):
    """Set sensible defaults for every test without leaking state."""
    for key, value in DEFAULT_ENV.items():
        monkeypatch.setenv(key, value)
    from app.config import get_settings
    get_settings.cache_clear()


# -- App clients -----------------------------------------------------------

@pytest.fixture()
def client():
    """Standard test client with CORS enabled for localhost."""
    from app.config import get_settings
    get_settings.cache_clear()
    with TestClient(create_app()) as tc:
        yield tc


@pytest.fixture()
def strict_client(monkeypatch):
    """Test client with CORS blocked and docs hidden."""
    monkeypatch.setenv("ALLOWED_ORIGINS", "")
    monkeypatch.setenv("EXPOSE_API_DOCS", "false")
    from app.config import get_settings
    get_settings.cache_clear()
    with TestClient(create_app()) as tc:
        yield tc


@pytest.fixture()
def fresh_app_client(monkeypatch, public_dns):
    """Create a fresh TestClient with isolated environment.

    For tests that need custom env vars beyond what autouse provides.
    """
    def _make(extra_env=None):
        env = dict(DEFAULT_ENV)
        if extra_env:
            env.update(extra_env)
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        from app.config import get_settings
        get_settings.cache_clear()
        tc = TestClient(create_app())
        tc.__enter__()
        return tc
    yield _make


PUBLIC_ADDRINFO = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]


@pytest.fixture()
def public_dns(monkeypatch):
    """Make every hostname resolve to a public IP — keeps tests offline."""
    monkeypatch.setattr(
        "app.validation.socket.getaddrinfo", lambda *a, **kw: PUBLIC_ADDRINFO
    )


@pytest.fixture()
def gsb_key(monkeypatch):
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "test-key")
    from app.config import get_settings
    get_settings.cache_clear()
    yield "test-key"
    get_settings.cache_clear()
