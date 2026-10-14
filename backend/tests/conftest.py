import socket
from contextlib import AsyncExitStack, asynccontextmanager

import httpx
import pytest
import respx

from app.main import create_app

OLD_DOMAIN_RDAP = {
    "events": [{"eventAction": "registration", "eventDate": "2013-01-01T00:00:00Z"}]
}


@pytest.fixture()
def external_network(monkeypatch):
    """Default happy-path mocks for RDAP and redirect probes; GSB added per-test."""
    monkeypatch.setenv("PIN_REDIRECT_FETCHES", "false")
    monkeypatch.setenv("PIN_RDAP_FETCHES", "false")
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
    "PIN_RDAP_FETCHES": "false",                  # Use shared client for tests
}


@pytest.fixture(autouse=True)
def _default_test_env(monkeypatch):
    """Set sensible defaults for every test without leaking state."""
    for key, value in DEFAULT_ENV.items():
        monkeypatch.setenv(key, value)
    from app.config import get_settings
    get_settings.cache_clear()


# -- App clients -----------------------------------------------------------

@asynccontextmanager
async def app_client(app):
    """Drive the app in-process over httpx, running its lifespan like a server would."""
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
            yield ac


@pytest.fixture()
async def client():
    """Standard test client with CORS enabled for localhost."""
    from app.config import get_settings
    get_settings.cache_clear()
    async with app_client(create_app()) as ac:
        yield ac


@pytest.fixture()
async def strict_client(monkeypatch):
    """Test client with CORS blocked and docs hidden."""
    monkeypatch.setenv("ALLOWED_ORIGINS", "")
    monkeypatch.setenv("EXPOSE_API_DOCS", "false")
    from app.config import get_settings
    get_settings.cache_clear()
    async with app_client(create_app()) as ac:
        yield ac


@pytest.fixture()
async def fresh_app_client(monkeypatch, public_dns):
    """Create a fresh client with isolated environment.

    For tests that need custom env vars beyond what autouse provides.
    """
    async with AsyncExitStack() as stack:
        async def _make(extra_env=None):
            env = dict(DEFAULT_ENV)
            if extra_env:
                env.update(extra_env)
            for k, v in env.items():
                monkeypatch.setenv(k, v)
            from app.config import get_settings
            get_settings.cache_clear()
            return await stack.enter_async_context(app_client(create_app()))
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
