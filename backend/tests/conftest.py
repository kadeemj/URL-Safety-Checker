import socket

import pytest
from fastapi.testclient import TestClient

from app.main import create_app

PUBLIC_ADDRINFO = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]


@pytest.fixture()
def public_dns(monkeypatch):
    """Make every hostname resolve to a public IP — keeps tests offline."""
    monkeypatch.setattr(
        "app.validation.socket.getaddrinfo", lambda *a, **kw: PUBLIC_ADDRINFO
    )


@pytest.fixture()
def client():
    return TestClient(create_app())
