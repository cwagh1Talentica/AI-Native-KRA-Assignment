from __future__ import annotations

import requests

from config.settings import SecuritySettings
from discovery_agent.agent import DiscoveryAgent


def test_fallback_catalog_is_complete(monkeypatch):
    def raise_error(*args, **kwargs):
        raise requests.RequestException("offline")

    monkeypatch.setattr(requests.Session, "get", raise_error)
    agent = DiscoveryAgent(SecuritySettings(base_url="http://localhost:5000"))
    result = agent.discover()

    assert len(result.endpoints) >= 9
    assert any(endpoint.path == "/users/v1" and endpoint.method == "GET" for endpoint in result.endpoints)
    assert any(endpoint.path == "/books/v1/{book_title}" for endpoint in result.endpoints)
