from __future__ import annotations

import jwt

from config.settings import SecuritySettings
from models import DiscoveryResult, EndpointMetadata
from security_agent.agent import AuthContext, SecurityTestingAgent


class FakeResponse:
    def __init__(self, status_code=200, data=None, text="", headers=None):
        self.status_code = status_code
        self._data = data
        self.text = text
        self.headers = headers or {}

    @property
    def ok(self):
        return self.status_code < 400

    def json(self):
        if self._data is None:
            raise ValueError("not json")
        return self._data


def test_security_agent_detects_known_findings(monkeypatch):
    settings = SecuritySettings(base_url="http://localhost:5000", request_delay_seconds=0)
    discovery = DiscoveryResult(
        base_url=settings.normalized_base_url(),
        source="fallback",
        endpoints=[
            EndpointMetadata(path="/users/v1", method="GET", auth_required=True),
            EndpointMetadata(path="/users/v1/register", method="POST", auth_required=False),
            EndpointMetadata(path="/users/v1/login", method="POST", auth_required=False),
            EndpointMetadata(path="/users/v1/{user_id}", method="GET", auth_required=True),
            EndpointMetadata(path="/users/v1/{user_id}", method="DELETE", auth_required=True),
            EndpointMetadata(path="/users/v1/{user_id}/email", method="PUT", auth_required=True),
            EndpointMetadata(path="/users/v1/{user_id}/password", method="PUT", auth_required=True),
            EndpointMetadata(path="/books/v1", method="GET", auth_required=False),
            EndpointMetadata(path="/books/v1", method="POST", auth_required=True),
            EndpointMetadata(path="/books/v1/{book_title}", method="GET", auth_required=False),
        ],
    )
    agent = SecurityTestingAgent(settings)

    token = jwt.encode({"sub": "1"}, "secret", algorithm="HS256")
    auth = AuthContext("demo", "secret", token, 1, {"Authorization": f"Bearer {token}"})
    monkeypatch.setattr(SecurityTestingAgent, "_ensure_auth_context", lambda self, endpoints: auth)

    def fake_request(self, method, path, **kwargs):
        if method == "POST" and path == "/users/v1/login":
            payload = kwargs.get("json", {})
            if payload.get("username") == "rate_limit_probe":
                return FakeResponse(401, {"error": "invalid"})
            return FakeResponse(200, {"token": token})
        if method == "GET" and path == "/users/v1":
            return FakeResponse(200, [{"id": 1, "username": "demo", "password": "hash", "email": "demo@example.com"}])
        if method == "GET" and path == "/users/v1/name1":
            return FakeResponse(200, {"user_id": 2, "username": "name1"})
        if method == "GET" and path == "/users/v1/name2":
            return FakeResponse(200, {"user_id": 3, "username": "name2"})
        if method == "GET" and path == "/users/v1/2":
            return FakeResponse(200, {"user_id": 2, "username": "other"})
        if method == "PUT" and path in {"/users/v1/1/email", "/users/v1/demo/email"}:
            return FakeResponse(500, text="sqlite syntax error near OR")
        if method == "PUT" and path in {"/users/v1/1/password", "/users/v1/demo/password"}:
            return FakeResponse(400, {"error": "weak password"})
        if method == "DELETE" and path in {"/users/v1/2", "/users/v1/name1", "/users/v1/name2"}:
            return FakeResponse(403, {"error": "forbidden"})
        if method == "GET" and path == "/books/v1":
            return FakeResponse(200, [{"title": "Book 1"}])
        if method == "GET" and path == "/books/v1/Book%201":
            return FakeResponse(200, {"title": "Book 1"})
        if method == "POST" and path == "/books/v1":
            return FakeResponse(403, {"error": "forbidden"})
        if method == "POST" and path == "/users/v1/register":
            payload = kwargs.get("json", {})
            if payload.get("password") == "12345":
                return FakeResponse(400, {"error": "weak password"})
            return FakeResponse(201, {"username": "mass", "admin": True})
        return FakeResponse(404, {})

    monkeypatch.setattr(SecurityTestingAgent, "_request", fake_request)

    assessment = agent.assess(discovery)

    titles = {finding.title for finding in assessment.findings}
    assert "Excessive data exposure in user listing" in titles
    assert "Broken object level authorization on user detail endpoint" in titles
    assert "SQL injection indicators found in email update endpoint" in titles
    assert "Mass assignment allows privileged fields during registration" in titles
    assert any("JWT" in finding.title for finding in assessment.findings)  # JWT weakness detected
    assert any("exploit_command" in finding.evidence for finding in assessment.findings)


def test_security_agent_covers_missing_owasp_categories(monkeypatch):
    settings = SecuritySettings(base_url="http://localhost:5000", request_delay_seconds=0)
    discovery = DiscoveryResult(
        base_url=settings.normalized_base_url(),
        source="fallback",
        endpoints=[
            EndpointMetadata(path="/users/v1", method="GET", auth_required=True),
            EndpointMetadata(path="/users/v1/register", method="POST", auth_required=False),
            EndpointMetadata(path="/users/v1/login", method="POST", auth_required=False),
            EndpointMetadata(path="/users/v1/{user_id}", method="GET", auth_required=True),
            EndpointMetadata(path="/users/v1/{user_id}", method="DELETE", auth_required=True),
            EndpointMetadata(path="/users/v1/{user_id}/email", method="PUT", auth_required=True),
            EndpointMetadata(path="/users/v1/{user_id}/password", method="PUT", auth_required=True),
            EndpointMetadata(path="/books/v1", method="GET", auth_required=False),
            EndpointMetadata(path="/books/v1", method="POST", auth_required=True),
            EndpointMetadata(path="/books/v1/{book_title}", method="GET", auth_required=False),
        ],
    )
    agent = SecurityTestingAgent(settings)
    token = jwt.encode({"sub": "7", "exp": 9999999999}, "super-secret-signing-key", algorithm="HS256")
    auth = AuthContext("demo", "secret", token, 7, {"Authorization": f"Bearer {token}"})
    monkeypatch.setattr(SecurityTestingAgent, "_ensure_auth_context", lambda self, endpoints: auth)

    def fake_request(self, method, path, **kwargs):
        if method == "POST" and path == "/users/v1/register":
            payload = kwargs.get("json", {})
            if "admin" in payload or "is_admin" in payload or "role" in payload:
                return FakeResponse(201, {"username": payload.get("username"), "admin": True})
            return FakeResponse(201, {"username": payload.get("username")})
        if method == "POST" and path == "/users/v1/login":
            payload = kwargs.get("json", {})
            if payload.get("username") == "rate_limit_probe":
                return FakeResponse(401, {"error": "invalid"})
            return FakeResponse(200, {"token": token})
        if method == "GET" and path == "/users/v1":
            return FakeResponse(200, [{"id": 1, "username": "demo", "password": "hash"}])
        if method == "GET" and path in {"/users/v1/2", "/users/v1/name1", "/users/v1/name2"}:
            return FakeResponse(200, {"user_id": 2, "username": "other"})
        if method == "PUT" and path in {"/users/v1/7/email", "/users/v1/demo/email"}:
            return FakeResponse(500, text="traceback: sqlite syntax error")
        if method == "PUT" and path in {"/users/v1/7/password", "/users/v1/demo/password"}:
            return FakeResponse(200, {"message": "password updated"})
        if method == "DELETE" and path in {"/users/v1/1", "/users/v1/name1", "/users/v1/name2"}:
            return FakeResponse(204, None)
        if method == "POST" and path == "/books/v1":
            return FakeResponse(201, {"title": "Security Test Book"})
        if method == "GET" and path == "/books/v1":
            return FakeResponse(200, [{"title": "Book 1"}], headers={"Server": "Werkzeug/3.0"})
        if method == "GET" and path == "/books/v1/Book%201":
            return FakeResponse(500, text="sql exception")
        if method == "GET" and path == "/":
            return FakeResponse(500, text="Traceback (most recent call last)")
        if method == "GET" and path in {"/api/v1/users", "/users/v2"}:
            return FakeResponse(200, {"version": "legacy"})
        if method == "GET" and path in {"/me", "/users/v1/me"}:
            return FakeResponse(200, {"username": "demo", "admin": False})
        return FakeResponse(404, {})

    monkeypatch.setattr(SecurityTestingAgent, "_request", fake_request)

    assessment = agent.assess(discovery)
    categories = {finding.owasp_category for finding in assessment.findings}

    assert "API5: Broken Function Level Authorization" in categories
    assert "API7: Security Misconfiguration" in categories
    assert "API9: Improper Inventory Management" in categories
    assert "API10: Unsafe Consumption of APIs" in categories
    assert "API1: Broken Object Level Authorization" in categories
    assert "API2: Broken Authentication" in categories
