"""Security testing agent for the VAmPI target."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import quote

import jwt
import requests
import sqlparse

from config.settings import SecuritySettings
from models import DiscoveryResult, EndpointMetadata, SecurityAssessment, SecurityFinding


@dataclass
class AuthContext:
    username: Optional[str]
    password: Optional[str]
    token: Optional[str]
    user_id: Optional[int]
    headers: Dict[str, str]


class SecurityTestingAgent:
    """Run local-only security checks against the discovered endpoints."""

    def __init__(self, settings: Optional[SecuritySettings] = None) -> None:
        self.settings = settings or SecuritySettings()
        self.session = requests.Session()
        self.audit_events: List[Dict[str, Any]] = []
        self._last_endpoints: Sequence[EndpointMetadata] = []
        self._last_auth: Optional[AuthContext] = None

    def assess(self, discovery: DiscoveryResult) -> SecurityAssessment:
        self.audit_events = []
        self._last_endpoints = discovery.endpoints
        auth = self._ensure_auth_context(discovery.endpoints)
        self._last_auth = auth
        findings: List[SecurityFinding] = []
        notes = ["Assessment is scoped to the local VAmPI instance only."]
        findings.extend(self._jwt_findings(auth))
        findings.extend(self._password_policy_findings(discovery, auth))
        findings.extend(self._excessive_data_exposure_findings(discovery, auth))
        findings.extend(self._debug_endpoint_exposure_findings(discovery, auth))
        findings.extend(self._bola_findings(discovery, auth))
        findings.extend(self._function_level_authorization_findings(discovery, auth))
        findings.extend(self._injection_findings(discovery, auth))
        findings.extend(self._mass_assignment_findings(discovery, auth))
        findings.extend(self._security_misconfiguration_findings(discovery, auth))
        findings.extend(self._inventory_management_findings(discovery))
        findings.extend(self._asset_management_findings(discovery, auth))
        findings.extend(self._unsafe_consumption_findings(discovery))
        findings.extend(self._authentication_bypass_findings(discovery, auth))
        strict_findings, strict_notes = self._run_required_endpoint_validations(discovery, auth)
        findings.extend(strict_findings)
        notes.extend(strict_notes)
        findings.extend(self._rate_limiting_findings(discovery))
        self._enrich_findings_with_exploits(findings, auth)
        return SecurityAssessment(
            base_url=self.settings.normalized_base_url(),
            findings=findings,
            notes=notes,
            auth_context={
                "username": auth.username,
                "user_id": auth.user_id,
                "token_present": bool(auth.token),
            },
            audit_events=list(self.audit_events),
        )

    def _ensure_auth_context(self, endpoints: Sequence[EndpointMetadata]) -> AuthContext:
        register = self._find_endpoint(endpoints, "POST", "/users/v1/register")
        login = self._find_endpoint(endpoints, "POST", "/users/v1/login")
        if not register or not login:
            return AuthContext(None, None, None, None, {})

        username = self.settings.username or f"copilot_{self._stable_suffix()}"
        password = self.settings.password or f"Passw0rd!{self._stable_suffix()}"
        email = f"{username}@example.com"
        register_payload = {"username": username, "email": email, "password": password}

        try:
            register_response = self._request("POST", register.path, json=register_payload)
            if not register_response.ok and register_response.status_code not in {200, 201, 409}:
                return AuthContext(username, password, None, None, {})
        except requests.RequestException:
            return AuthContext(username, password, None, None, {})

        token = self._login(login.path, username, password)
        headers = (
            {
                "Authorization": f"Bearer {token}",
                "x-access-token": token,
                "X-Access-Token": token,
            }
            if token
            else {}
        )
        user_id = self._extract_user_id(token) if token else None
        return AuthContext(username, password, token, user_id, headers)

    def _login(self, path: str, username: str, password: str) -> Optional[str]:
        payload = {"username": username, "password": password}
        try:
            response = self._request("POST", path, json=payload)
        except requests.RequestException:
            return None
        data = self._as_json(response)
        if isinstance(data, dict):
            for key in ("token", "access_token", "jwt", "auth_token"):
                token = data.get(key)
                if isinstance(token, str) and token:
                    return token
        return None

    def _jwt_findings(self, auth: AuthContext) -> List[SecurityFinding]:
        if not auth.token:
            return [
                self._finding(
                    title="Authentication token was not issued",
                    severity="medium",
                    score=5.3,
                    category="API2: Broken Authentication",
                    endpoint="/users/v1/login",
                    method="POST",
                    evidence={"message": "The login flow did not return a JWT token during testing."},
                    remediation="Verify the login endpoint issues a signed JWT and that the test credentials are valid.",
                    poc="POST /users/v1/login with valid credentials and inspect the token response.",
                )
            ]

        findings: List[SecurityFinding] = []
        try:
            header = jwt.get_unverified_header(auth.token)
            claims = jwt.decode(auth.token, options={"verify_signature": False})
        except jwt.PyJWTError as exc:
            return [
                self._finding(
                    title="JWT parsing failed",
                    severity="high",
                    score=7.5,
                    category="API2: Broken Authentication",
                    endpoint="/users/v1/login",
                    method="POST",
                    evidence={"error": str(exc)},
                    remediation="Ensure JWTs are signed with a valid algorithm and can be parsed by standard JWT libraries.",
                    poc="Decode the token header and payload to verify standard JWT structure.",
                )
            ]

        if header.get("alg") in {"none", "None"}:
            findings.append(
                self._finding(
                    title="JWT uses an unsigned or 'none' algorithm",
                    severity="critical",
                    score=9.8,
                    category="API2: Broken Authentication",
                    endpoint="/users/v1/login",
                    method="POST",
                    evidence={"header": header},
                    remediation="Reject unsigned JWTs and enforce a strong signing algorithm such as HS256 or RS256.",
                    poc="Inspect the JWT header and confirm the algorithm is not 'none'.",
                )
            )

        weak_secret_tested = self._test_jwt_weak_secrets(auth.token, claims)
        if weak_secret_tested:
            findings.append(
                self._finding(
                    title="JWT can be forged with weak secrets",
                    severity="critical",
                    score=9.2,
                    category="API2: Broken Authentication",
                    endpoint="/users/v1/login",
                    method="POST",
                    evidence={"message": "Token successfully re-signed with common weak secrets"},
                    remediation="Use cryptographically strong secrets for HMAC signing and consider asymmetric algorithms like RS256.",
                    poc="Attempt to re-sign JWT with weak secrets like 'secret', 'password', or key derivable from public info.",
                )
            )

        algo_confusion = self._test_jwt_algorithm_confusion(auth.token, claims)
        if algo_confusion:
            findings.append(
                self._finding(
                    title="JWT algorithm confusion vulnerability detected",
                    severity="critical",
                    score=9.5,
                    category="API2: Broken Authentication",
                    endpoint="/users/v1/login",
                    method="POST",
                    evidence={"issue": "Token vulnerable to algorithm downgrade or confusion attacks"},
                    remediation="Enforce strict algorithm validation. Use asymmetric algorithms (RS256) and reject unexpected algorithm types.",
                    poc="Attempt algorithm confusion: downgrade RS256→HS256 or switch to 'none' algorithm.",
                )
            )

        if "nbf" not in claims:
            findings.append(
                self._finding(
                    title="JWT does not include not-before claim",
                    severity="low",
                    score=3.9,
                    category="API2: Broken Authentication",
                    endpoint="/users/v1/login",
                    method="POST",
                    evidence={"claims": {k: v for k, v in claims.items() if k in ("exp", "iat", "nbf", "sub")}},
                    remediation="Include nbf to prevent tokens being accepted before intended validity windows.",
                    poc="Decode JWT payload and verify nbf is missing.",
                )
            )

        claim_injection = self._test_jwt_claim_tampering(auth.token)
        if claim_injection:
            findings.append(
                self._finding(
                    title="JWT claims can be modified without validation",
                    severity="high",
                    score=8.4,
                    category="API2: Broken Authentication",
                    endpoint="/users/v1/login",
                    method="POST",
                    evidence={"message": "Tampered JWT claims accepted by application"},
                    remediation="Implement strict JWT signature verification and reject any modified tokens. Validate all critical claims.",
                    poc="Modify JWT payload (e.g., change user_id/role) and send modified token to protected endpoints.",
                )
            )

        return findings

    def _test_jwt_algorithm_confusion(self, token: str, claims: Dict[str, Any]) -> bool:
        """Test for JWT RS256→HS256 algorithm confusion (downgrade) vulnerabilities."""
        try:
            header = jwt.get_unverified_header(token)
            alg = header.get("alg", "").lower()
            if alg == "none":
                return True
            # HS-family tokens cannot be attacked by algorithm confusion;
            # only RS/ES tokens are susceptible to HS256 downgrade.
            if alg.startswith("rs") or alg.startswith("es"):
                try:
                    jwt.decode(token, "", algorithms=["HS256"])
                    return True
                except (jwt.InvalidSignatureError, jwt.DecodeError):
                    pass
        except Exception:
            pass
        return False

    def _test_jwt_claim_tampering(self, token: str) -> bool:
        """Test if the server accepts a JWT with tampered claims but the original signature."""
        try:
            import base64 as _b64
            import json as _json
            parts = token.split(".")
            if len(parts) != 3:
                return False
            padding = "=" * (4 - len(parts[1]) % 4)
            decoded_payload = _json.loads(_b64.urlsafe_b64decode(parts[1] + padding))
            tampered_claims = dict(decoded_payload)
            tampered_claims["admin"] = True
            tampered_claims["sub"] = "admin"
            tampered_payload = _b64.urlsafe_b64encode(
                _json.dumps(tampered_claims, separators=(",", ":")).encode()
            ).decode().rstrip("=")
            # Keep the original signature — a correctly-implemented server rejects this
            tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"
            headers = {
                "Authorization": f"Bearer {tampered_token}",
                "x-access-token": tampered_token,
            }
            try:
                resp = self._request("GET", "/me", headers=headers)
                if resp.status_code in {200, 201}:
                    data = self._as_json(resp)
                    if isinstance(data, dict) and data.get("username") == "admin":
                        return True
            except requests.RequestException:
                pass
        except Exception:
            pass
        return False

    def _test_jwt_weak_secrets(self, token: str, claims: Dict[str, Any]) -> bool:
        weak_secrets = [
            "secret1",  # VAmPI default SECRET_KEY
            "random", "secret", "password", "123456", "admin", "key",
            "flask", "django", "vampi", "test", "changeme",
        ]
        for secret in weak_secrets:
            if not secret:
                continue
            try:
                jwt.decode(token, secret, algorithms=["HS256"])
                return True
            except (jwt.InvalidSignatureError, jwt.DecodeError, jwt.InvalidKeyError):
                continue
        return False

    def _debug_endpoint_exposure_findings(
        self, discovery: DiscoveryResult, auth: AuthContext
    ) -> List[SecurityFinding]:
        endpoint = self._find_endpoint(discovery.endpoints, "GET", "/users/v1/_debug")
        if not endpoint:
            return []
        response = self._request("GET", endpoint.path, headers=dict(auth.headers) or None)
        data = self._as_json(response)
        leaked = self._find_sensitive_fields(data)
        if response.status_code in {200, 201} and leaked:
            return [
                self._finding(
                    title="Debug endpoint exposes sensitive user data",
                    severity="critical",
                    score=9.0,
                    category="API3: Excessive Data Exposure",
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    evidence={"status": response.status_code, "sensitive_fields": leaked},
                    remediation="Disable debug data endpoints in production and remove sensitive fields from all responses.",
                    poc=f"GET {endpoint.path} and inspect for password hashes, tokens, or admin fields.",
                )
            ]
        return []

    def _asset_management_findings(
        self, discovery: DiscoveryResult, auth: AuthContext
    ) -> List[SecurityFinding]:
        endpoint = self._find_endpoint(discovery.endpoints, "GET", "/createdb")
        if not endpoint:
            return []
        response = self._request("GET", endpoint.path, headers=dict(auth.headers) or None)
        if response.status_code in {200, 201, 202, 204}:
            return [
                self._finding(
                    title="Database initialization endpoint exposed in runtime API",
                    severity="high",
                    score=8.0,
                    category="API9: Improper Inventory Management",
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    evidence={"status": response.status_code, "response_excerpt": response.text[:180]},
                    remediation="Remove operational/bootstrap endpoints from runtime environments or guard them behind strict admin-only controls.",
                    poc=f"GET {endpoint.path} on runtime deployment and confirm it is reachable.",
                )
            ]
        return []

    def _password_policy_findings(self, discovery: DiscoveryResult, auth: AuthContext) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        weak_password = self.settings.weak_password_candidates[0] if self.settings.weak_password_candidates else "12345"
        register = self._find_endpoint(discovery.endpoints, "POST", "/users/v1/register")
        if register:
            username = f"weak_{self._stable_suffix()}"
            payload = {"username": username, "email": f"{username}@example.com", "password": weak_password}
            try:
                response = self._request("POST", register.path, json=payload)
            except requests.RequestException:
                response = None
            if response and response.status_code in {200, 201}:
                findings.append(
                    self._finding(
                        title="Weak password accepted during registration",
                        severity="high",
                        score=7.7,
                        category="API2: Broken Authentication",
                        endpoint=register.path,
                        method=register.method,
                        evidence={"status": response.status_code, "weak_password": weak_password},
                        remediation="Enforce minimum password length and complexity requirements in registration flows.",
                        poc=f"POST {register.path} with weak password '{weak_password}'.",
                    )
                )

        password_update = (
            self._find_endpoint(discovery.endpoints, "PUT", "/users/v1/{username}/password")
            or self._find_endpoint(discovery.endpoints, "PUT", "/users/v1/{user_id}/password")
        )
        if password_update:
            path_key = "username" if "{username}" in password_update.path else "user_id"
            target_identifier = auth.username or auth.user_id or self.settings.user_ids_to_probe[0]
            candidate_payloads = [
                {"password": weak_password},
                {"new_password": weak_password},
                {"password": weak_password, "old_password": auth.password or "test"},
            ]
            for candidate in candidate_payloads:
                try:
                    response = self._request(
                        "PUT",
                        password_update.path.format(**{path_key: target_identifier}),
                        json=candidate,
                        headers=dict(auth.headers) or None,
                    )
                except requests.RequestException:
                    continue
                if response.status_code in {200, 201, 202, 204}:
                    findings.append(
                        self._finding(
                            title="Weak password accepted in password update endpoint",
                            severity="high",
                            score=7.5,
                            category="API2: Broken Authentication",
                            endpoint=password_update.path,
                            method=password_update.method,
                            evidence={"status": response.status_code, "payload": candidate},
                            remediation="Reject weak passwords during password change and enforce strong password policy consistently.",
                            poc=f"PUT {password_update.path.format(**{path_key: target_identifier})} with weak password data.",
                        )
                    )
                    break
        return findings

    def _run_required_endpoint_validations(
        self, discovery: DiscoveryResult, auth: AuthContext
    ) -> Tuple[List[SecurityFinding], List[str]]:
        findings: List[SecurityFinding] = []
        notes: List[str] = []
        findings.extend(self._check_delete_user_endpoint(discovery, auth, notes))
        findings.extend(self._check_password_update_endpoint(discovery, auth, notes))
        findings.extend(self._check_book_title_lookup_endpoint(discovery, auth, notes))
        return findings, notes

    def _check_delete_user_endpoint(
        self, discovery: DiscoveryResult, auth: AuthContext, notes: List[str]
    ) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        delete_user_endpoint = (
            self._find_endpoint(discovery.endpoints, "DELETE", "/users/v1/{username}")
            or self._find_endpoint(discovery.endpoints, "DELETE", "/users/v1/{user_id}")
        )
        if not delete_user_endpoint:
            return findings

        path_key = "username" if "{username}" in delete_user_endpoint.path else "user_id"
        non_owner_target_ids = [value for value in self.settings.user_ids_to_probe if value != auth.username]
        if not non_owner_target_ids:
            return findings

        target_id = non_owner_target_ids[0]
        try:
            delete_response = self._request(
                "DELETE",
                delete_user_endpoint.path.format(**{path_key: target_id}),
                headers=dict(auth.headers) or None,
            )
            notes.append(f"Tested DELETE {delete_user_endpoint.path} with target={target_id}; status={delete_response.status_code}.")
            if delete_response.status_code in {200, 202, 204}:
                findings.append(
                    self._finding(
                        title="Unauthorized cross-user deletion allowed",
                        severity="critical",
                        score=9.3,
                        category="API1: Broken Object Level Authorization",
                        endpoint=delete_user_endpoint.path,
                        method=delete_user_endpoint.method,
                        evidence={"target_user": target_id, "status": delete_response.status_code},
                        remediation="Verify ownership and role authorization before allowing user account deletion.",
                        poc=f"DELETE {delete_user_endpoint.path.format(**{path_key: target_id})} as another authenticated user.",
                    )
                )
        except requests.RequestException as exc:
            notes.append(f"DELETE {delete_user_endpoint.path} test failed with error: {exc}.")
        return findings

    def _check_password_update_endpoint(
        self, discovery: DiscoveryResult, auth: AuthContext, notes: List[str]
    ) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        password_update_endpoint = (
            self._find_endpoint(discovery.endpoints, "PUT", "/users/v1/{username}/password")
            or self._find_endpoint(discovery.endpoints, "PUT", "/users/v1/{user_id}/password")
        )
        if not password_update_endpoint:
            return findings

        path_key = "username" if "{username}" in password_update_endpoint.path else "user_id"
        target_id = auth.username or auth.user_id or self.settings.user_ids_to_probe[0]
        weak_password = self.settings.weak_password_candidates[0] if self.settings.weak_password_candidates else "12345"
        candidate_password_payloads = [
            {"password": weak_password},
            {"new_password": weak_password},
            {"password": weak_password, "old_password": auth.password or "test"},
        ]
        observed_status_codes: List[int] = []
        for password_payload in candidate_password_payloads:
            try:
                password_update_response = self._request(
                    "PUT",
                    password_update_endpoint.path.format(**{path_key: target_id}),
                    json=password_payload,
                    headers=dict(auth.headers) or None,
                )
            except requests.RequestException as exc:
                notes.append(f"PUT {password_update_endpoint.path} test failed with error: {exc}.")
                continue
            observed_status_codes.append(password_update_response.status_code)
            if password_update_response.status_code in {200, 201, 202, 204}:
                findings.append(
                    self._finding(
                        title="Password update endpoint accepts weak password payloads",
                        severity="high",
                        score=7.5,
                        category="API2: Broken Authentication",
                        endpoint=password_update_endpoint.path,
                        method=password_update_endpoint.method,
                        evidence={"status": password_update_response.status_code, "payload": password_payload},
                        remediation="Enforce robust password validation and deny weak passwords on update operations.",
                        poc=f"PUT {password_update_endpoint.path.format(**{path_key: target_id})} with weak password payload.",
                    )
                )
                break
        if observed_status_codes:
            notes.append(f"Tested PUT {password_update_endpoint.path} with statuses={observed_status_codes}.")
        return findings

    def _check_book_title_lookup_endpoint(
        self, discovery: DiscoveryResult, auth: AuthContext, notes: List[str]
    ) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        book_lookup_endpoint = self._find_endpoint(discovery.endpoints, "GET", "/books/v1/{book_title}")
        if not book_lookup_endpoint:
            return findings

        discovered_title = self._discover_book_title_for_lookup(discovery, auth)
        encoded_title = quote(str(discovered_title), safe="")
        try:
            lookup_response = self._request(
                "GET",
                book_lookup_endpoint.path.format(book_title=encoded_title),
                headers=dict(auth.headers) or None,
            )
            notes.append(
                f"Tested GET /books/v1/{{book_title}} using book_title={discovered_title!r}; status={lookup_response.status_code}."
            )
            if self._has_backend_error_indicators(lookup_response):
                findings.append(
                    self._finding(
                        title="Book title lookup endpoint shows injection/error handling weakness",
                        severity="high",
                        score=7.2,
                        category="API8: Injection",
                        endpoint=book_lookup_endpoint.path,
                        method=book_lookup_endpoint.method,
                        evidence={"status": lookup_response.status_code, "response_excerpt": lookup_response.text[:240]},
                        remediation="Sanitize book title inputs and return generic error messages without backend details.",
                        poc=f"GET {book_lookup_endpoint.path.format(book_title=encoded_title)} and inspect backend error details.",
                    )
                )
        except requests.RequestException as exc:
            notes.append(f"GET /books/v1/{{book_title}} test failed with error: {exc}.")
        return findings

    def _discover_book_title_for_lookup(self, discovery: DiscoveryResult, auth: AuthContext) -> str:
        list_books_endpoint = self._find_endpoint(discovery.endpoints, "GET", "/books/v1")
        if not list_books_endpoint:
            return "test"
        try:
            list_books_response = self._request("GET", list_books_endpoint.path, headers=dict(auth.headers) or None)
        except requests.RequestException:
            return "test"
        list_payload = self._as_json(list_books_response)
        return self._extract_book_title(list_payload) or "test"

    @staticmethod
    def _has_backend_error_indicators(response: requests.Response) -> bool:
        response_text = response.text.lower()
        return response.status_code >= 500 or any(
            marker in response_text for marker in ("traceback", "sql", "syntax error", "exception")
        )

    def _excessive_data_exposure_findings(self, discovery: DiscoveryResult, auth: AuthContext) -> List[SecurityFinding]:
        endpoint = self._find_endpoint(discovery.endpoints, "GET", "/users/v1")
        if not endpoint:
            return []
        self._last_endpoints = discovery.endpoints
        headers = dict(auth.headers)
        response = self._request("GET", endpoint.path, headers=headers or None)
        data = self._as_json(response)
        findings: List[SecurityFinding] = []
        
        leaked = self._find_sensitive_fields(data)
        if leaked:
            findings.append(
                self._finding(
                    title="Excessive data exposure in user listing",
                    severity="high",
                    score=8.1,
                    category="API3: Excessive Data Exposure",
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    evidence={"sensitive_fields": leaked, "sample_status": response.status_code},
                    remediation="Filter sensitive fields from user list responses and return only the minimum required profile data.",
                    poc="GET /users/v1 and inspect the JSON payload for passwords, hashes, tokens, or administrative flags.",
                )
            )
        
        email_leaked = self._check_email_exposure(data)
        if email_leaked:
            findings.append(
                self._finding(
                    title="Email addresses exposed in user listing endpoint",
                    severity="high",
                    score=7.8,
                    category="API3: Excessive Data Exposure",
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    evidence={"email_count": email_leaked, "sample_status": response.status_code},
                    remediation="Remove email addresses or mask them in list endpoints. Return only to authenticated users requesting their own data.",
                    poc="GET /users/v1 and confirm email fields are visible to unauthorized users.",
                )
            )
        
        return findings

    @staticmethod
    def _check_email_exposure(data: Any) -> int:
        if not isinstance(data, list):
            return 0
        email_count = 0
        for item in data:
            if isinstance(item, dict) and "email" in item:
                email_count += 1
        return email_count

    def _bola_findings(self, discovery: DiscoveryResult, auth: AuthContext) -> List[SecurityFinding]:
        # Prefer the OpenAPI {username} template; fall back to the legacy {user_id} entry
        endpoint = (
            self._find_endpoint(discovery.endpoints, "GET", "/users/v1/{username}")
            or self._find_endpoint(discovery.endpoints, "GET", "/users/v1/{user_id}")
        )
        if not endpoint:
            return []
        path_key = "username" if "{username}" in endpoint.path else "user_id"
        target_usernames = [value for value in self.settings.user_ids_to_probe if value != auth.username]
        for target_username in target_usernames:
            try:
                response = self._request(
                    "GET",
                    endpoint.path.format(**{path_key: target_username}),
                    headers=dict(auth.headers) or None,
                )
            except requests.RequestException:
                continue
            if response.status_code not in {200, 201}:
                continue
            data = self._as_json(response)
            if SecurityTestingAgent._response_refers_to_user(data, target_username):
                return [
                    self._finding(
                        title="Broken object level authorization on user detail endpoint",
                        severity="critical",
                        score=9.1,
                        category="API1: Broken Object Level Authorization",
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        evidence={"target_username": target_username, "status": response.status_code, "response": data},
                        remediation="Enforce per-object authorization checks before returning user records.",
                        poc=f"GET {endpoint.path.format(**{path_key: target_username})} with a different authenticated user and compare the response.",
                    )
                ]
        return []

    def _injection_findings(self, discovery: DiscoveryResult, auth: AuthContext) -> List[SecurityFinding]:
        # Prefer the OpenAPI {username} template; fall back to the legacy {user_id} entry
        endpoint = (
            self._find_endpoint(discovery.endpoints, "PUT", "/users/v1/{username}/email")
            or self._find_endpoint(discovery.endpoints, "PUT", "/users/v1/{user_id}/email")
        )
        if not endpoint:
            return []
        target_user_identifier = auth.username or self.settings.user_ids_to_probe[0]
        path_key = "username" if "{username}" in endpoint.path else "user_id"
        findings: List[SecurityFinding] = []
        payloads = self._generate_context_aware_payloads(endpoint.path, "email")
        accepted_malicious: Optional[str] = None
        for payload in payloads:
            body = {"email": payload}
            fmt_path = endpoint.path.format(**{path_key: target_user_identifier})
            try:
                response = self._request("PUT", fmt_path, json=body, headers=dict(auth.headers) or None)
            except requests.RequestException as exc:
                findings.append(
                    self._finding(
                        title="Injection endpoint triggered request failure",
                        severity="high",
                        score=7.1,
                        category="API8: Injection",
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        evidence={"payload": sqlparse.format(payload, strip_comments=True), "error": str(exc)},
                        remediation="Validate email input with strict allow-lists and parameterized queries on the server side.",
                        poc=f"PUT {fmt_path} with email={payload!r}.",
                    )
                )
                continue
            response_text = response.text.lower()
            if response.status_code >= 500 or any(marker in response_text for marker in self.settings.sql_error_markers):
                findings.append(
                    self._finding(
                        title="SQL injection indicators found in email update endpoint",
                        severity="critical",
                        score=9.0,
                        category="API8: Injection",
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        evidence={
                            "payload": sqlparse.format(payload, keyword_case="upper", strip_comments=True),
                            "payloads_tested": payloads[:8],
                            "status": response.status_code,
                            "response_excerpt": response.text[:240],
                        },
                        remediation="Use parameterized queries and reject email values that do not match a strict email pattern.",
                        poc=f"PUT {fmt_path} with email={payload!r}.",
                    )
                )
                return findings
            # Track silently-accepted malicious payloads as blind/stored injection indicator
            if response.status_code in {200, 201, 204} and accepted_malicious is None:
                accepted_malicious = payload
        if not findings and accepted_malicious is not None:
            fmt_path = endpoint.path.format(**{path_key: target_user_identifier})
            findings.append(
                self._finding(
                    title="Email update endpoint accepts unsanitized SQL injection payloads",
                    severity="high",
                    score=8.2,
                    category="API8: Injection",
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    evidence={
                        "sample_payload": sqlparse.format(accepted_malicious, keyword_case="upper", strip_comments=True),
                        "payloads_tested": payloads[:8],
                        "status": 200,
                        "note": "Payload accepted without error — potential blind/stored SQL injection.",
                    },
                    remediation="Use parameterized queries and validate that email fields reject non-email input.",
                    poc=f"PUT {fmt_path} with email={accepted_malicious!r} and verify storage.",
                )
            )

        password_endpoint = (
            self._find_endpoint(discovery.endpoints, "PUT", "/users/v1/{username}/password")
            or self._find_endpoint(discovery.endpoints, "PUT", "/users/v1/{user_id}/password")
        )
        if password_endpoint:
            password_path_key = "username" if "{username}" in password_endpoint.path else "user_id"
            password_target_identifier = auth.username or self.settings.user_ids_to_probe[0]
            password_payloads = self._generate_context_aware_payloads(password_endpoint.path, "password")
            password_accepted_malicious: Optional[str] = None
            for payload in password_payloads:
                body = {"password": payload}
                fmt_path = password_endpoint.path.format(**{password_path_key: password_target_identifier})
                try:
                    response = self._request("PUT", fmt_path, json=body, headers=dict(auth.headers) or None)
                except requests.RequestException as exc:
                    findings.append(
                        self._finding(
                            title="Injection endpoint triggered request failure",
                            severity="high",
                            score=7.1,
                            category="API8: Injection",
                            endpoint=password_endpoint.path,
                            method=password_endpoint.method,
                            evidence={"payload": sqlparse.format(payload, strip_comments=True), "error": str(exc)},
                            remediation="Validate password input with strict allow-lists and avoid directly interpolating user-controlled values.",
                            poc=f"PUT {fmt_path} with password={payload!r}.",
                        )
                    )
                    continue
                response_text = response.text.lower()
                if response.status_code >= 500 or any(marker in response_text for marker in self.settings.sql_error_markers):
                    findings.append(
                        self._finding(
                            title="SQL injection indicators found in password update endpoint",
                            severity="critical",
                            score=9.0,
                            category="API8: Injection",
                            endpoint=password_endpoint.path,
                            method=password_endpoint.method,
                            evidence={
                                "payload": sqlparse.format(payload, keyword_case="upper", strip_comments=True),
                                "payloads_tested": password_payloads[:8],
                                "status": response.status_code,
                                "response_excerpt": response.text[:240],
                            },
                            remediation="Use parameterized queries and reject password values that do not match a strict policy.",
                            poc=f"PUT {fmt_path} with password={payload!r}.",
                        )
                    )
                    return findings
                if response.status_code in {200, 201, 202, 204} and password_accepted_malicious is None and any(
                    marker in payload for marker in ("'", '"', ";", " OR ", "UNION", "SELECT", "--")
                ):
                    password_accepted_malicious = payload
            if not findings and password_accepted_malicious is not None:
                fmt_path = password_endpoint.path.format(**{password_path_key: password_target_identifier})
                findings.append(
                    self._finding(
                        title="Password update endpoint accepts SQL injection payloads",
                        severity="high",
                        score=8.1,
                        category="API8: Injection",
                        endpoint=password_endpoint.path,
                        method=password_endpoint.method,
                        evidence={
                            "sample_payload": sqlparse.format(password_accepted_malicious, keyword_case="upper", strip_comments=True),
                            "payloads_tested": password_payloads[:8],
                            "status": 200,
                            "note": "Payload accepted without error — potential blind/stored SQL injection.",
                        },
                        remediation="Use parameterized queries and validate that password fields reject SQL metacharacters.",
                        poc=f"PUT {fmt_path} with password={password_accepted_malicious!r} and verify persistence.",
                    )
                )
        return findings

    def _authentication_bypass_findings(self, discovery: DiscoveryResult, auth: AuthContext) -> List[SecurityFinding]:
        # Prefer the OpenAPI {username} endpoint; fall back to the legacy {user_id} entry
        endpoint = (
            self._find_endpoint(discovery.endpoints, "GET", "/users/v1/{username}")
            or self._find_endpoint(discovery.endpoints, "GET", "/users/v1/{user_id}")
        )
        if not endpoint:
            return []
        path_key = "username" if "{username}" in endpoint.path else "user_id"
        # VAmPI uses username-based paths (not integer IDs)
        target_id = auth.username or self.settings.user_ids_to_probe[0]
        findings: List[SecurityFinding] = []
        fmt_path = endpoint.path.format(**{path_key: target_id})
        try:
            no_auth_response = self._request("GET", fmt_path)
            if no_auth_response.status_code in {200, 201}:
                findings.append(
                    self._finding(
                        title="Authentication bypass possible without token",
                        severity="critical",
                        score=9.4,
                        category="API2: Broken Authentication",
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        evidence={"status": no_auth_response.status_code},
                        remediation="Require valid authentication token checks for all protected user-resource endpoints.",
                        poc=f"GET {fmt_path} without Authorization headers.",
                    )
                )
        except requests.RequestException:
            pass

        update_endpoints = []
        password_update = (
            self._find_endpoint(discovery.endpoints, "PUT", "/users/v1/{username}/password")
            or self._find_endpoint(discovery.endpoints, "PUT", "/users/v1/{user_id}/password")
        )
        email_update = (
            self._find_endpoint(discovery.endpoints, "PUT", "/users/v1/{username}/email")
            or self._find_endpoint(discovery.endpoints, "PUT", "/users/v1/{user_id}/email")
        )
        if password_update:
            update_endpoints.append((password_update, {"password": "CrossUser!123"}))
        if email_update:
            update_endpoints.append((email_update, {"email": "crossuser@example.com"}))
        for update_endpoint, body in update_endpoints:
            update_path_key = "username" if "{username}" in update_endpoint.path else "user_id"
            for target_username in [value for value in self.settings.user_ids_to_probe if value != auth.username]:
                try:
                    cross_user_response = self._request(
                        "PUT",
                        update_endpoint.path.format(**{update_path_key: target_username}),
                        json=body,
                        headers=dict(auth.headers) or None,
                    )
                except requests.RequestException:
                    continue
                if cross_user_response.status_code in {200, 201, 202, 204}:
                    findings.append(
                        self._finding(
                            title="Authentication bypass allows cross-user profile updates",
                            severity="critical",
                            score=9.3,
                            category="API2: Broken Authentication",
                            endpoint=update_endpoint.path,
                            method=update_endpoint.method,
                            evidence={"target_username": target_username, "status": cross_user_response.status_code, "payload": body},
                            remediation="Bind profile updates to the authenticated subject and reject cross-user modifications unless the caller is an admin.",
                            poc=f"PUT {update_endpoint.path.format(**{update_path_key: target_username})} with another user's token.",
                        )
                    )
                    return findings
        malformed_headers = {"Authorization": "Bearer invalid.invalid.invalid", "x-access-token": "invalid.invalid.invalid"}
        try:
            malformed_response = self._request("GET", fmt_path, headers=malformed_headers)
            if malformed_response.status_code in {200, 201}:
                findings.append(
                    self._finding(
                        title="Authentication bypass possible with malformed JWT",
                        severity="high",
                        score=8.1,
                        category="API2: Broken Authentication",
                        endpoint=endpoint.path,
                        method=endpoint.method,
                        evidence={"status": malformed_response.status_code},
                        remediation="Validate JWT signature, structure, expiration, and claims before authorization decisions.",
                        poc=f"GET {fmt_path} with a malformed bearer token.",
                    )
                )
        except requests.RequestException:
            pass
        return findings

    def _function_level_authorization_findings(self, discovery: DiscoveryResult, auth: AuthContext) -> List[SecurityFinding]:
        endpoint = self._find_endpoint(discovery.endpoints, "POST", "/books/v1")
        if not endpoint:
            return []
        payload = {"title": f"Security Test Book {self._stable_suffix()}", "description": "API5 probe"}
        headers = dict(auth.headers) if auth.headers else None
        try:
            response = self._request("POST", endpoint.path, json=payload, headers=headers)
        except requests.RequestException as exc:
            return [
                self._finding(
                    title="Function level authorization test could not complete",
                    severity="medium",
                    score=5.0,
                    category="API5: Broken Function Level Authorization",
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    evidence={"error": str(exc)},
                    remediation="Validate administrative access controls before exposing state-changing book management operations.",
                    poc=f"POST {endpoint.path} with a standard authenticated user token.",
                )
            ]
        if response.status_code in {200, 201, 202, 204}:
            return [
                self._finding(
                    title="Broken function level authorization on book creation",
                    severity="high",
                    score=8.4,
                    category="API5: Broken Function Level Authorization",
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    evidence={"status": response.status_code, "response": self._as_json(response) or response.text[:200]},
                    remediation="Restrict privileged book-management operations to authorized roles only.",
                    poc=f"POST {endpoint.path} with a normal authenticated user and observe whether creation succeeds.",
                )
            ]
        return []

    def _mass_assignment_findings(self, discovery: DiscoveryResult, auth: AuthContext) -> List[SecurityFinding]:
        endpoint = self._find_endpoint(discovery.endpoints, "POST", "/users/v1/register")
        if not endpoint:
            return []
        username = f"mass_{self._stable_suffix()}"
        password = f"MassAssign!{self._stable_suffix()}"
        payload: Dict[str, Any] = {
            "username": username,
            "email": f"{username}@example.com",
            "password": password,
        }
        for key in self.settings.mass_assignment_keys:
            if key == "role":
                payload[key] = "admin"
            elif key == "permissions":
                payload[key] = ["admin"]
            else:
                payload[key] = True
        try:
            response = self._request("POST", endpoint.path, json=payload)
        except requests.RequestException as exc:
            return [
                self._finding(
                    title="Mass assignment test could not complete",
                    severity="medium",
                    score=5.0,
                    category="API6: Mass Assignment",
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    evidence={"error": str(exc)},
                    remediation="Review request binding and explicitly whitelist user-registration fields.",
                    poc=f"POST {endpoint.path} with privileged fields such as admin/is_admin/role.",
                )
            ]
        data = self._as_json(response)
        if response.status_code not in {200, 201, 202, 204}:
            return []

        admin_confirmed = self._verify_admin_privilege_via_me(username, password)
        if admin_confirmed:
            return [
                self._finding(
                    title="Mass assignment allows and persists privileged fields during registration",
                    severity="critical",
                    score=9.1,
                    category="API6: Mass Assignment",
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    evidence={"payload_keys": sorted(payload), "response": data, "status": response.status_code, "admin_verified": True},
                    remediation="Explicitly whitelist registration fields and discard any privilege-related request properties.",
                    poc=f"POST {endpoint.path} with admin/is_admin/role fields and verify via GET /me.",
                )
            ]
        return [
            self._finding(
                title="Mass assignment allows privileged fields during registration",
                severity="high",
                score=8.6,
                category="API6: Mass Assignment",
                endpoint=endpoint.path,
                method=endpoint.method,
                evidence={"payload_keys": sorted(payload), "response": data, "status": response.status_code},
                remediation="Explicitly whitelist registration fields and discard any privilege-related request properties.",
                poc=f"POST {endpoint.path} with admin/is_admin/role fields and check whether they are accepted.",
            )
        ]

    def _verify_admin_privilege_via_me(self, username: str, password: str) -> bool:
        login_endpoint = None
        for endpoint in getattr(self, '_last_endpoints', []):
            if endpoint.method == "POST" and "/login" in endpoint.path:
                login_endpoint = endpoint
                break
        if not login_endpoint:
            return False
        
        try:
            login_response = self._request("POST", login_endpoint.path, json={"username": username, "password": password})
            token_data = self._as_json(login_response)
            if isinstance(token_data, dict):
                for key in ("token", "access_token", "jwt", "auth_token"):
                    token = token_data.get(key)
                    if isinstance(token, str) and token:
                        headers = {"Authorization": f"Bearer {token}", "x-access-token": token}
                        # VAmPI self-profile endpoint is /me; /users/v1/me is a fallback
                        for me_path in ("/me", "/users/v1/me"):
                            me_response = self._request("GET", me_path, headers=headers)
                            if me_response.status_code not in {200, 201}:
                                continue
                            me_data = self._as_json(me_response)
                            if isinstance(me_data, dict):
                                for admin_key in ("admin", "is_admin", "role"):
                                    value = me_data.get(admin_key)
                                    if admin_key == "role" and value in ("admin", "administrator"):
                                        return True
                                    elif admin_key in ("admin", "is_admin") and value is True:
                                        return True
                            break
                        return False
        except requests.RequestException:
            pass
        return False

    def _security_misconfiguration_findings(self, discovery: DiscoveryResult, auth: AuthContext) -> List[SecurityFinding]:
        probe_paths = list(self.settings.misconfiguration_probe_paths)
        headers = dict(auth.headers) if auth.headers else None
        findings: List[SecurityFinding] = []
        for path in probe_paths:
            try:
                response = self._request("GET", path, headers=headers)
            except requests.RequestException:
                continue
            server_header = response.headers.get("Server", "")
            cors_origin = response.headers.get("Access-Control-Allow-Origin", "")
            if server_header and any(marker in server_header.lower() for marker in ("werkzeug", "flask", "python")):
                findings.append(
                    self._finding(
                        title="Verbose server banner exposes implementation details",
                        severity="low",
                        score=3.7,
                        category="API7: Security Misconfiguration",
                        endpoint=path,
                        method="GET",
                        evidence={"server": server_header},
                        remediation="Strip framework and version banners from API responses.",
                        poc=f"GET {path} and inspect the Server header.",
                    )
                )
                break
            if cors_origin == "*":
                findings.append(
                    self._finding(
                        title="Permissive CORS policy allows any origin",
                        severity="medium",
                        score=6.2,
                        category="API7: Security Misconfiguration",
                        endpoint=path,
                        method="GET",
                        evidence={"access_control_allow_origin": cors_origin},
                        remediation="Restrict CORS to trusted origins and avoid wildcard responses for authenticated APIs.",
                        poc=f"GET {path} and inspect Access-Control-Allow-Origin.",
                    )
                )
                break
            if response.status_code >= 500 or "traceback" in response.text.lower() or "debug" in response.text.lower():
                findings.append(
                    self._finding(
                        title="Verbose error handling reveals implementation details",
                        severity="medium",
                        score=6.5,
                        category="API7: Security Misconfiguration",
                        endpoint=path,
                        method="GET",
                        evidence={"status": response.status_code, "response_excerpt": response.text[:240]},
                        remediation="Disable debug mode and sanitize error responses to avoid leaking stack traces or runtime details.",
                        poc=f"GET {path} and inspect the response body for framework or traceback details.",
                    )
                )
                break
        return findings

    def _inventory_management_findings(self, discovery: DiscoveryResult) -> List[SecurityFinding]:
        candidate_paths = list(self.settings.inventory_probe_paths)
        findings: List[SecurityFinding] = []
        for path in candidate_paths:
            try:
                response = self._request("GET", path)
            except requests.RequestException:
                continue
            if response.status_code not in {404, 405}:
                findings.append(
                    self._finding(
                        title="Undocumented or legacy API version remains reachable",
                        severity="medium",
                        score=6.0,
                        category="API9: Improper Inventory Management",
                        endpoint=path,
                        method="GET",
                        evidence={"status": response.status_code, "response_excerpt": response.text[:200]},
                        remediation="Retire unused versions and maintain a complete, enforced API inventory with explicit deprecation.",
                        poc=f"GET {path} and confirm the older endpoint still responds.",
                    )
                )
                break
        return findings

    def _unsafe_consumption_findings(self, discovery: DiscoveryResult) -> List[SecurityFinding]:
        collection_paths = [
            endpoint.path
            for endpoint in discovery.endpoints
            if endpoint.method == "GET" and "{" not in endpoint.path and endpoint.path.endswith(self.settings.collection_endpoint_suffix)
        ]
        findings: List[SecurityFinding] = []
        for path in collection_paths:
            try:
                response = self._request("GET", path)
            except requests.RequestException:
                continue
            data = self._as_json(response)
            if not isinstance(data, (list, dict)):
                continue
            if isinstance(data, dict) and any(key in data for key in ("items", "results", "data", "page", "limit", "offset")):
                continue
            if isinstance(data, list) or isinstance(data, dict):
                findings.append(
                    self._finding(
                        title="Collection endpoint lacks pagination or consumption controls",
                        severity="low",
                        score=4.0,
                        category="API10: Unsafe Consumption of APIs",
                        endpoint=path,
                        method="GET",
                        evidence={"response_type": type(data).__name__, "status": response.status_code},
                        remediation="Add pagination, filtering, and response-size controls for collection endpoints.",
                        poc=f"GET {path} and observe that the collection is returned without pagination metadata.",
                    )
                )
                break
        return findings

    def _rate_limiting_findings(self, discovery: DiscoveryResult) -> List[SecurityFinding]:
        endpoint = self._find_endpoint(discovery.endpoints, "POST", "/users/v1/login")
        if not endpoint:
            return []
        status_codes: List[int] = []
        for _ in range(self.settings.rate_limit_probe_attempts):
            try:
                response = self._request("POST", endpoint.path, json={"username": "rate_limit_probe", "password": "incorrect"})
            except requests.RequestException:
                break
            status_codes.append(response.status_code)
            time.sleep(self.settings.request_delay_seconds)
        if status_codes and all(status < 429 for status in status_codes):
            return [
                self._finding(
                    title="No rate limiting observed on repeated login attempts",
                    severity="low",
                    score=4.3,
                    category="API4: Unrestricted Resource Consumption",
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    evidence={"status_codes": status_codes},
                    remediation="Introduce request throttling and lockout controls for repeated failed logins.",
                    poc="Send several rapid login attempts and confirm the API does not return 429 or lockout responses.",
                )
            ]
        return []

    def _request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        url = f"{self.settings.normalized_base_url()}{path}"
        kwargs.setdefault("timeout", self.settings.timeout_seconds)
        start = time.perf_counter()
        headers = kwargs.get("headers") or {}
        try:
            response = self.session.request(method.upper(), url, **kwargs)
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            self.audit_events.append(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "method": method.upper(),
                    "path": path,
                    "status_code": response.status_code,
                    "duration_ms": duration_ms,
                    "header_keys": sorted(list(headers.keys())) if isinstance(headers, dict) else [],
                    "error": None,
                }
            )
            return response
        except requests.RequestException as exc:
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            self.audit_events.append(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "method": method.upper(),
                    "path": path,
                    "status_code": None,
                    "duration_ms": duration_ms,
                    "header_keys": sorted(list(headers.keys())) if isinstance(headers, dict) else [],
                    "error": str(exc),
                }
            )
            raise

    @staticmethod
    def _find_endpoint(endpoints: Sequence[EndpointMetadata], method: str, path: str) -> Optional[EndpointMetadata]:
        for endpoint in endpoints:
            if endpoint.method == method and endpoint.path == path:
                return endpoint
        return None

    @staticmethod
    def _as_json(response: requests.Response) -> Any:
        try:
            return response.json()
        except ValueError:
            return None

    def _find_sensitive_fields(self, data: Any) -> List[str]:
        sensitive_keys = set(self.settings.sensitive_keys)
        found: List[str] = []
        if isinstance(data, dict):
            for key, value in data.items():
                if str(key).lower() in sensitive_keys:
                    found.append(str(key))
                found.extend(self._find_sensitive_fields(value))
        elif isinstance(data, list):
            for item in data:
                found.extend(self._find_sensitive_fields(item))
        return sorted(set(found))

    @staticmethod
    def _response_refers_to_user(data: Any, user_identifier: Any) -> bool:
        if isinstance(data, dict):
            for key in ("user_id", "id", "uid"):
                if str(data.get(key)) == str(user_identifier):
                    return True
            if isinstance(user_identifier, str) and "username" in data:
                if str(data.get("username")) == str(user_identifier):
                    return True
            return any(SecurityTestingAgent._response_refers_to_user(value, user_identifier) for value in data.values())
        if isinstance(data, list):
            return any(SecurityTestingAgent._response_refers_to_user(item, user_identifier) for item in data)
        if isinstance(data, (str, int, float)):
            return str(data) == str(user_identifier)
        return False

    def _privilege_field_detected(self, data: Any, payload: Dict[str, Any]) -> bool:
        if isinstance(data, dict):
            suspicious_keys = set(self.settings.mass_assignment_keys)
            for key in suspicious_keys:
                if key in data:
                    value = data[key]
                    if value is True or str(value).lower() in {"true", "1", "admin", "yes"}:
                        return True
            for key in payload:
                if key in suspicious_keys and key in data and data[key] == payload[key]:
                    return True
        return False

    @staticmethod
    def _extract_book_title(data: Any) -> Optional[str]:
        if isinstance(data, list):
            for item in data:
                title = SecurityTestingAgent._extract_book_title(item)
                if title:
                    return title
        if isinstance(data, dict):
            for key in ("book_title", "title", "name"):
                value = data.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
            for value in data.values():
                title = SecurityTestingAgent._extract_book_title(value)
                if title:
                    return title
        return None

    @staticmethod
    def _finding(
        title: str,
        severity: str,
        score: float,
        category: str,
        endpoint: str,
        method: str,
        evidence: Dict[str, Any],
        remediation: str,
        poc: str,
    ) -> SecurityFinding:
        return SecurityFinding(
            title=title,
            severity=severity,
            cvss_score=score,
            owasp_category=category,
            endpoint=endpoint,
            method=method,
            evidence=evidence,
            remediation=remediation,
            proof_of_concept=poc,
        )

    def _enrich_findings_with_exploits(self, findings: List[SecurityFinding], auth: AuthContext) -> None:
        """Enrich findings with both curl commands and live PoC results."""
        from security_agent.exploit_generator import ExploitGenerator

        generator = ExploitGenerator(
            base_url=self.settings.normalized_base_url(),
            request_delay=self.settings.request_delay_seconds,
        )

        try:
            exploit_results = generator.generate_exploits(findings, auth.token)
        except Exception as e:
            self.audit_events.append(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event": "exploit_generation_error",
                    "error": str(e),
                }
            )
            exploit_results = []

        for finding in findings:
            if finding.evidence.get("exploit_command"):
                continue
            headers = dict(auth.headers) if auth.headers else {}
            exploit = self._build_exploit_command(finding.method, finding.endpoint, headers, finding)
            finding.evidence["exploit_command"] = exploit

            related_results = [r for r in exploit_results if r.endpoint == finding.endpoint]
            if related_results:
                successful = [r for r in related_results if r.success]
                finding.evidence["poc_results"] = {
                    "total_attempts": len(related_results),
                    "successful": len(successful),
                    "sample_payloads": [
                        {
                            "payload": r.payload,
                            "status": r.status_code,
                            "success": r.success,
                        }
                        for r in related_results[:3]
                    ],
                }


    def _build_exploit_command(
        self, method: str, endpoint: str, headers: Dict[str, str], finding: SecurityFinding
    ) -> str:
        header_flags = " ".join(f"-H '{key}: {value}'" for key, value in headers.items() if value)
        payload_hint = ""
        if finding.owasp_category == "API8: Injection":
            payload_hint = "-H 'Content-Type: application/json' -d '{\"email\":\"test@example.com\\' OR \\'1\\'=\\'1\"}'"
        elif finding.owasp_category == "API6: Mass Assignment":
            primary_key = self.settings.mass_assignment_keys[0] if self.settings.mass_assignment_keys else "admin"
            payload_hint = (
                "-H 'Content-Type: application/json' "
                f"-d '{{\"username\":\"demo\",\"email\":\"demo@example.com\",\"password\":\"Passw0rd!\",\"{primary_key}\":true}}'"
            )
        elif finding.owasp_category == "API2: Broken Authentication" and "login" in endpoint:
            weak_password = self.settings.weak_password_candidates[0] if self.settings.weak_password_candidates else "12345"
            payload_hint = f"-H 'Content-Type: application/json' -d '{{\"username\":\"demo\",\"password\":\"{weak_password}\"}}'"
        return f"curl -i -X {method.upper()} '{self.settings.normalized_base_url()}{endpoint}' {header_flags} {payload_hint}".strip()

    def _generate_context_aware_payloads(self, endpoint: str, parameter: str) -> List[str]:
        base = list(self.settings.injection_payloads)
        lowered_endpoint = endpoint.lower()
        lowered_param = parameter.lower()
        payloads: List[str] = []

        if "email" in lowered_param:
            payloads.extend(list(self.settings.email_context_payloads))
        if "book" in lowered_endpoint or "title" in lowered_param:
            payloads.extend(list(self.settings.book_context_payloads))
        payloads.extend(base)
        deduped: List[str] = []
        seen = set()
        for item in payloads:
            if item not in seen:
                deduped.append(item)
                seen.add(item)
        return deduped

    @staticmethod
    def _extract_user_id(token: str) -> Optional[int]:
        try:
            claims = jwt.decode(token, options={"verify_signature": False})
        except jwt.PyJWTError:
            return None
        for key in ("user_id", "id", "sub"):
            value = claims.get(key)
            if isinstance(value, int):
                return value
            if isinstance(value, str) and value.isdigit():
                return int(value)
        return None

    @staticmethod
    def _stable_suffix() -> str:
        return hashlib.sha1(str(time.time()).encode("utf-8")).hexdigest()[:8]