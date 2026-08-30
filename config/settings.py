"""Runtime settings for the API security testing duo."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from config.resources import load_mapping


def _load_security_payloads() -> Dict[str, Any]:
    return load_mapping("security_payloads.json")


def _load_security_policies() -> Dict[str, Any]:
    return load_mapping("security_policies.json")


def _load_discovery_catalog() -> Dict[str, Any]:
    return load_mapping("discovery_catalog.json")


def _load_compliance_mapping() -> Dict[str, Any]:
    return load_mapping("compliance_mapping.json")


@dataclass(frozen=True)
class SecuritySettings:
    base_url: str = field(default_factory=lambda: os.getenv("VAMPI_BASE_URL", "http://localhost:5000"))
    timeout_seconds: float = field(default_factory=lambda: float(os.getenv("VAMPI_TIMEOUT", "5")))
    request_delay_seconds: float = field(default_factory=lambda: float(os.getenv("VAMPI_REQUEST_DELAY", "0.1")))
    output_dir: Path = field(default_factory=lambda: Path(os.getenv("VAMPI_OUTPUT_DIR", "reports")))
    username: Optional[str] = field(default_factory=lambda: os.getenv("VAMPI_TEST_USERNAME"))
    password: Optional[str] = field(default_factory=lambda: os.getenv("VAMPI_TEST_PASSWORD"))

    openapi_paths: Tuple[str, ...] = (
        "/openapi.json",
        "/swagger.json",
        "/api-docs",
        "/docs/swagger.json",
        "/v1/openapi.json",
    )

    _security_payloads: Dict[str, Any] = field(default_factory=_load_security_payloads)
    _security_policies: Dict[str, Any] = field(default_factory=_load_security_policies)
    _discovery_catalog: Dict[str, Any] = field(default_factory=_load_discovery_catalog)
    _compliance_mapping: Dict[str, Any] = field(default_factory=_load_compliance_mapping)

    user_ids_to_probe: Tuple[str, ...] = field(init=False)
    injection_payloads: Tuple[str, ...] = field(init=False)
    mass_assignment_keys: Tuple[str, ...] = field(init=False)
    email_context_payloads: Tuple[str, ...] = field(init=False)
    book_context_payloads: Tuple[str, ...] = field(init=False)
    weak_password_candidates: Tuple[str, ...] = field(init=False)
    jwt_max_ttl_seconds: int = field(init=False)
    rate_limit_probe_attempts: int = field(init=False)
    sensitive_keys: Tuple[str, ...] = field(init=False)
    sql_error_markers: Tuple[str, ...] = field(init=False)
    misconfiguration_probe_paths: Tuple[str, ...] = field(init=False)
    inventory_probe_paths: Tuple[str, ...] = field(init=False)
    collection_endpoint_suffix: str = field(init=False)
    discovery_fallback_catalog: Tuple[Dict[str, Any], ...] = field(init=False)
    owasp_api_categories: Tuple[str, ...] = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "user_ids_to_probe", tuple(str(value) for value in self._security_payloads.get("user_ids_to_probe", [])))
        object.__setattr__(self, "injection_payloads", tuple(str(value) for value in self._security_payloads.get("injection_payloads", [])))
        object.__setattr__(self, "mass_assignment_keys", tuple(str(value) for value in self._security_payloads.get("mass_assignment_keys", [])))
        object.__setattr__(self, "email_context_payloads", tuple(str(value) for value in self._security_payloads.get("email_context_payloads", [])))
        object.__setattr__(self, "book_context_payloads", tuple(str(value) for value in self._security_payloads.get("book_context_payloads", [])))
        object.__setattr__(self, "weak_password_candidates", tuple(str(value) for value in self._security_policies.get("weak_password_candidates", [])))
        object.__setattr__(self, "jwt_max_ttl_seconds", int(self._security_policies.get("jwt_max_ttl_seconds", 86400)))
        object.__setattr__(self, "rate_limit_probe_attempts", int(self._security_policies.get("rate_limit_probe_attempts", 5)))
        object.__setattr__(self, "sensitive_keys", tuple(str(value) for value in self._security_policies.get("sensitive_keys", [])))
        object.__setattr__(self, "sql_error_markers", tuple(str(value) for value in self._security_policies.get("sql_error_markers", [])))
        object.__setattr__(self, "misconfiguration_probe_paths", tuple(str(value) for value in self._security_policies.get("misconfiguration_probe_paths", [])))
        object.__setattr__(self, "inventory_probe_paths", tuple(str(value) for value in self._security_policies.get("inventory_probe_paths", [])))
        object.__setattr__(self, "collection_endpoint_suffix", str(self._security_policies.get("collection_endpoint_suffix", "/v1")))
        object.__setattr__(self, "discovery_fallback_catalog", tuple(self._discovery_catalog.get("fallback_catalog", [])))
        object.__setattr__(self, "owasp_api_categories", tuple(self._compliance_mapping.keys()))

    def normalized_base_url(self) -> str:
        return self.base_url.rstrip("/")


def build_settings() -> SecuritySettings:
    """Return settings populated from the environment."""

    return SecuritySettings()