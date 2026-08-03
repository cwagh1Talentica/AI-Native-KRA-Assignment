"""API discovery agent for the VAmPI target."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

import requests

from config.settings import SecuritySettings
from models import DiscoveryResult, EndpointMetadata


@dataclass
class _SpecEndpoint:
    path: str
    method: str
    operation: Dict[str, Any]


class DiscoveryAgent:
    """Discover and catalog API endpoints."""

    def __init__(self, settings: Optional[SecuritySettings] = None) -> None:
        self.settings = settings or SecuritySettings()
        self.session = requests.Session()

    def discover(self) -> DiscoveryResult:
        discovered = self._discover_from_specs()
        if discovered:
            endpoints = self._merge_with_fallback(discovered)
            notes = ["Discovered OpenAPI/Swagger specification and merged with the VAmPI fallback catalog."]
            source = "openapi+fallback"
        else:
            endpoints = self._fallback_catalog()
            notes = ["No usable OpenAPI specification was found; using the curated VAmPI fallback catalog."]
            source = "fallback"
        return DiscoveryResult(base_url=self.settings.normalized_base_url(), endpoints=endpoints, source=source, notes=notes)

    def _discover_from_specs(self) -> List[EndpointMetadata]:
        for candidate in self.settings.openapi_paths:
            url = f"{self.settings.normalized_base_url()}{candidate}"
            try:
                response = self.session.get(url, timeout=self.settings.timeout_seconds)
            except requests.RequestException:
                continue
            if not response.ok:
                continue
            spec = self._safe_json(response.text)
            if not isinstance(spec, dict):
                continue
            paths = spec.get("paths")
            if not isinstance(paths, dict):
                continue
            return self._parse_openapi_paths(paths)
        return []

    def _parse_openapi_paths(self, paths: Dict[str, Any]) -> List[EndpointMetadata]:
        endpoints: List[EndpointMetadata] = []
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, operation in methods.items():
                if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                    continue
                if not isinstance(operation, dict):
                    operation = {}
                parameters = []
                for parameter in operation.get("parameters", []):
                    if isinstance(parameter, dict):
                        parameters.append(
                            {
                                "name": parameter.get("name"),
                                "in": parameter.get("in"),
                                "required": bool(parameter.get("required", False)),
                                "schema": parameter.get("schema", {}),
                            }
                        )
                endpoints.append(
                    EndpointMetadata(
                        path=path,
                        method=method.upper(),
                        summary=str(operation.get("summary") or operation.get("description") or "").strip(),
                        parameters=parameters,
                        auth_required=bool(operation.get("security")),
                        category=self._categorize(path, method),
                        risk=self._risk_level(path, method, bool(operation.get("security"))),
                        source="openapi",
                    )
                )
        return endpoints

    def _merge_with_fallback(self, discovered: Sequence[EndpointMetadata]) -> List[EndpointMetadata]:
        merged: Dict[tuple[str, str], EndpointMetadata] = {
            (endpoint.method, endpoint.path): endpoint for endpoint in self._fallback_catalog()
        }
        for endpoint in discovered:
            merged[(endpoint.method, endpoint.path)] = endpoint
        return sorted(merged.values(), key=lambda item: (item.category, item.method, item.path))

    def _fallback_catalog(self) -> List[EndpointMetadata]:
        raw_catalog = self.settings.discovery_fallback_catalog
        return [
            EndpointMetadata(
                path=str(item.get("path", "")),
                method=str(item.get("method", "GET")).upper(),
                summary=str(item.get("summary", "")),
                auth_required=bool(item.get("auth_required", False)),
                category=self._categorize(str(item.get("path", "")), str(item.get("method", "GET"))),
                risk=self._risk_level(
                    str(item.get("path", "")),
                    str(item.get("method", "GET")),
                    bool(item.get("auth_required", False)),
                ),
                source="fallback",
            )
            for item in raw_catalog
        ]

    @staticmethod
    def _safe_json(text: str) -> Any:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _categorize(path: str, method: str) -> str:
        lowered = path.lower()
        if "/users/" in lowered:
            return "user-management"
        if "/books/" in lowered:
            return "book-management"
        if method.upper() == "POST":
            return "mutating"
        return "general"

    @staticmethod
    def _risk_level(path: str, method: str, auth_required: bool) -> str:
        if "register" in path or "login" in path:
            return "high"
        if not auth_required and method.upper() == "GET":
            return "medium"
        if auth_required and method.upper() in {"PUT", "DELETE", "POST"}:
            return "high"
        return "medium"