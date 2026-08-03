"""Shared data models for discovery, testing, and reporting."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class EndpointMetadata:
    path: str
    method: str
    summary: str = ""
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    auth_required: bool = False
    category: str = "general"
    risk: str = "medium"
    source: str = "fallback"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DiscoveryResult:
    base_url: str
    endpoints: List[EndpointMetadata]
    source: str
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "base_url": self.base_url,
            "source": self.source,
            "notes": list(self.notes),
            "endpoints": [endpoint.to_dict() for endpoint in self.endpoints],
        }


@dataclass
class SecurityFinding:
    title: str
    severity: str
    cvss_score: float
    owasp_category: str
    endpoint: str
    method: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    proof_of_concept: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityAssessment:
    base_url: str
    findings: List[SecurityFinding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    auth_context: Dict[str, Any] = field(default_factory=dict)
    audit_events: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "base_url": self.base_url,
            "notes": list(self.notes),
            "auth_context": dict(self.auth_context),
            "audit_events": list(self.audit_events),
            "findings": [finding.to_dict() for finding in self.findings],
            "risk_summary": self.risk_summary(),
        }

    def risk_summary(self) -> Dict[str, int]:
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.findings:
            key = finding.severity.lower()
            if key not in summary:
                key = "info"
            summary[key] += 1
        return summary
