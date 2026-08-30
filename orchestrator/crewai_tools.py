"""Custom tools for CrewAI agents to perform API discovery and security testing."""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from config.settings import SecuritySettings
from discovery_agent.agent import DiscoveryAgent
from models import DiscoveryResult
from security_agent.agent import SecurityTestingAgent


class CrewAIToolkit:
    """Toolkit for CrewAI agent tools."""

    def __init__(self, settings: SecuritySettings) -> None:
        self.settings = settings
        self.discovery_agent = DiscoveryAgent(settings)
        self.security_agent = SecurityTestingAgent(settings)
        self.discovery_result: Optional[DiscoveryResult] = None

    def discover_endpoints(self) -> str:
        """
        Discover all API endpoints from VAmPI target.
        Returns a summary of discovered endpoints and their metadata.
        """
        self.discovery_result = self.discovery_agent.discover()
        summary = f"Discovered {len(self.discovery_result.endpoints)} endpoints:\n"
        for ep in self.discovery_result.endpoints[:10]:
            summary += f"  - {ep.method} {ep.path} (auth={ep.auth_required})\n"
        if len(self.discovery_result.endpoints) > 10:
            summary += f"  ... and {len(self.discovery_result.endpoints) - 10} more\n"
        return summary

    def test_api_security(self) -> str:
        """
        Test discovered API endpoints for OWASP API Top 10 vulnerabilities.
        Returns a summary of detected vulnerabilities.
        """
        if not self.discovery_result:
            return "ERROR: Must run Discover API Endpoints tool first."
        
        assessment = self.security_agent.assess(self.discovery_result)
        summary = f"Security Assessment Complete:\n"
        summary += f"  - Total Endpoints: {len(self.discovery_result.endpoints)}\n"
        summary += f"  - Vulnerabilities Found: {len(assessment.findings)}\n"
        
        risk_count = assessment.risk_summary()
        summary += f"  - Critical: {risk_count.get('critical', 0)}\n"
        summary += f"  - High: {risk_count.get('high', 0)}\n"
        summary += f"  - Medium: {risk_count.get('medium', 0)}\n"
        
        top_findings = sorted(assessment.findings, key=lambda f: f.cvss_score, reverse=True)[:3]
        if top_findings:
            summary += "\n  Top Findings:\n"
            for finding in top_findings:
                summary += f"    - [{finding.severity.upper()}] {finding.title} (CVSS {finding.cvss_score})\n"
        
        return summary

    def get_vulnerability_details(self, finding_index: int = 0) -> str:
        """
        Get detailed information about a specific vulnerability finding.
        Args:
            finding_index: Index of the finding (default 0 for highest CVSS)
        Returns: Detailed vulnerability information with remediation
        """
        if not self.discovery_result:
            return "ERROR: Must run security tests first."
        
        assessment = self.security_agent.assess(self.discovery_result)
        if not assessment.findings:
            return "No vulnerabilities found."
        
        sorted_findings = sorted(assessment.findings, key=lambda f: f.cvss_score, reverse=True)
        if finding_index >= len(sorted_findings):
            finding_index = len(sorted_findings) - 1
        
        finding = sorted_findings[finding_index]
        details = f"Vulnerability: {finding.title}\n"
        details += f"  OWASP Category: {finding.owasp_category}\n"
        details += f"  Severity: {finding.severity.upper()}\n"
        details += f"  CVSS Score: {finding.cvss_score}\n"
        details += f"  Endpoint: {finding.method} {finding.endpoint}\n"
        details += f"  Remediation: {finding.remediation}\n"
        details += f"  PoC: {finding.poc}\n"
        return details


def create_crewai_tools(settings: SecuritySettings) -> Dict[str, Callable[[], str]]:
    """Create and return CrewAI-compatible tools as callables."""
    toolkit = CrewAIToolkit(settings)
    return {
        "discover_endpoints": toolkit.discover_endpoints,
        "test_api_security": toolkit.test_api_security,
        "get_vulnerability_details": toolkit.get_vulnerability_details,
    }
