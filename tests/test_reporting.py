from __future__ import annotations

from pathlib import Path

from config.settings import SecuritySettings
from discovery_agent.agent import DiscoveryAgent
from models import DiscoveryResult, EndpointMetadata, SecurityAssessment, SecurityFinding
from reports.generator import SecurityReportGenerator


def test_report_generator_writes_json_and_html(tmp_path):
    discovery = DiscoveryResult(
        base_url="http://localhost:5000",
        source="fallback",
        endpoints=[EndpointMetadata(path="/users/v1", method="GET")],
    )
    assessment = SecurityAssessment(
        base_url="http://localhost:5000",
        findings=[SecurityFinding(
            title="Example issue",
            severity="high",
            cvss_score=8.1,
            owasp_category="API3: Excessive Data Exposure",
            endpoint="/users/v1",
            method="GET",
            evidence={"field": "password"},
            remediation="Remove sensitive fields",
            proof_of_concept="GET /users/v1",
        )],
    )
    artifacts = SecurityReportGenerator().generate(discovery, assessment, tmp_path)

    assert artifacts.json_path.exists()
    assert artifacts.html_path.exists()
    assert artifacts.pdf_path is not None and artifacts.pdf_path.exists()
    assert "Example issue" in artifacts.json_path.read_text(encoding="utf-8")
    payload = artifacts.json_path.read_text(encoding="utf-8")
    assert "compliance_mapping" in payload
    assert "exploit_playbook" in payload
