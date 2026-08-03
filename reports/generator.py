"""Report generation for discovery and security assessment output."""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, cast

from config.resources import load_mapping
from models import DiscoveryResult, SecurityAssessment

_COMPLIANCE_MAPPING = load_mapping("compliance_mapping.json")


@dataclass
class ReportArtifacts:
    json_path: Path
    html_path: Path
    pdf_path: Optional[Path] = None
    audit_log_path: Optional[Path] = None


class SecurityReportGenerator:
    """Generate JSON and HTML reports."""

    def generate(
        self,
        discovery: DiscoveryResult,
        assessment: SecurityAssessment,
        output_dir: Path,
        basename: str = "vampi-security-assessment",
    ) -> ReportArtifacts:
        output_dir.mkdir(parents=True, exist_ok=True)
        payload = self._build_payload(discovery, assessment)
        json_path = output_dir / f"{basename}.json"
        html_path = output_dir / f"{basename}.html"
        pdf_path = output_dir / f"{basename}.pdf"
        audit_log_path = output_dir / f"{basename}.audit.jsonl"
        json_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        html_path.write_text(self._render_html(payload), encoding="utf-8")
        pdf_path.write_bytes(self._render_pdf(payload))
        self._write_audit_log(audit_log_path, assessment)
        return ReportArtifacts(json_path=json_path, html_path=html_path, pdf_path=pdf_path, audit_log_path=audit_log_path)

    def _build_payload(self, discovery: DiscoveryResult, assessment: SecurityAssessment) -> Dict[str, object]:
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target": discovery.base_url,
            "discovery": discovery.to_dict(),
            "assessment": assessment.to_dict(),
            "compliance_mapping": self._compliance_mapping(assessment),
            "exploit_playbook": self._exploit_playbook(assessment),
            "executive_summary": self._executive_summary(assessment),
            "remediation_roadmap": self._remediation_roadmap(assessment),
            "summary": {
                "endpoint_count": len(discovery.endpoints),
                "finding_count": len(assessment.findings),
                "risk_summary": assessment.risk_summary(),
            },
        }

    def _executive_summary(self, assessment: SecurityAssessment) -> Dict[str, Any]:
        risk = assessment.risk_summary()
        posture = "high risk" if risk["critical"] > 0 or risk["high"] >= 2 else "moderate risk" if risk["high"] > 0 else "elevated risk"
        top_findings = sorted(assessment.findings, key=lambda f: f.cvss_score, reverse=True)[:3]
        return {
            "security_posture": posture,
            "total_findings": len(assessment.findings),
            "critical_findings": risk["critical"],
            "high_findings": risk["high"],
            "priority_themes": [finding.title for finding in top_findings],
            "recommended_next_step": "Address critical/high findings first, then apply hardening for exposure and rate limiting gaps.",
        }

    def _remediation_roadmap(self, assessment: SecurityAssessment) -> List[Dict[str, Any]]:
        buckets = {"P1": [], "P2": [], "P3": []}
        for finding in sorted(assessment.findings, key=lambda f: f.cvss_score, reverse=True):
            if finding.severity.lower() in {"critical", "high"}:
                priority = "P1"
            elif finding.severity.lower() == "medium":
                priority = "P2"
            else:
                priority = "P3"
            buckets[priority].append(
                {
                    "finding": finding.title,
                    "endpoint": f"{finding.method} {finding.endpoint}",
                    "owasp_category": finding.owasp_category,
                    "cvss_score": finding.cvss_score,
                    "remediation": finding.remediation,
                }
            )
        roadmap: List[Dict[str, Any]] = []
        for priority in ("P1", "P2", "P3"):
            roadmap.append({"priority": priority, "items": buckets[priority]})
        return roadmap

    def _write_audit_log(self, path: Path, assessment: SecurityAssessment) -> None:
        lines: List[str] = []
        for event in assessment.audit_events:
            lines.append(json.dumps(event, sort_keys=True))
        path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    def _compliance_mapping(self, assessment: SecurityAssessment) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        seen = set()
        for finding in assessment.findings:
            category = finding.owasp_category
            if category in seen:
                continue
            seen.add(category)
            controls = _COMPLIANCE_MAPPING.get(category, {"legacy_2019": "", "nist": [], "iso27001": []})
            results.append(
                {
                    "owasp_api": category,
                    "owasp_api_2019": controls["legacy_2019"],
                    "nist_800_53": controls["nist"],
                    "iso_27001": controls["iso27001"],
                }
            )
        return results

    def _exploit_playbook(self, assessment: SecurityAssessment) -> List[Dict[str, Any]]:
        playbook: List[Dict[str, Any]] = []
        for finding in assessment.findings:
            command = finding.evidence.get("exploit_command") if isinstance(finding.evidence, dict) else None
            if not command:
                continue
            playbook.append(
                {
                    "title": finding.title,
                    "endpoint": finding.endpoint,
                    "method": finding.method,
                    "owasp_category": finding.owasp_category,
                    "exploit_command": command,
                }
            )
        return playbook

    def _render_html(self, payload: Dict[str, object]) -> str:
        discovery = cast(Dict[str, Any], payload["discovery"])
        assessment = cast(Dict[str, Any], payload["assessment"])
        summary = cast(Dict[str, Any], payload["summary"])
        findings = cast(List[Dict[str, Any]], assessment["findings"])
        endpoint_rows = "".join(
            f"<tr><td>{html.escape(item['method'])}</td><td>{html.escape(item['path'])}</td><td>{html.escape(item.get('category', ''))}</td><td>{html.escape(item.get('risk', ''))}</td></tr>"
            for item in cast(List[Dict[str, Any]], discovery["endpoints"])
        )
        finding_rows = "".join(
            f"<tr><td>{html.escape(item['severity'])}</td><td>{html.escape(item['title'])}</td><td>{html.escape(item['endpoint'])}</td><td>{html.escape(str(item['cvss_score']))}</td></tr>"
            for item in findings
        )
        risk_summary = "".join(
            f"<li>{html.escape(level.title())}: {count}</li>"
            for level, count in cast(Dict[str, Any], summary["risk_summary"]).items()
        )
        compliance_rows = self._render_compliance_rows(payload)
        roadmap = cast(List[Dict[str, Any]], payload.get("remediation_roadmap", []))
        roadmap_rows = self._render_roadmap_summary_rows(roadmap)
        roadmap_detail_rows = self._render_roadmap_detail_rows(roadmap)
        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>VAmPI Security Assessment</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; color: #1f2937; }}
    table {{ border-collapse: collapse; width: 100%; margin-bottom: 1.5rem; }}
    th, td {{ border: 1px solid #d1d5db; padding: 0.5rem; text-align: left; vertical-align: top; }}
    th {{ background: #f3f4f6; }}
    .summary {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 1rem; }}
    .card {{ background: #f9fafb; padding: 1rem; border: 1px solid #e5e7eb; border-radius: 0.5rem; }}
  </style>
</head>
<body>
  <h1>VAmPI Security Assessment</h1>
  <p><strong>Target:</strong> {html.escape(str(payload["target"]))}</p>
  <p><strong>Generated:</strong> {html.escape(str(payload["generated_at"]))}</p>
  <div class="summary">
    <div class="card"><strong>Endpoints</strong><br>{summary["endpoint_count"]}</div>
    <div class="card"><strong>Findings</strong><br>{summary["finding_count"]}</div>
    <div class="card"><strong>Risk Summary</strong><ul>{risk_summary}</ul></div>
  </div>
  <h2>Discovered Endpoints</h2>
  <table>
    <thead><tr><th>Method</th><th>Path</th><th>Category</th><th>Risk</th></tr></thead>
    <tbody>{endpoint_rows}</tbody>
  </table>
  <h2>Security Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Title</th><th>Endpoint</th><th>CVSS</th></tr></thead>
    <tbody>{finding_rows}</tbody>
  </table>
  <h2>Compliance Mapping</h2>
  <table>
    <thead><tr><th>OWASP API</th><th>OWASP API 2019</th><th>NIST 800-53</th><th>ISO 27001</th></tr></thead>
    <tbody>{compliance_rows}</tbody>
  </table>
  <h2>Executive Summary</h2>
  <p>{html.escape(str(payload.get("executive_summary", {}).get("security_posture", "n/a")).title())} with {html.escape(str(payload.get("executive_summary", {}).get("total_findings", 0)))} findings.</p>
  <h2>Prioritized Remediation Roadmap</h2>
  <table>
    <thead><tr><th>Priority</th><th>Count</th></tr></thead>
    <tbody>{roadmap_rows}</tbody>
  </table>
  <table>
    <thead><tr><th>Priority</th><th>Finding</th><th>Endpoint</th><th>OWASP API</th><th>CVSS</th><th>Remediation</th></tr></thead>
    <tbody>{roadmap_detail_rows}</tbody>
  </table>
</body>
</html>
"""

    @staticmethod
    def _render_compliance_rows(payload: Dict[str, object]) -> str:
        rows: List[str] = []
        for item in cast(List[Dict[str, Any]], payload.get("compliance_mapping", [])):
            rows.append(
                "<tr>"
                f"<td>{html.escape(item['owasp_api'])}</td>"
                f"<td>{html.escape(item.get('owasp_api_2019', ''))}</td>"
                f"<td>{html.escape(', '.join(item['nist_800_53']))}</td>"
                f"<td>{html.escape(', '.join(item['iso_27001']))}</td>"
                "</tr>"
            )
        return "".join(rows)

    @staticmethod
    def _render_roadmap_summary_rows(roadmap: List[Dict[str, Any]]) -> str:
        return "".join(
            f"<tr><td>{html.escape(bucket['priority'])}</td><td>{len(bucket['items'])}</td></tr>"
            for bucket in roadmap
        )

    @staticmethod
    def _render_roadmap_detail_rows(roadmap: List[Dict[str, Any]]) -> str:
        rows = [
            "<tr>"
            f"<td>{html.escape(bucket['priority'])}</td>"
            f"<td>{html.escape(item['finding'])}</td>"
            f"<td>{html.escape(item['endpoint'])}</td>"
            f"<td>{html.escape(item['owasp_category'])}</td>"
            f"<td>{html.escape(str(item['cvss_score']))}</td>"
            f"<td>{html.escape(item['remediation'])}</td>"
            "</tr>"
            for bucket in roadmap
            for item in cast(List[Dict[str, Any]], bucket.get("items", []))
        ]
        return "".join(rows) or "<tr><td colspan='6'>No remediation items available.</td></tr>"

    def _render_pdf(self, payload: Dict[str, object]) -> bytes:
        summary = cast(Dict[str, Any], payload["summary"])
        assessment = cast(Dict[str, Any], payload["assessment"])
        lines = [
            "VAmPI Security Assessment",
            f"Target: {payload['target']}",
            f"Generated: {payload['generated_at']}",
            f"Endpoints: {summary['endpoint_count']}",
            f"Findings: {summary['finding_count']}",
            f"Posture: {cast(Dict[str, Any], payload.get('executive_summary', {})).get('security_posture', 'n/a')}",
            "",
            "Findings:",
        ]
        for finding in cast(List[Dict[str, Any]], assessment["findings"])[:25]:
            lines.append(
                f"- [{finding['severity'].upper()}] {finding['title']} ({finding['method']} {finding['endpoint']}) CVSS {finding['cvss_score']}"
            )
        lines.append("")
        lines.append("Compliance Mapping:")
        for item in cast(List[Dict[str, Any]], payload.get("compliance_mapping", [])):
            lines.append(
                f"- {item['owasp_api']} ({item.get('owasp_api_2019', '')}) | NIST: {', '.join(item['nist_800_53'])} | ISO: {', '.join(item['iso_27001'])}"
            )
        lines.append("")
        lines.append("Remediation Roadmap:")
        for bucket in cast(List[Dict[str, Any]], payload.get("remediation_roadmap", [])):
            lines.append(f"- {bucket['priority']}: {len(bucket['items'])} item(s)")
            for item in cast(List[Dict[str, Any]], bucket.get("items", []))[:5]:
                lines.append(f"  * {item['finding']} [{item['endpoint']}] CVSS {item['cvss_score']}")
        return self._simple_pdf_from_lines(lines)

    @staticmethod
    def _simple_pdf_from_lines(lines: List[str]) -> bytes:
        escaped = []
        for line in lines:
            line = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            escaped.append(line)
        y = 770
        chunks = ["BT /F1 10 Tf 40 800 Td"]
        for line in escaped:
            chunks.append(f"0 -14 Td ({line}) Tj")
            y -= 14
            if y < 60:
                break
        chunks.append("ET")
        stream = "\n".join(chunks).encode("latin-1", "replace")
        objects: List[bytes] = []
        objects.append(b"1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n")
        objects.append(b"2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n")
        objects.append(b"3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>endobj\n")
        objects.append(b"4 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>endobj\n")
        objects.append(b"5 0 obj<< /Length " + str(len(stream)).encode("ascii") + b" >>stream\n" + stream + b"\nendstream endobj\n")
        pdf = b"%PDF-1.4\n"
        offsets = [0]
        for obj in objects:
            offsets.append(len(pdf))
            pdf += obj
        xref_start = len(pdf)
        pdf += b"xref\n0 6\n0000000000 65535 f \n"
        for offset in offsets[1:]:
            pdf += f"{offset:010d} 00000 n \n".encode("ascii")
        pdf += b"trailer<< /Size 6 /Root 1 0 R >>\nstartxref\n" + str(xref_start).encode("ascii") + b"\n%%EOF\n"
        return pdf