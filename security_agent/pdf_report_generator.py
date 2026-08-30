"""Enhanced PDF report generation with charts and heatmaps."""

from __future__ import annotations

import base64
import io
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from models import SecurityAssessment


@dataclass
class ChartConfig:
    """Configuration for chart generation."""

    title: str
    data: List[Dict[str, Any]]


class PDFChartGenerator:
    """Generate SVG charts for PDF reports."""

    @staticmethod
    def generate_severity_pie_chart(findings_by_severity: Dict[str, int]) -> str:
        """Generate SVG pie chart for severity distribution."""
        colors = {"critical": "#DC3545", "high": "#FFC107", "medium": "#FFC107", "low": "#6C757D"}
        total = sum(findings_by_severity.values())
        if total == 0:
            return ""

        svg_lines = [
            '<svg width="300" height="300" viewBox="0 0 300 300" xmlns="http://www.w3.org/2000/svg">',
            '<circle cx="150" cy="150" r="100" fill="white" stroke="black" stroke-width="1"/>',
        ]

        current_angle = 0
        for severity, count in sorted(findings_by_severity.items(), key=lambda x: -x[1]):
            percentage = (count / total) * 100
            angle_range = (percentage / 100) * 360
            color = colors.get(severity, "#999")

            svg_lines.append(
                f'<path d="M 150,150 L {150 + 100 * _cos_deg(current_angle)},{150 + 100 * _sin_deg(current_angle)} '
                f'A 100,100 0 {1 if angle_range > 180 else 0},1 {150 + 100 * _cos_deg(current_angle + angle_range)},'
                f'{150 + 100 * _sin_deg(current_angle + angle_range)} Z" fill="{color}" stroke="white" stroke-width="2"/>'
            )
            current_angle += angle_range

        svg_lines.append("</svg>")
        return "\n".join(svg_lines)

    @staticmethod
    def generate_cvss_distribution_chart(findings_scores: List[float]) -> str:
        """Generate SVG bar chart for CVSS score distribution."""
        if not findings_scores:
            return ""

        buckets = {
            "0-3.9": 0,
            "4-6.9": 0,
            "7-8.9": 0,
            "9-10": 0,
        }

        for score in findings_scores:
            if score < 4:
                buckets["0-3.9"] += 1
            elif score < 7:
                buckets["4-6.9"] += 1
            elif score < 9:
                buckets["7-8.9"] += 1
            else:
                buckets["9-10"] += 1

        max_height = max(buckets.values()) if buckets.values() else 1
        bar_width = 40
        bar_spacing = 10
        chart_width = len(buckets) * (bar_width + bar_spacing) + 40
        chart_height = 250

        svg_lines = [
            f'<svg width="{chart_width}" height="{chart_height}" viewBox="0 0 {chart_width} {chart_height}" xmlns="http://www.w3.org/2000/svg">',
            '<rect width="100%" height="100%" fill="white"/>',
        ]

        x_pos = 30
        colors_map = {"0-3.9": "#28A745", "4-6.9": "#FFC107", "7-8.9": "#FF9800", "9-10": "#DC3545"}

        for label, count in buckets.items():
            bar_height = (count / max_height) * 200 if max_height > 0 else 0
            y_pos = 220 - bar_height
            color = colors_map.get(label, "#999")

            svg_lines.append(f'<rect x="{x_pos}" y="{y_pos}" width="{bar_width}" height="{bar_height}" fill="{color}"/>')
            svg_lines.append(
                f'<text x="{x_pos + bar_width / 2}" y="240" text-anchor="middle" font-size="10">{label}</text>'
            )
            svg_lines.append(
                f'<text x="{x_pos + bar_width / 2}" y="{y_pos - 5}" text-anchor="middle" font-size="10" font-weight="bold">{count}</text>'
            )

            x_pos += bar_width + bar_spacing

        svg_lines.append("</svg>")
        return "\n".join(svg_lines)

    @staticmethod
    def generate_endpoint_risk_heatmap(
        endpoints: List[str], endpoint_finding_counts: Dict[str, int]
    ) -> str:
        """Generate SVG heatmap for endpoint risk levels."""
        if not endpoints:
            return ""

        cell_width = 120
        cell_height = 30
        cols = 3
        rows = (len(endpoints) + cols - 1) // cols
        chart_width = cols * cell_width + 40
        chart_height = rows * cell_height + 40

        svg_lines = [
            f'<svg width="{chart_width}" height="{chart_height}" viewBox="0 0 {chart_width} {chart_height}" xmlns="http://www.w3.org/2000/svg">',
            '<rect width="100%" height="100%" fill="white"/>',
        ]

        max_findings = max(endpoint_finding_counts.values()) if endpoint_finding_counts else 1

        for idx, endpoint in enumerate(endpoints):
            row = idx // cols
            col = idx % cols
            x = col * cell_width + 20
            y = row * cell_height + 20

            count = endpoint_finding_counts.get(endpoint, 0)
            intensity = count / max_findings if max_findings > 0 else 0

            if intensity > 0.7:
                color = "#DC3545"
            elif intensity > 0.4:
                color = "#FFC107"
            else:
                color = "#28A745"

            svg_lines.append(
                f'<rect x="{x}" y="{y}" width="{cell_width - 5}" height="{cell_height - 5}" fill="{color}" stroke="black"/>'
            )

            endpoint_short = endpoint[:20] + ".." if len(endpoint) > 20 else endpoint
            svg_lines.append(f'<text x="{x + 5}" y="{y + 20}" font-size="9">{endpoint_short} ({count})</text>')

        svg_lines.append("</svg>")
        return "\n".join(svg_lines)


class EnhancedPDFReportGenerator:
    """Generate professional PDF reports with charts."""

    def __init__(self) -> None:
        self.chart_generator = PDFChartGenerator()

    def generate_html_with_charts(self, assessment: SecurityAssessment) -> str:
        """Generate HTML report with embedded SVG charts."""
        severity_counts = Counter(f.severity for f in assessment.findings)
        cvss_scores = [f.cvss_score for f in assessment.findings]
        endpoint_counts: Dict[str, int] = {}
        for finding in assessment.findings:
            endpoint_counts[finding.endpoint] = endpoint_counts.get(finding.endpoint, 0) + 1

        severity_pie = self.chart_generator.generate_severity_pie_chart(dict(severity_counts))
        cvss_dist = self.chart_generator.generate_cvss_distribution_chart(cvss_scores)
        endpoint_heatmap = self.chart_generator.generate_endpoint_risk_heatmap(
            list(set(f.endpoint for f in assessment.findings)), endpoint_counts
        )

        html_parts = [
            '<!DOCTYPE html>',
            '<html lang="en">',
            '<head>',
            '<meta charset="UTF-8">',
            '<title>VAmPI Security Assessment Report</title>',
            '<style>',
            'body { font-family: Arial, sans-serif; margin: 20px; background: white; }',
            'h1, h2 { color: #333; }',
            '.chart-container { background: #f5f5f5; padding: 20px; margin: 20px 0; border-radius: 5px; }',
            '.severity-critical { color: #DC3545; font-weight: bold; }',
            '.severity-high { color: #FFC107; font-weight: bold; }',
            '.severity-medium { color: #FF9800; font-weight: bold; }',
            '.severity-low { color: #6C757D; font-weight: bold; }',
            '.finding-item { border-left: 4px solid #999; padding: 15px; margin: 10px 0; background: #f9f9f9; }',
            '.finding-item.critical { border-left-color: #DC3545; }',
            '.finding-item.high { border-left-color: #FFC107; }',
            '.table { width: 100%; border-collapse: collapse; margin: 20px 0; }',
            '.table th, .table td { padding: 10px; border: 1px solid #ddd; text-align: left; }',
            '.table th { background: #f0f0f0; font-weight: bold; }',
            '.evidence { background: #f5f5f5; padding: 10px; font-family: monospace; font-size: 12px; }',
            'page-break-after { page-break-after: always; }',
            '</style>',
            '</head>',
            '<body>',
        ]

        html_parts.append('<h1>VAmPI Security Assessment Report</h1>')
        html_parts.append(f'<p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>')
        html_parts.append(f'<p><strong>Target:</strong> {assessment.base_url}</p>')

        html_parts.append('<h2>Executive Summary</h2>')
        total_findings = len(assessment.findings)
        critical_count = sum(1 for f in assessment.findings if f.severity == "critical")
        high_count = sum(1 for f in assessment.findings if f.severity == "high")
        html_parts.append(
            f'<p>This assessment identified <strong>{total_findings}</strong> security findings, '
            f'including <span class="severity-critical">{critical_count} Critical</span> and '
            f'<span class="severity-high">{high_count} High</span> severity issues.</p>'
        )

        html_parts.append('<h2>Findings Distribution</h2>')
        html_parts.append('<div class="chart-container">')
        html_parts.append('<h3>Severity Distribution</h3>')
        html_parts.append(severity_pie)
        html_parts.append('</div>')

        html_parts.append('<div class="chart-container">')
        html_parts.append('<h3>CVSS Score Distribution</h3>')
        html_parts.append(cvss_dist)
        html_parts.append('</div>')

        html_parts.append('<div class="chart-container">')
        html_parts.append('<h3>Endpoint Risk Heatmap</h3>')
        html_parts.append(endpoint_heatmap)
        html_parts.append('</div>')

        html_parts.append('<h2>Detailed Findings</h2>')
        for idx, finding in enumerate(sorted(assessment.findings, key=lambda f: -f.cvss_score), 1):
            severity_class = finding.severity.lower()
            html_parts.append(f'<div class="finding-item {severity_class}">')
            html_parts.append(f'<h3>[{idx}] {finding.title}</h3>')
            html_parts.append(
                f'<p><strong>Severity:</strong> <span class="severity-{severity_class}">{finding.severity.upper()}</span> | '
                f'<strong>CVSS:</strong> {finding.cvss_score} | '
                f'<strong>Category:</strong> {finding.owasp_category}</p>'
            )
            html_parts.append(f'<p><strong>Endpoint:</strong> {finding.method} {finding.endpoint}</p>')
            html_parts.append(f'<p><strong>Description:</strong> {finding.description}</p>')
            html_parts.append(f'<p><strong>PoC:</strong> {finding.poc}</p>')
            html_parts.append(f'<p><strong>Remediation:</strong> {finding.remediation}</p>')

            if finding.evidence:
                html_parts.append('<p><strong>Evidence:</strong></p>')
                html_parts.append('<div class="evidence">')
                for key, value in finding.evidence.items():
                    if isinstance(value, dict):
                        html_parts.append(f'<strong>{key}:</strong> {str(value)[:200]}...<br/>')
                    else:
                        html_parts.append(f'<strong>{key}:</strong> {value}<br/>')
                html_parts.append('</div>')

            html_parts.append('</div>')

        html_parts.append('<h2>Remediation Roadmap</h2>')
        html_parts.append('<table class="table">')
        html_parts.append('<tr><th>Priority</th><th>Finding</th><th>CVSS</th><th>Recommendation</th></tr>')
        for finding in sorted(assessment.findings, key=lambda f: -f.cvss_score):
            priority = "IMMEDIATE" if finding.cvss_score >= 9 else "URGENT" if finding.cvss_score >= 7 else "HIGH"
            html_parts.append(
                f'<tr><td>{priority}</td><td>{finding.title}</td><td>{finding.cvss_score}</td>'
                f'<td>{finding.remediation[:100]}...</td></tr>'
            )
        html_parts.append('</table>')

        html_parts.append('</body></html>')
        return "\n".join(html_parts)


def _cos_deg(degrees: float) -> float:
    """Cosine of angle in degrees."""
    import math

    return math.cos(math.radians(degrees))


def _sin_deg(degrees: float) -> float:
    """Sine of angle in degrees."""
    import math

    return math.sin(math.radians(degrees))
