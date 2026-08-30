"""Continuous monitoring and trend analysis for security assessments."""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from models import SecurityAssessment


@dataclass
class AssessmentSnapshot:
    """Snapshot of an assessment at a point in time."""

    timestamp: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    avg_cvss_score: float
    findings_by_endpoint: Dict[str, int]
    findings_by_category: Dict[str, int]


class ContinuousMonitor:
    """Track security trends across multiple assessment runs."""

    def __init__(self, monitoring_dir: Path) -> None:
        self.monitoring_dir = Path(monitoring_dir)
        self.monitoring_dir.mkdir(parents=True, exist_ok=True)
        self.history_file = self.monitoring_dir / "assessment_history.jsonl"
        self.trends_file = self.monitoring_dir / "trends_summary.json"

    def record_assessment(self, assessment: SecurityAssessment) -> None:
        """Record a new assessment snapshot."""
        snapshot = self._create_snapshot(assessment)
        self._append_to_history(snapshot)
        self._update_trends()

    def _create_snapshot(self, assessment: SecurityAssessment) -> AssessmentSnapshot:
        """Create a snapshot from assessment."""
        severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        endpoint_count: Dict[str, int] = {}
        category_count: Dict[str, int] = {}
        cvss_scores: List[float] = []

        for finding in assessment.findings:
            severity = finding.severity.lower()
            if severity in severity_count:
                severity_count[severity] += 1

            endpoint = finding.endpoint
            endpoint_count[endpoint] = endpoint_count.get(endpoint, 0) + 1

            category = finding.owasp_category
            category_count[category] = category_count.get(category, 0) + 1

            cvss_scores.append(finding.cvss_score)

        avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0

        return AssessmentSnapshot(
            timestamp=datetime.now(timezone.utc).isoformat(),
            total_findings=len(assessment.findings),
            critical_count=severity_count["critical"],
            high_count=severity_count["high"],
            medium_count=severity_count["medium"],
            low_count=severity_count["low"],
            avg_cvss_score=avg_cvss,
            findings_by_endpoint=endpoint_count,
            findings_by_category=category_count,
        )

    def _append_to_history(self, snapshot: AssessmentSnapshot) -> None:
        """Append snapshot to history file."""
        with open(self.history_file, "a") as f:
            f.write(json.dumps(asdict(snapshot)) + "\n")

    def _update_trends(self) -> None:
        """Update trends analysis."""
        snapshots = self._load_history()
        if not snapshots:
            return

        trends = {
            "total_assessments": len(snapshots),
            "latest_snapshot": snapshots[-1],
            "trends": {
                "total_findings": self._calculate_trend([s["total_findings"] for s in snapshots]),
                "critical_findings": self._calculate_trend([s["critical_count"] for s in snapshots]),
                "high_findings": self._calculate_trend([s["high_count"] for s in snapshots]),
                "avg_cvss_score": self._calculate_trend([s["avg_cvss_score"] for s in snapshots]),
            },
            "alerts": self._generate_alerts(snapshots),
        }

        with open(self.trends_file, "w") as f:
            json.dump(trends, f, indent=2)

    def _load_history(self) -> List[Dict[str, Any]]:
        """Load all snapshots from history file."""
        if not self.history_file.exists():
            return []

        snapshots = []
        with open(self.history_file, "r") as f:
            for line in f:
                try:
                    snapshots.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue
        return snapshots

    @staticmethod
    def _calculate_trend(values: List[float]) -> Dict[str, Any]:
        """Calculate trend statistics."""
        if len(values) < 2:
            return {
                "current": values[-1] if values else 0,
                "previous": None,
                "change": 0,
                "direction": "neutral",
            }

        current = values[-1]
        previous = values[-2]
        change = current - previous
        direction = "improving" if change < 0 else "degrading" if change > 0 else "stable"

        return {
            "current": current,
            "previous": previous,
            "change": change,
            "direction": direction,
            "min": min(values),
            "max": max(values),
            "avg": sum(values) / len(values),
        }

    @staticmethod
    def _generate_alerts(snapshots: List[Dict[str, Any]]) -> List[str]:
        """Generate alerts based on trends."""
        alerts: List[str] = []

        if len(snapshots) < 2:
            return alerts

        latest = snapshots[-1]
        previous = snapshots[-2]

        if latest["critical_count"] > previous["critical_count"]:
            new_critical = latest["critical_count"] - previous["critical_count"]
            alerts.append(f"ALERT: {new_critical} new critical vulnerabilities detected!")

        if latest["total_findings"] > previous["total_findings"] * 1.2:
            alerts.append("ALERT: Finding count increased by more than 20%")

        if latest["avg_cvss_score"] > previous["avg_cvss_score"] + 1:
            alerts.append("ALERT: Average CVSS score increased significantly")

        if latest["critical_count"] > 5:
            alerts.append(f"ALERT: {latest['critical_count']} critical findings present")

        return alerts

    def get_trends_report(self) -> Optional[Dict[str, Any]]:
        """Get current trends report."""
        if not self.trends_file.exists():
            return None

        with open(self.trends_file, "r") as f:
            return json.load(f)

    def get_assessment_history(self) -> List[Dict[str, Any]]:
        """Get full assessment history."""
        return self._load_history()


class MonitoringReportGenerator:
    """Generate monitoring and trend reports."""

    def __init__(self, monitor: ContinuousMonitor) -> None:
        self.monitor = monitor

    def generate_html_report(self) -> str:
        """Generate HTML report of monitoring trends."""
        history = self.monitor.get_assessment_history()
        trends = self.monitor.get_trends_report()

        if not history:
            return "<html><body><h1>No monitoring data available</h1></body></html>"

        assessment_timeline = "".join(
            f"<tr><td>{s['timestamp']}</td><td>{s['total_findings']}</td><td>{s['critical_count']}</td><td>{s['avg_cvss_score']:.2f}</td></tr>"
            for s in history
        )

        alerts_html = ""
        if trends and trends.get("alerts"):
            alerts_html = "".join(f"<li>{alert}</li>" for alert in trends["alerts"])

        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>VAmPI Continuous Monitoring Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; color: #1f2937; }}
    h1 {{ color: #111827; border-bottom: 2px solid #1f2937; padding-bottom: 0.5rem; }}
    h2 {{ color: #374151; margin-top: 2rem; }}
    table {{ border-collapse: collapse; width: 100%; margin-bottom: 1.5rem; }}
    th, td {{ border: 1px solid #d1d5db; padding: 0.5rem; text-align: left; }}
    th {{ background: #f3f4f6; font-weight: bold; }}
    .alert {{ background: #fee2e2; border-left: 4px solid #DC3545; padding: 1rem; margin: 1rem 0; }}
    .improving {{ color: #059669; font-weight: bold; }}
    .degrading {{ color: #DC3545; font-weight: bold; }}
    .stable {{ color: #6B7280; font-weight: bold; }}
    .trend-section {{ background: #f9fafb; padding: 1rem; margin: 1rem 0; border-radius: 0.5rem; }}
  </style>
</head>
<body>
  <h1>Continuous Monitoring & Trends Report</h1>
  <p><strong>Generated:</strong> {datetime.now(timezone.utc).isoformat()}</p>
  <p><strong>Total Assessments:</strong> {len(history)}</p>
  
  <h2>Alerts & Anomalies</h2>
  {f'<ul>{alerts_html}</ul>' if alerts_html else '<p>No alerts detected</p>'}
  
  <h2>Assessment Timeline</h2>
  <table>
    <thead><tr><th>Timestamp</th><th>Total Findings</th><th>Critical</th><th>Avg CVSS</th></tr></thead>
    <tbody>{assessment_timeline}</tbody>
  </table>
  
  <h2>Trend Analysis</h2>
  {self._render_trends_section(trends) if trends else '<p>Insufficient data for trend analysis</p>'}
  
</body>
</html>"""

    @staticmethod
    def _render_trends_section(trends: Dict[str, Any]) -> str:
        """Render trends section."""
        html_parts = []
        for metric, trend_data in trends.get("trends", {}).items():
            direction = trend_data.get("direction", "neutral")
            direction_class = direction.replace(" ", "_")
            change = trend_data.get("change", 0)

            html_parts.append('<div class="trend-section">')
            html_parts.append(f'<h3>{metric.replace("_", " ").title()}</h3>')
            html_parts.append(f'<p><strong>Current:</strong> {trend_data.get("current", "N/A")}</p>')
            if trend_data.get("previous") is not None:
                html_parts.append(f'<p><strong>Previous:</strong> {trend_data.get("previous")}</p>')
                html_parts.append(f'<p><strong>Change:</strong> <span class="{direction_class}">{change:+.2f} ({direction})</span></p>')
            html_parts.append(f'<p><strong>Min:</strong> {trend_data.get("min", "N/A")} | <strong>Max:</strong> {trend_data.get("max", "N/A")} | <strong>Avg:</strong> {trend_data.get("avg", "N/A"):.2f}</p>')
            html_parts.append('</div>')

        return "\n".join(html_parts)
