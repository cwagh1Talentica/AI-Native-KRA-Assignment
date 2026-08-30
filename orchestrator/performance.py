"""Performance profiling and SLA compliance analysis."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests


@dataclass
class PerformanceMetrics:
    """Performance metrics for API testing."""

    timestamp: str
    endpoint: str
    method: str
    response_time_ms: float
    status_code: int
    success: bool
    rate_limit_remaining: Optional[int] = None
    rate_limit_reset: Optional[str] = None


@dataclass
class SLAThresholds:
    """SLA thresholds for compliance."""

    max_response_time_ms: float = 1000.0
    max_error_rate_percent: float = 5.0
    min_availability_percent: float = 99.0
    rate_limit_requests_per_minute: int = 60


class PerformanceProfiler:
    """Profile API performance metrics."""

    def __init__(self, base_url: str, thresholds: Optional[SLAThresholds] = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.thresholds = thresholds or SLAThresholds()
        self.metrics: List[PerformanceMetrics] = []

    def profile_endpoint(self, method: str, endpoint: str, headers: Optional[Dict[str, str]] = None) -> PerformanceMetrics:
        """Profile a single endpoint."""
        url = f"{self.base_url}{endpoint}"
        headers = headers or {}

        start_time = time.time()
        try:
            if method.upper() == "GET":
                response = requests.get(url, headers=headers, timeout=30)
            elif method.upper() == "POST":
                response = requests.post(url, json={}, headers=headers, timeout=30)
            elif method.upper() == "PUT":
                response = requests.put(url, json={}, headers=headers, timeout=30)
            elif method.upper() == "DELETE":
                response = requests.delete(url, headers=headers, timeout=30)
            else:
                response = requests.request(method, url, headers=headers, timeout=30)

            response_time = (time.time() - start_time) * 1000

            metric = PerformanceMetrics(
                timestamp=datetime.now(timezone.utc).isoformat(),
                endpoint=endpoint,
                method=method,
                response_time_ms=response_time,
                status_code=response.status_code,
                success=(response.status_code < 500),
                rate_limit_remaining=self._extract_rate_limit(response, "remaining"),
                rate_limit_reset=self._extract_rate_limit_reset(response),
            )

            self.metrics.append(metric)
            return metric
        except Exception as e:
            response_time = (time.time() - start_time) * 1000

            metric = PerformanceMetrics(
                timestamp=datetime.now(timezone.utc).isoformat(),
                endpoint=endpoint,
                method=method,
                response_time_ms=response_time,
                status_code=0,
                success=False,
            )

            self.metrics.append(metric)
            return metric

    def profile_endpoints(
        self, endpoints: List[tuple[str, str]], headers: Optional[Dict[str, str]] = None
    ) -> List[PerformanceMetrics]:
        """Profile multiple endpoints."""
        results = []
        for method, endpoint in endpoints:
            results.append(self.profile_endpoint(method, endpoint, headers))
        return results

    def analyze_sla_compliance(self) -> Dict[str, Any]:
        """Analyze SLA compliance based on metrics."""
        if not self.metrics:
            return {"error": "No metrics collected"}

        response_times = [m.response_time_ms for m in self.metrics]
        successful = sum(1 for m in self.metrics if m.success)
        total = len(self.metrics)
        error_rate = ((total - successful) / total * 100) if total > 0 else 0

        response_time_compliant = all(rt <= self.thresholds.max_response_time_ms for rt in response_times)
        error_rate_compliant = error_rate <= self.thresholds.max_error_rate_percent
        availability = (successful / total * 100) if total > 0 else 0
        availability_compliant = availability >= self.thresholds.min_availability_percent

        endpoints_by_perf: Dict[str, Dict[str, Any]] = {}
        for metric in self.metrics:
            if metric.endpoint not in endpoints_by_perf:
                endpoints_by_perf[metric.endpoint] = {
                    "method": metric.method,
                    "samples": 0,
                    "avg_response_time": 0,
                    "min_response_time": float("inf"),
                    "max_response_time": 0,
                    "success_rate": 0,
                }

            perf = endpoints_by_perf[metric.endpoint]
            perf["samples"] += 1
            perf["avg_response_time"] = (perf["avg_response_time"] * (perf["samples"] - 1) + metric.response_time_ms) / perf["samples"]
            perf["min_response_time"] = min(perf["min_response_time"], metric.response_time_ms)
            perf["max_response_time"] = max(perf["max_response_time"], metric.response_time_ms)

        for perf in endpoints_by_perf.values():
            perf["min_response_time"] = perf["min_response_time"] if perf["min_response_time"] != float("inf") else 0

        return {
            "summary": {
                "total_requests": total,
                "successful_requests": successful,
                "error_rate_percent": round(error_rate, 2),
                "availability_percent": round(availability, 2),
                "avg_response_time_ms": round(sum(response_times) / len(response_times), 2),
                "min_response_time_ms": min(response_times) if response_times else 0,
                "max_response_time_ms": max(response_times) if response_times else 0,
            },
            "sla_compliance": {
                "response_time_compliant": response_time_compliant,
                "error_rate_compliant": error_rate_compliant,
                "availability_compliant": availability_compliant,
                "overall_compliant": response_time_compliant and error_rate_compliant and availability_compliant,
            },
            "endpoints": endpoints_by_perf,
        }

    def detect_rate_limiting(self) -> Dict[str, Any]:
        """Detect rate limiting behavior."""
        rate_limited = [m for m in self.metrics if m.rate_limit_remaining is not None]

        if not rate_limited:
            return {"detected": False, "reason": "No rate limit headers found"}

        rate_limits_decreasing = True
        prev_limit = None
        for metric in rate_limited:
            if prev_limit is not None and metric.rate_limit_remaining is not None:
                if metric.rate_limit_remaining >= prev_limit:
                    rate_limits_decreasing = False
            prev_limit = metric.rate_limit_remaining

        min_remaining = min((m.rate_limit_remaining for m in rate_limited if m.rate_limit_remaining is not None), default=None)

        return {
            "detected": rate_limits_decreasing,
            "rate_limit_header_present": True,
            "min_remaining_requests": min_remaining,
            "total_rate_limited_requests": len(rate_limited),
            "recommendation": "API implements rate limiting. Adjust testing frequency accordingly." if rate_limits_decreasing else "No evidence of rate limiting",
        }

    @staticmethod
    def _extract_rate_limit(response: requests.Response, field: str) -> Optional[int]:
        """Extract rate limit info from response headers."""
        headers_to_check = [f"X-RateLimit-{field}", f"RateLimit-{field}", f"X-Rate-Limit-{field}"]
        for header in headers_to_check:
            value = response.headers.get(header)
            if value:
                try:
                    return int(value)
                except ValueError:
                    continue
        return None

    @staticmethod
    def _extract_rate_limit_reset(response: requests.Response) -> Optional[str]:
        """Extract rate limit reset time."""
        headers_to_check = ["X-RateLimit-Reset", "RateLimit-Reset", "X-Rate-Limit-Reset"]
        for header in headers_to_check:
            value = response.headers.get(header)
            if value:
                return value
        return None

    def save_metrics(self, output_file: Path) -> None:
        """Save metrics to JSON file."""
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w") as f:
            json.dump([asdict(m) for m in self.metrics], f, indent=2)

    def generate_report(self) -> str:
        """Generate HTML performance report."""
        analysis = self.analyze_sla_compliance()
        rate_limit = self.detect_rate_limiting()

        endpoint_rows = "".join(
            f"<tr><td>{endpoint}</td><td>{perf['method']}</td><td>{perf['samples']}</td>"
            f"<td>{perf['avg_response_time']:.2f}</td><td>{perf['min_response_time']:.2f}</td>"
            f"<td>{perf['max_response_time']:.2f}</td></tr>"
            for endpoint, perf in analysis.get("endpoints", {}).items()
        )

        compliance_color = "green" if analysis["sla_compliance"]["overall_compliant"] else "red"
        compliance_status = "COMPLIANT" if analysis["sla_compliance"]["overall_compliant"] else "NON-COMPLIANT"

        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Performance & SLA Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; color: #1f2937; }}
    h1 {{ color: #111827; border-bottom: 2px solid #1f2937; }}
    h2 {{ color: #374151; margin-top: 2rem; }}
    table {{ border-collapse: collapse; width: 100%; margin-bottom: 1.5rem; }}
    th, td {{ border: 1px solid #d1d5db; padding: 0.5rem; text-align: left; }}
    th {{ background: #f3f4f6; font-weight: bold; }}
    .metric-box {{ display: inline-block; background: #f9fafb; padding: 1rem; margin: 0.5rem; border: 1px solid #e5e7eb; border-radius: 0.5rem; }}
    .compliance-{compliance_color} {{ color: {('green' if compliance_color == 'green' else '#DC3545')}; font-weight: bold; }}
  </style>
</head>
<body>
  <h1>API Performance & SLA Compliance Report</h1>
  <p><strong>Generated:</strong> {datetime.now(timezone.utc).isoformat()}</p>
  
  <h2>SLA Compliance Status: <span class="compliance-{compliance_color}">{compliance_status}</span></h2>
  <div class="metric-box">
    <strong>Response Time:</strong> {analysis['sla_compliance']['response_time_compliant']}<br>
    <strong>Error Rate:</strong> {analysis['sla_compliance']['error_rate_compliant']}<br>
    <strong>Availability:</strong> {analysis['sla_compliance']['availability_compliant']}
  </div>
  
  <h2>Performance Summary</h2>
  <div class="metric-box">
    <strong>Total Requests:</strong> {analysis['summary']['total_requests']}<br>
    <strong>Successful:</strong> {analysis['summary']['successful_requests']}<br>
    <strong>Error Rate:</strong> {analysis['summary']['error_rate_percent']}%<br>
    <strong>Availability:</strong> {analysis['summary']['availability_percent']}%
  </div>
  <div class="metric-box">
    <strong>Avg Response Time:</strong> {analysis['summary']['avg_response_time_ms']:.2f}ms<br>
    <strong>Min Response Time:</strong> {analysis['summary']['min_response_time_ms']:.2f}ms<br>
    <strong>Max Response Time:</strong> {analysis['summary']['max_response_time_ms']:.2f}ms
  </div>
  
  <h2>Rate Limiting Detection</h2>
  <p><strong>Rate Limiting Detected:</strong> {rate_limit['detected']}</p>
  <p><strong>Recommendation:</strong> {rate_limit['recommendation']}</p>
  
  <h2>Endpoint Performance</h2>
  <table>
    <thead><tr><th>Endpoint</th><th>Method</th><th>Samples</th><th>Avg (ms)</th><th>Min (ms)</th><th>Max (ms)</th></tr></thead>
    <tbody>{endpoint_rows}</tbody>
  </table>
  
</body>
</html>"""
