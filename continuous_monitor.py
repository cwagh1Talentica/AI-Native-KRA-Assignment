"""Continuous monitoring runner for recurring API security assessments."""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from config.settings import SecuritySettings
from orchestrator.pipeline import SecurityPipeline


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run recurring VAmPI security assessments.")
    parser.add_argument("--base-url", default="http://localhost:5000", help="Target base URL")
    parser.add_argument("--interval-seconds", type=int, default=300, help="Seconds between runs")
    parser.add_argument("--iterations", type=int, default=0, help="Number of runs (0 means continuous)")
    parser.add_argument("--output-dir", default="monitoring", help="Monitoring output directory")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    settings = SecuritySettings(base_url=args.base_url, output_dir=output_dir / "reports")
    pipeline = SecurityPipeline(settings)
    run_count = 0

    while True:
        run_count += 1
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        result = pipeline.run(output_dir=output_dir / "reports" / timestamp)
        summary = {
            "timestamp": timestamp,
            "target": settings.normalized_base_url(),
            "endpoint_count": len(result.discovery.endpoints),
            "finding_count": len(result.assessment.findings),
            "risk_summary": result.assessment.risk_summary(),
            "report_paths": {
                "json": str(result.artifacts.json_path),
                "html": str(result.artifacts.html_path),
                "pdf": str(result.artifacts.pdf_path) if result.artifacts.pdf_path else "",
                "audit_log": str(result.artifacts.audit_log_path) if result.artifacts.audit_log_path else "",
            },
        }
        (output_dir / f"run-{timestamp}.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
        (output_dir / "latest.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
        print(f"[monitor] run={run_count} findings={summary['finding_count']} report={summary['report_paths']['json']}")

        if args.iterations and run_count >= args.iterations:
            break
        time.sleep(args.interval_seconds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
