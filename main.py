"""Command-line entry point for the API security testing duo."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict

from config.settings import SecuritySettings
from orchestrator.pipeline import SecurityPipeline


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run VAmPI discovery and security testing.")
    parser.add_argument("--base-url", default=None, help="Target base URL, e.g. http://localhost:5000")
    parser.add_argument("--output-dir", default=None, help="Directory for JSON and HTML reports")
    parser.add_argument(
        "--phase",
        choices=["1", "2", "3"],
        default="3",
        help="Generate phase-specific deliverables (1=discovery, 2=security testing, 3=integrated assessment).",
    )
    parser.add_argument(
        "--deliverables-dir",
        default="deliverables",
        help="Base directory for phase deliverable artifacts.",
    )
    return parser.parse_args()


def _write_json(path: Path, payload: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def main() -> int:
    args = parse_args()
    default_settings = SecuritySettings()
    settings = SecuritySettings(
        base_url=args.base_url or default_settings.base_url,
        output_dir=Path(args.output_dir) if args.output_dir else default_settings.output_dir,
    )
    pipeline = SecurityPipeline(settings)
    deliverables_dir = Path(args.deliverables_dir)

    if args.phase == "1":
        discovery = pipeline.discovery_agent.discover()
        output_path = deliverables_dir / "phase1" / "vampi_api_catalog.json"
        _write_json(output_path, discovery.to_dict())
        print("Phase 1 complete")
        print(f"Discovered endpoints: {len(discovery.endpoints)}")
        print(f"API catalog: {output_path}")
        return 0

    if args.phase == "2":
        discovery = pipeline.discovery_agent.discover()
        assessment = pipeline.security_agent.assess(discovery)
        output_path = deliverables_dir / "phase2" / "vampi_vulnerability_assessment.json"
        _write_json(
            output_path,
            {
                "discovery_summary": {
                    "endpoint_count": len(discovery.endpoints),
                    "source": discovery.source,
                },
                "assessment": assessment.to_dict(),
            },
        )
        print("Phase 2 complete")
        print(f"Findings: {len(assessment.findings)}")
        print(f"Security assessment: {output_path}")
        return 0

    result = pipeline.run()
    phase3_dir = deliverables_dir / "phase3"
    phase3_dir.mkdir(parents=True, exist_ok=True)
    integrated_json = phase3_dir / "integrated_security_assessment.json"
    _write_json(
        integrated_json,
        {
            "discovery": result.discovery.to_dict(),
            "assessment": result.assessment.to_dict(),
            "report_paths": {
                "json": str(result.artifacts.json_path),
                "html": str(result.artifacts.html_path),
                "pdf": str(result.artifacts.pdf_path) if result.artifacts.pdf_path else "",
                "audit_log": str(result.artifacts.audit_log_path) if result.artifacts.audit_log_path else "",
            },
        },
    )
    print("Phase 3 complete")
    print(f"Discovery endpoints: {len(result.discovery.endpoints)}")
    print(f"Findings: {len(result.assessment.findings)}")
    print(f"Integrated assessment: {integrated_json}")
    print(f"JSON report: {result.artifacts.json_path}")
    print(f"HTML report: {result.artifacts.html_path}")
    if result.artifacts.pdf_path:
        print(f"PDF report: {result.artifacts.pdf_path}")
    if result.artifacts.audit_log_path:
        print(f"Audit log: {result.artifacts.audit_log_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
