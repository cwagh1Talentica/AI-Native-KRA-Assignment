#!/usr/bin/env python3
"""Example: Running the full VAmPI Security Assessment Pipeline with all enhancements."""

from pathlib import Path
from orchestrator.pipeline import SecurityPipeline
from config.settings import SecuritySettings

def main():
    """Run the complete security assessment with all features."""
    
    # Configure the pipeline
    settings = SecuritySettings(
        base_url="http://localhost:5000",
        request_delay_seconds=0.1,
    )
    
    # Create output directory
    output_dir = Path("./vampi_assessment_results")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize the pipeline
    print("🔍 Initializing VAmPI Security Assessment Pipeline...")
    pipeline = SecurityPipeline(settings=settings, use_crew=False)
    
    # Run the full pipeline with all enhancements
    print("🚀 Starting assessment with:")
    print("  ✓ API Discovery")
    print("  ✓ Security Testing (OWASP API Top 10)")
    print("  ✓ Working PoC Exploit Generation")
    print("  ✓ Professional PDF Reports with Charts")
    print("  ✓ Continuous Monitoring & Trends")
    print("  ✓ Performance & SLA Analysis")
    print()
    
    result = pipeline.run(
        output_dir=output_dir,
        use_crew_execution=False,
        enable_monitoring=True,
        enable_performance_profiling=True,
    )
    
    # Print summary
    print("\n" + "="*70)
    print("📊 ASSESSMENT COMPLETE")
    print("="*70)
    
    print(f"\n✓ Discovered Endpoints: {len(result.discovery.endpoints)}")
    print(f"✓ Security Findings: {len(result.assessment.findings)}")
    
    severity_counts = {}
    for finding in result.assessment.findings:
        sev = finding.severity.lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    print(f"\n📋 Findings by Severity:")
    for severity in ["critical", "high", "medium", "low"]:
        count = severity_counts.get(severity, 0)
        print(f"   {severity.upper():10s}: {count}")
    
    # Print report locations
    print(f"\n📁 Reports Generated:")
    print(f"   JSON Report:       {result.artifacts.json_path}")
    print(f"   HTML Report:       {result.artifacts.html_path}")
    print(f"   PDF Report:        {result.artifacts.pdf_path}")
    print(f"   Audit Log:         {result.artifacts.audit_log_path}")
    print(f"   Monitoring:        {output_dir / 'monitoring' / 'monitoring_report.html'}")
    print(f"   Performance:       {output_dir / 'performance' / 'performance_report.html'}")
    
    # Print top findings
    print(f"\n⚠️  Top Security Findings:")
    for idx, finding in enumerate(sorted(result.assessment.findings, key=lambda f: -f.cvss_score)[:5], 1):
        print(f"   {idx}. [{finding.severity.upper()}] {finding.title}")
        print(f"      CVSS: {finding.cvss_score} | {finding.method} {finding.endpoint}")
        if finding.evidence.get("poc_results"):
            poc = finding.evidence["poc_results"]
            print(f"      PoC: {poc['successful']}/{poc['total_attempts']} exploits succeeded")
        print()
    
    print("="*70)
    print("✅ VAmPI Security Assessment Complete!")
    print("="*70)


if __name__ == "__main__":
    main()
