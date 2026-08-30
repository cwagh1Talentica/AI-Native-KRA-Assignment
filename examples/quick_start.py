#!/usr/bin/env python3
"""Quick start: Run the VAmPI security assessment for phase demonstrations."""

from pathlib import Path
from orchestrator.pipeline import SecurityPipeline
from config.settings import SecuritySettings

def run_phase_1_discovery():
    """Phase 1: API Discovery Only"""
    print("\n" + "="*70)
    print("PHASE 1: API DISCOVERY")
    print("="*70)
    
    settings = SecuritySettings(base_url="http://localhost:5000")
    pipeline = SecurityPipeline(settings=settings, use_crew=False)
    result = pipeline.run(output_dir=Path("./phase1_results"), use_crew_execution=False)
    
    print(f"\n✓ Phase 1 Complete!")
    print(f"  Discovered {len(result.discovery.endpoints)} endpoints")
    print(f"  Reports: {result.artifacts.json_path}, {result.artifacts.html_path}")
    return result


def run_phase_2_security():
    """Phase 2: Security Testing"""
    print("\n" + "="*70)
    print("PHASE 2: SECURITY TESTING")
    print("="*70)
    
    settings = SecuritySettings(base_url="http://localhost:5000")
    pipeline = SecurityPipeline(settings=settings, use_crew=False)
    result = pipeline.run(output_dir=Path("./phase2_results"), use_crew_execution=False)
    
    severity_counts = {}
    for finding in result.assessment.findings:
        sev = finding.severity.lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    print(f"\n✓ Phase 2 Complete!")
    print(f"  Found {len(result.assessment.findings)} security issues")
    print(f"  Severity: {severity_counts}")
    print(f"  Reports: {result.artifacts.html_path}")
    
    print("\n  Top Findings:")
    for finding in sorted(result.assessment.findings, key=lambda f: -f.cvss_score)[:3]:
        print(f"    - [{finding.severity.upper()}] {finding.title} (CVSS {finding.cvss_score})")
    
    return result


def run_phase_3_integration():
    """Phase 3: Full Integration with Advanced Features"""
    print("\n" + "="*70)
    print("PHASE 3: INTEGRATED ASSESSMENT WITH ADVANCED FEATURES")
    print("="*70)
    
    settings = SecuritySettings(base_url="http://localhost:5000")
    pipeline = SecurityPipeline(settings=settings, use_crew=False)
    
    output_dir = Path("./phase3_results")
    result = pipeline.run(
        output_dir=output_dir,
        use_crew_execution=False,
        enable_monitoring=True,
        enable_performance_profiling=True,
    )
    
    print(f"\n✓ Phase 3 Complete!")
    print(f"  Endpoints: {len(result.discovery.endpoints)}")
    print(f"  Findings: {len(result.assessment.findings)}")
    print(f"\n  Reports Generated:")
    print(f"    - HTML with Charts: {result.artifacts.html_path}")
    print(f"    - Monitoring Trends: {output_dir / 'monitoring' / 'monitoring_report.html'}")
    print(f"    - Performance SLA: {output_dir / 'performance' / 'performance_report.html'}")
    
    # Show exploit results
    poc_count = 0
    for finding in result.assessment.findings:
        if finding.evidence.get("poc_results"):
            poc_count += finding.evidence["poc_results"]["successful"]
    
    print(f"\n  PoC Exploits Successful: {poc_count}")
    
    return result


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        phase = sys.argv[1]
        if phase == "1":
            run_phase_1_discovery()
        elif phase == "2":
            run_phase_2_security()
        elif phase == "3":
            run_phase_3_integration()
        else:
            print("Usage: python quick_start.py [1|2|3]")
            print("  1 = Phase 1 (Discovery)")
            print("  2 = Phase 2 (Security Testing)")
            print("  3 = Phase 3 (Full Integration)")
    else:
        print("Running full assessment...")
        run_phase_3_integration()
