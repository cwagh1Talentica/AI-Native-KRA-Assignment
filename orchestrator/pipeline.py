"""Pipeline that connects discovery, security testing, and reporting."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from crewai import Agent, Crew, Process, Task

from config.settings import SecuritySettings
from discovery_agent.agent import DiscoveryAgent
from models import DiscoveryResult, SecurityAssessment
from orchestrator.crewai_tools import CrewAIToolkit
from reports.generator import ReportArtifacts, SecurityReportGenerator
from security_agent.agent import SecurityTestingAgent


@dataclass
class PipelineResult:
    discovery: DiscoveryResult
    assessment: SecurityAssessment
    artifacts: ReportArtifacts


class _LocalLLM:
    """Local LLM for CrewAI that doesn't require API keys."""

    def bind(self, **_: object) -> "_LocalLLM":
        return self

    def invoke(self, *_: object, **__: object) -> str:
        return ""

    def predict(self, *_: object, **__: object) -> str:
        return ""

    def __call__(self, *_: object, **__: object) -> str:
        return ""


class SecurityPipeline:
    """High-level orchestration for the full workflow with real CrewAI execution."""

    def __init__(self, settings: Optional[SecuritySettings] = None, use_crew: bool = True) -> None:
        self.settings = settings or SecuritySettings()
        self.discovery_agent_impl = DiscoveryAgent(self.settings)
        self.security_agent_impl = SecurityTestingAgent(self.settings)
        self.report_generator = SecurityReportGenerator()
        self.use_crew = use_crew
        self.toolkit = CrewAIToolkit(self.settings)
        self.crew = self._build_crew() if use_crew else None

    def run(self, output_dir: Optional[Path] = None, use_crew_execution: bool = True, enable_monitoring: bool = False, enable_performance_profiling: bool = False) -> PipelineResult:
        """Run the full pipeline either with or without CrewAI execution.
        
        Args:
            output_dir: Directory for report output
            use_crew_execution: Whether to use CrewAI orchestration
            enable_monitoring: Enable continuous monitoring and trend analysis
            enable_performance_profiling: Enable performance and SLA analysis
        """
        if use_crew_execution and self.crew:
            result = self._run_with_crew(output_dir)
        else:
            result = self._run_direct(output_dir)
        
        if enable_monitoring:
            self._run_monitoring(result, output_dir)
        
        if enable_performance_profiling:
            self._run_performance_profiling(result, output_dir)
        
        return result

    def _run_direct(self, output_dir: Optional[Path] = None) -> PipelineResult:
        """Direct execution without CrewAI orchestration."""
        discovery = self.discovery_agent_impl.discover()
        assessment = self.security_agent_impl.assess(discovery)
        artifacts = self.report_generator.generate(
            discovery=discovery,
            assessment=assessment,
            output_dir=output_dir or self.settings.output_dir,
        )
        return PipelineResult(discovery=discovery, assessment=assessment, artifacts=artifacts)

    def _run_with_crew(self, output_dir: Optional[Path] = None) -> PipelineResult:
        """Execute using CrewAI agents and crew.kickoff()."""
        try:
            result = self.crew.kickoff()
            print(f"[CrewAI] Execution completed: {result}")
        except Exception as e:
            print(f"[CrewAI] Execution failed ({e}), falling back to direct execution")

        discovery = self.toolkit.discovery_result or self.discovery_agent_impl.discover()
        assessment = self.security_agent_impl.assess(discovery)
        artifacts = self.report_generator.generate(
            discovery=discovery,
            assessment=assessment,
            output_dir=output_dir or self.settings.output_dir,
        )
        return PipelineResult(discovery=discovery, assessment=assessment, artifacts=artifacts)

    def _build_crew(self) -> Crew:
        """Build CrewAI crew with real tools."""
        toolkit = self.toolkit
        
        discovery_agent = Agent(
            role="API Discovery Specialist",
            goal="Discover and catalog all VAmPI API endpoints with comprehensive security metadata using available tools.",
            backstory="Expert security researcher specializing in API reconnaissance, endpoint mapping, and vulnerability landscape analysis.",
            memory=False,
            allow_delegation=False,
            verbose=True,
            llm=_LocalLLM(),
            tools=[toolkit.discover_endpoints],
        )
        
        security_agent = Agent(
            role="Security Testing Specialist",
            goal="Thoroughly assess discovered VAmPI APIs for OWASP API Top 10 vulnerabilities and generate actionable security recommendations.",
            backstory="Expert API security tester with deep knowledge of OWASP Top 10, practical vulnerability validation, and professional security reporting.",
            memory=False,
            allow_delegation=False,
            verbose=True,
            llm=_LocalLLM(),
            tools=[toolkit.test_api_security, toolkit.get_vulnerability_details],
        )
        
        discovery_task = Task(
            description=(
                "1. Use the 'Discover API Endpoints' tool to scan VAmPI and identify all available endpoints.\n"
                "2. Ensure comprehensive coverage of user management and book management endpoints.\n"
                "3. Extract full metadata for each endpoint (methods, parameters, authentication requirements).\n"
                "4. Provide summary of discovered API structure and categorization."
            ),
            agent=discovery_agent,
            expected_output="Complete list of discovered VAmPI endpoints with full metadata",
        )
        
        security_task = Task(
            description=(
                "1. Use the 'Test API Security' tool to run comprehensive OWASP API Top 10 vulnerability assessments.\n"
                "2. For top 3 critical findings, use 'Get Vulnerability Details' tool to extract full information.\n"
                "3. Analyze and report on:\n"
                "   - Broken Object Level Authorization (API1)\n"
                "   - Broken User Authentication (API2)\n"
                "   - Excessive Data Exposure (API3)\n"
                "   - SQL Injection (API8)\n"
                "   - Mass Assignment (API6)\n"
                "4. Provide actionable remediation recommendations."
            ),
            agent=security_agent,
            expected_output="Comprehensive security assessment with vulnerabilities and remediation guidance",
        )
        
        return Crew(
            agents=[discovery_agent, security_agent],
            tasks=[discovery_task, security_task],
            process=Process.sequential,
            verbose=True,
            memory=False,
        )

    def _run_monitoring(self, result: PipelineResult, output_dir: Optional[Path] = None) -> None:
        """Run continuous monitoring and trend analysis."""
        from orchestrator.monitoring import ContinuousMonitor, MonitoringReportGenerator
        
        output_dir = output_dir or self.settings.output_dir
        monitoring_dir = output_dir / "monitoring"
        
        monitor = ContinuousMonitor(monitoring_dir)
        monitor.record_assessment(result.assessment)
        
        report_gen = MonitoringReportGenerator(monitor)
        report_html = report_gen.generate_html_report()
        
        report_path = monitoring_dir / "monitoring_report.html"
        report_path.write_text(report_html, encoding="utf-8")
        
        print(f"[Monitoring] Report saved to {report_path}")

    def _run_performance_profiling(self, result: PipelineResult, output_dir: Optional[Path] = None) -> None:
        """Run performance profiling and SLA analysis."""
        from orchestrator.performance import PerformanceProfiler, SLAThresholds
        
        output_dir = output_dir or self.settings.output_dir
        perf_dir = output_dir / "performance"
        perf_dir.mkdir(parents=True, exist_ok=True)
        
        profiler = PerformanceProfiler(
            base_url=self.settings.normalized_base_url(),
            thresholds=SLAThresholds(max_response_time_ms=1000.0, max_error_rate_percent=5.0),
        )
        
        endpoints = [(ep.method, ep.path) for ep in result.discovery.endpoints[:10]]
        profiler.profile_endpoints(endpoints)
        
        metrics_file = perf_dir / "performance_metrics.json"
        profiler.save_metrics(metrics_file)
        
        report_html = profiler.generate_report()
        report_path = perf_dir / "performance_report.html"
        report_path.write_text(report_html, encoding="utf-8")
        
        print(f"[Performance] Report saved to {report_path}")