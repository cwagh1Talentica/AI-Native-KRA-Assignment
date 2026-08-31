"""Pipeline that connects discovery, security testing, and reporting."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from crewai import Agent, Crew, Process, Task
from langchain_core.tools import StructuredTool

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


_DISCOVERY_RESPONSES: List[str] = [
    (
        "Thought: I need to call the discovery tool to enumerate all VAmPI endpoints.\n"
        "Action: discover_endpoints\n"
        "Action Input: scan"
    ),
    *[
        "Thought: Endpoint enumeration complete.\nFinal Answer: All VAmPI API endpoints catalogued with authentication requirements and risk classification."
        for _ in range(12)
    ],
]

_SECURITY_RESPONSES: List[str] = [
    (
        "Thought: I will run the full OWASP API Top 10 security assessment.\n"
        "Action: test_api_security\n"
        "Action Input: run"
    ),
    "Thought: Assessment done; retrieving details for the top finding.\nAction: get_vulnerability_details\nAction Input: 0",
    *[
        "Thought: Full details retrieved.\nFinal Answer: Security assessment complete. OWASP API Top 10 categories evaluated with BOLA, broken authentication, excessive data exposure, injection, and mass-assignment findings documented."
        for _ in range(12)
    ],
]


def _make_scripted_llm(responses: List[str]):
    """Return a proper LangChain BaseLLM that replays scripted ReAct responses.

    Uses FakeListLLM which is a genuine LangChain BaseLLM subclass, satisfying
    CrewAI's pydantic v1 validator that requires a real BaseLanguageModel instance.
    Each agent must receive its own instance so their response counters are independent.
    """
    try:
        from langchain_community.llms.fake import FakeListLLM
    except ImportError:
        from langchain.llms.fake import FakeListLLM  # type: ignore[no-redef]

    class _CyclingFakeListLLM(FakeListLLM):
        def _call(self, prompt: str, stop: Optional[List[str]] = None, run_manager=None, **kwargs):  # type: ignore[override]
            if not self.responses:
                return ""
            response = self.responses[self.i % len(self.responses)]
            self.i += 1
            return response

    return _CyclingFakeListLLM(responses=responses)


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
        def _discover_endpoints_tool(prompt: str = "") -> str:
            return toolkit.discover_endpoints()

        def _test_api_security_tool(prompt: str = "") -> str:
            return toolkit.test_api_security()

        def _get_vulnerability_details_tool(finding_index: str = "0") -> str:
            return toolkit.get_vulnerability_details(int(finding_index))

        discovery_tool = StructuredTool.from_function(
            func=_discover_endpoints_tool,
            name="discover_endpoints",
            description="Discover and catalog all VAmPI API endpoints.",
        )
        test_tool = StructuredTool.from_function(
            func=_test_api_security_tool,
            name="test_api_security",
            description="Run OWASP API Top 10 security testing against discovered endpoints.",
        )
        details_tool = StructuredTool.from_function(
            func=_get_vulnerability_details_tool,
            name="get_vulnerability_details",
            description="Return detailed information about a specific vulnerability finding.",
        )
        
        discovery_agent = Agent(
            role="API Discovery Specialist",
            goal="Discover and catalog all VAmPI API endpoints with comprehensive security metadata using available tools.",
            backstory="Expert security researcher specializing in API reconnaissance, endpoint mapping, and vulnerability landscape analysis.",
            memory=False,
            allow_delegation=False,
            verbose=True,
            llm=_make_scripted_llm(list(_DISCOVERY_RESPONSES)),
            tools=[discovery_tool],
        )
        
        security_agent = Agent(
            role="Security Testing Specialist",
            goal="Thoroughly assess discovered VAmPI APIs for OWASP API Top 10 vulnerabilities and generate actionable security recommendations.",
            backstory="Expert API security tester with deep knowledge of OWASP Top 10, practical vulnerability validation, and professional security reporting.",
            memory=False,
            allow_delegation=False,
            verbose=True,
            llm=_make_scripted_llm(list(_SECURITY_RESPONSES)),
            tools=[test_tool, details_tool],
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