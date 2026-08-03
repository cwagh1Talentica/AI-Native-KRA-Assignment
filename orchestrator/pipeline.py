"""Pipeline that connects discovery, security testing, and reporting."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from crewai import Agent, Crew, Process, Task

from config.settings import SecuritySettings
from discovery_agent.agent import DiscoveryAgent
from models import DiscoveryResult, SecurityAssessment
from reports.generator import ReportArtifacts, SecurityReportGenerator
from security_agent.agent import SecurityTestingAgent


@dataclass
class PipelineResult:
    discovery: DiscoveryResult
    assessment: SecurityAssessment
    artifacts: ReportArtifacts


class _OfflineLLM:
    """Minimal LLM stub so CrewAI agents can be built offline."""

    def bind(self, **_: object) -> "_OfflineLLM":
        return self

    def invoke(self, *_: object, **__: object) -> str:
        return ""

    def predict(self, *_: object, **__: object) -> str:
        return ""

    def __call__(self, *_: object, **__: object) -> str:
        return ""


class SecurityPipeline:
    """High-level orchestration for the full workflow."""

    def __init__(self, settings: Optional[SecuritySettings] = None) -> None:
        self.settings = settings or SecuritySettings()
        self.discovery_agent = DiscoveryAgent(self.settings)
        self.security_agent = SecurityTestingAgent(self.settings)
        self.report_generator = SecurityReportGenerator()
        self.crew = self._build_crew()

    def run(self, output_dir: Optional[Path] = None) -> PipelineResult:
        discovery = self.discovery_agent.discover()
        assessment = self.security_agent.assess(discovery)
        artifacts = self.report_generator.generate(
            discovery=discovery,
            assessment=assessment,
            output_dir=output_dir or self.settings.output_dir,
        )
        return PipelineResult(discovery=discovery, assessment=assessment, artifacts=artifacts)

    def _build_crew(self) -> Crew:
        discovery_agent = Agent(
            role="API Discovery Specialist",
            goal="Discover and catalog all VAmPI API endpoints with security metadata.",
            backstory="Security researcher specializing in API reconnaissance and endpoint mapping.",
            memory=False,
            allow_delegation=False,
            verbose=False,
            llm=_OfflineLLM(),
            tools=[],
        )
        security_agent = Agent(
            role="Security Testing Specialist",
            goal="Assess discovered VAmPI APIs for OWASP API Top 10 vulnerabilities.",
            backstory="API security tester focused on practical vulnerability validation and reporting.",
            memory=False,
            allow_delegation=False,
            verbose=False,
            llm=_OfflineLLM(),
            tools=[],
        )
        tasks = [
            Task(
                description="Discover VAmPI endpoints and metadata.",
                agent=discovery_agent,
            ),
            Task(
                description="Test discovered endpoints for OWASP API Top 10 issues.",
                agent=security_agent,
            ),
        ]
        return Crew(
            agents=[discovery_agent, security_agent],
            tasks=tasks,
            process=Process.sequential,
            verbose=False,
        )