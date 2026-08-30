from __future__ import annotations

import pytest

from orchestrator.pipeline import SecurityPipeline


@pytest.mark.skip(reason="CrewAI 0.1.32 compatibility issue with LangChain - crew execution works but crew building has Pydantic validation errors")
def test_pipeline_builds_two_agent_crew():
    pipeline = SecurityPipeline(use_crew=False)

    assert pipeline.discovery_agent_impl is not None
    assert pipeline.security_agent_impl is not None

