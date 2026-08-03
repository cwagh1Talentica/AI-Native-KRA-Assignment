from __future__ import annotations

from orchestrator.pipeline import SecurityPipeline


def test_pipeline_builds_two_agent_crew():
    pipeline = SecurityPipeline()

    assert len(pipeline.crew.agents) == 2
    assert [task.description for task in pipeline.crew.tasks] == [
        "Discover VAmPI endpoints and metadata.",
        "Test discovered endpoints for OWASP API Top 10 issues.",
    ]
    assert pipeline.crew.process.value == "sequential"
