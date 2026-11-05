
from unittest.mock import Mock

import pytest

from src.agents.llm_explanation import LLMExplanationAgent


@pytest.fixture
def sample_analysis():
    return {
        "cve_id": "CVE-2025-12345",
        "risk": {
            "score": 85.0,
            "level": "CRITICAL",
            "is_kev": True,
            "cvss_score": 9.8,
            "cvss_severity": "CRITICAL",
            "epss_score": 0.95,
            "epss_percentile": 0.99,
            "scoring_basis": "KEV_OVERRIDE",
        },
        "description": "Example vulnerability description.",
        "advisories": [
            {
                "osv_id": "GHSA-example",
                "summary": "Example vulnerability description.",
                "details": "The issue allows stored cross-site scripting.",
                "published": "2025-01-01",
                "modified": "2025-01-02",
            }
        ],
        "affected_packages": [
            {
                "ecosystem": "PyPI",
                "package_name": "example-package",
                "installed_version": "1.0.0",
                "version_status": "AFFECTED",
                "fixed_versions": ["1.0.2"],
            }
        ],
        "installed_package_check_performed": True,
        "analysis": ["Example deterministic analysis."],
        "recommendations": ["Upgrade example-package to 1.0.2."],
        "metadata": {
            "osv_record_count": 1,
            "advisory_count": 1,
            "affected_package_count": 1,
        },
    }


def test_explain_returns_structured_result(sample_analysis):
    provider = Mock()
    provider.generate.return_value = (
        "1. Vulnerability Summary\n"
        "Example explanation."
    )
    provider.model = "llama3.2:3b"

    agent = LLMExplanationAgent(provider=provider)

    result = agent.explain(sample_analysis)

    assert result["cve_id"] == "CVE-2025-12345"
    assert "Example explanation" in result["explanation"]
    assert result["risk"] == sample_analysis["risk"]
    assert result["affected_packages"] == sample_analysis["affected_packages"]
    assert result["metadata"]["provider"] == "Mock"
    provider.generate.assert_called_once()


def test_explain_builds_prompt_with_analysis_data(sample_analysis):
    provider = Mock()
    provider.generate.return_value = "Explanation"

    agent = LLMExplanationAgent(provider=provider)

    agent.explain(sample_analysis)

    prompt = provider.generate.call_args[0][0]

    assert "CVE-2025-12345" in prompt
    assert "example-package" in prompt
    assert "1.0.2" in prompt
    assert "KEV_OVERRIDE" in prompt
    assert "The issue allows stored cross-site scripting." in prompt


def test_prompt_forbids_unsupported_impact_and_explains_zero_boundary(
    sample_analysis,
):
    prompt = " ".join(
        LLMExplanationAgent(provider=Mock())
        ._build_prompt(sample_analysis)
        .split()
    )

    assert "A vulnerability title or class alone is not enough" in prompt
    assert "If impact is not explicitly established" in prompt
    assert "literal released package version" in prompt
    assert "Keep Potential Impact and Analysis Limitations consistent" in prompt


def test_explain_rejects_non_dictionary():
    agent = LLMExplanationAgent(provider=Mock())

    with pytest.raises(ValueError, match="dictionary"):
        agent.explain("invalid")


def test_explain_rejects_missing_cve():
    agent = LLMExplanationAgent(provider=Mock())

    with pytest.raises(ValueError, match="CVE ID"):
        agent.explain({"risk": {}})


def test_explain_rejects_missing_required_field(sample_analysis):
    provider = Mock()
    agent = LLMExplanationAgent(provider=provider)

    invalid_analysis = sample_analysis.copy()
    del invalid_analysis["risk"]

    with pytest.raises(ValueError, match="risk"):
        agent.explain(invalid_analysis)

    provider.generate.assert_not_called()


def test_explain_handles_provider_error(sample_analysis):
    provider = Mock()
    provider.generate.side_effect = RuntimeError("LLM unavailable")

    agent = LLMExplanationAgent(provider=provider)

    with pytest.raises(RuntimeError, match="LLM unavailable"):
        agent.explain(sample_analysis)
