
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
    assert result["validation_errors"] == []
    assert result["validation_version"] == 2
    provider.generate.assert_called_once()


def test_omissions_are_notes_not_blocking_errors(sample_analysis):
    provider = Mock()
    provider.generate.return_value = "A short explanation without every metric."

    result = LLMExplanationAgent(provider=provider).explain(sample_analysis)

    assert result["validation_warnings"]
    assert result["validation_errors"] == []


def test_explicit_mismatched_cvss_is_blocking(sample_analysis):
    provider = Mock()
    provider.generate.return_value = (
        "CVE-2025-12345 has a CRITICAL CVSS score of 4.1. "
        "The example-package version 1.0.0 is AFFECTED and OSV lists 1.0.2 as fixed. "
        "The risk score is 85, EPSS score is 0.95 and EPSS percentile is 0.99. "
        "It is listed in KEV."
    )

    result = LLMExplanationAgent(provider=provider).explain(sample_analysis)

    assert any("cvss_score" in warning for warning in result["validation_errors"])


def test_withholds_false_package_status_but_not_omitted_fixed_version(sample_analysis):
    provider = Mock()
    provider.generate.return_value = (
        "CVE-2025-12345 is CRITICAL. The example-package version 1.0.0 "
        "is not affected. The risk score is 85, CVSS score is 9.8, "
        "EPSS score is 0.95 and EPSS percentile is 0.99. It is listed in KEV."
    )

    result = LLMExplanationAgent(provider=provider).explain(sample_analysis)

    assert any("Package status contradiction" in item for item in result["validation_errors"])


def test_retries_once_to_repair_kev_contradiction(sample_analysis):
    provider = Mock()
    provider.generate.side_effect = [
        "CVE-2025-12345 is CRITICAL with score 85 and CVSS 9.8. "
        "EPSS is 0.95 and its percentile is 0.99. It is listed in KEV. "
        "The KEV status is unavailable. example-package 1.0.0 is AFFECTED; "
        "version 1.0.2 is fixed.",
        "CVE-2025-12345 is CRITICAL with score 85 and CVSS 9.8. "
        "EPSS is 0.95 and its percentile is 0.99. It is listed in KEV. "
        "example-package 1.0.0 is AFFECTED; OSV lists 1.0.2 as fixed.",
    ]

    result = LLMExplanationAgent(provider=provider).explain(sample_analysis)

    assert provider.generate.call_count == 2
    assert result["repair_attempts"] == 1
    assert result["validation_errors"] == []


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
