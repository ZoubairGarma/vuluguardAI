from src.agents.llm_explanation import LLMExplanationAgent


def test_detects_false_absence_from_kev():
    facts = {
        "risk": {
            "is_kev": True,
            "epss_percentile": 0.99,
        }
    }

    warnings = LLMExplanationAgent._validate_generated_explanation(
        "This vulnerability is not listed in the KEV catalog.",
        facts,
    )

    assert any("KEV" in warning for warning in warnings)


def test_detects_false_presence_in_kev():
    facts = {
        "risk": {
            "is_kev": False,
            "epss_percentile": 0.99,
        }
    }

    warnings = LLMExplanationAgent._validate_generated_explanation(
        "This vulnerability is listed in the KEV catalog.",
        facts,
    )

    assert any("KEV" in warning for warning in warnings)


def test_detects_unavailable_percentile_when_present():
    facts = {
        "risk": {
            "is_kev": True,
            "epss_percentile": 0.99,
        }
    }

    warnings = LLMExplanationAgent._validate_generated_explanation(
        "The EPSS percentile is unavailable.",
        facts,
    )

    assert any("percentile" in warning.lower() for warning in warnings)


def test_accepts_consistent_explanation():
    facts = {
        "risk": {
            "is_kev": True,
            "epss_percentile": 0.99,
        }
    }

    warnings = LLMExplanationAgent._validate_generated_explanation(
        "This vulnerability is listed in the KEV catalog. "
        "Its EPSS percentile is 0.99.",
        facts,
    )

    assert warnings == []


def test_does_not_flag_unknown_kev_status():
    facts = {
        "risk": {
            "is_kev": None,
            "epss_percentile": None,
        }
    }

    warnings = LLMExplanationAgent._validate_generated_explanation(
        "The KEV status and EPSS percentile are unavailable.",
        facts,
    )

    assert warnings == []

def test_detects_kev_claim_with_full_catalog_name():
    facts = {
        "risk": {
            "is_kev": False,
            "epss_percentile": 0.99,
        }
    }

    warnings = LLMExplanationAgent._validate_generated_explanation(
        "The vulnerability is listed in the Known Exploited Vulnerabilities (KEV) catalog.",
        facts,
    )

    assert any("KEV" in warning for warning in warnings)


def test_detects_unavailable_kev_status_when_false():
    facts = {
        "risk": {
            "is_kev": False,
            "epss_percentile": None,
        }
    }

    warnings = LLMExplanationAgent._validate_generated_explanation(
        "The KEV status is unavailable.",
        facts,
    )

    assert any("KEV" in warning for warning in warnings)


def test_detects_unavailable_kev_status_when_true():
    facts = {
        "risk": {
            "is_kev": True,
            "epss_percentile": None,
        }
    }

    warnings = LLMExplanationAgent._validate_generated_explanation(
        "The KEV status is unavailable.",
        facts,
    )

    assert any("KEV" in warning for warning in warnings)    


def test_flags_missing_or_mismatched_source_metrics():
    facts = {
        "cve_id": "CVE-2025-12345",
        "risk": {
            "score": 85.0,
            "level": "CRITICAL",
            "cvss_score": 9.8,
            "epss_score": 0.95,
            "epss_percentile": 0.99,
            "is_kev": True,
        },
        "affected_packages": [
            {
                "package_name": "example-package",
                "installed_version": "1.0.0",
                "version_status": "AFFECTED",
                "fixed_versions": ["1.0.2"],
            }
        ],
    }

    warnings = LLMExplanationAgent._validate_generated_explanation(
        "CVE-2025-12345 is CRITICAL with a CVSS score of 7.2. "
        "The example-package version 1.0.0 is not affected.",
        facts,
    )

    assert any("cvss_score" in warning for warning in warnings)
    assert any("Package status contradiction" in warning for warning in warnings)
    assert any("Fixed version missing" in warning for warning in warnings)


def test_accepts_complete_matching_facts():
    facts = {
        "cve_id": "CVE-2025-12345",
        "risk": {
            "score": 85.0,
            "level": "CRITICAL",
            "cvss_score": 9.8,
            "epss_score": 0.95,
            "epss_percentile": 0.99,
            "is_kev": True,
        },
        "affected_packages": [
            {
                "package_name": "example-package",
                "installed_version": "1.0.0",
                "version_status": "AFFECTED",
                "fixed_versions": ["1.0.2"],
            }
        ],
    }

    explanation = (
        "CVE-2025-12345 is CRITICAL with VulnGuard score 85, CVSS 9.8, "
        "EPSS 0.95 and percentile 0.99. It is listed in KEV. "
        "example-package version 1.0.0 is AFFECTED; OSV lists 1.0.2 as fixed."
    )

    assert LLMExplanationAgent._validate_generated_explanation(
        explanation, facts
    ) == []