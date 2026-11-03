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