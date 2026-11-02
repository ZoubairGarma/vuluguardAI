
import pandas as pd
import pytest

from src.agents.risk_scoring import (
    calculate_risk,
    parse_boolean,
    select_cvss,
)


def make_row(
    is_kev=False,
    cvss_v3=8.0,
    cvss_v4=9.0,
    epss=0.5,
):
    return pd.Series({
        "cve_id": "CVE-2025-12345",
        "is_kev": is_kev,
        "cvss_v3_score": cvss_v3,
        "cvss_v3_severity": "High" if pd.notna(cvss_v3) else None,
        "cvss_v4_score": cvss_v4,
        "cvss_v4_severity": "Critical" if pd.notna(cvss_v4) else None,
        "epss_score": epss,
    })


def test_kev_always_receives_critical_score():
    row = make_row(
        is_kev=True,
        cvss_v3=4.0,
        cvss_v4=5.0,
        epss=0.01,
    )

    result = calculate_risk(row)

    assert result["risk_score"] == 100.0
    assert result["risk_level"] == "CRITICAL"
    assert result["scoring_basis"] == "KEV_OVERRIDE"


def test_cvss_v3_is_preferred_over_v4():
    row = make_row(cvss_v3=7.5, cvss_v4=9.0)

    score, severity, source = select_cvss(row)

    assert score == 7.5
    assert severity == "High"
    assert source == "CVSS_V3"


def test_cvss_v4_is_used_when_v3_is_missing():
    row = make_row(cvss_v3=float("nan"), cvss_v4=8.0)

    score, severity, source = select_cvss(row)

    assert score == 8.0
    assert severity == "Critical"
    assert source == "CVSS_V4"


def test_risk_score_with_cvss_and_epss():
    row = make_row(cvss_v3=8.0, epss=0.5)

    result = calculate_risk(row)

    # (0.60 * 0.80 + 0.40 * 0.50) * 100 = 68
    assert result["risk_score"] == 68.0
    assert result["risk_level"] == "HIGH"
    assert result["scoring_basis"] == "CVSS_EPSS"


def test_risk_score_with_cvss_only():
    row = make_row(cvss_v3=9.0, cvss_v4=float("nan"), epss=float("nan"))

    result = calculate_risk(row)

    assert result["risk_score"] == 90.0
    assert result["risk_level"] == "CRITICAL"
    assert result["scoring_basis"] == "CVSS_ONLY"


def test_risk_score_with_epss_only():
    row = make_row(
        cvss_v3=float("nan"),
        cvss_v4=float("nan"),
        epss=0.7,
    )

    result = calculate_risk(row)

    assert result["risk_score"] == 70.0
    assert result["risk_level"] == "HIGH"
    assert result["scoring_basis"] == "EPSS_ONLY"


def test_missing_cvss_and_epss_returns_unknown():
    row = make_row(
        cvss_v3=float("nan"),
        cvss_v4=float("nan"),
        epss=float("nan"),
    )

    result = calculate_risk(row)

    assert pd.isna(result["risk_score"])
    assert result["risk_level"] == "UNKNOWN"
    assert result["scoring_basis"] == "NO_DATA"


@pytest.mark.parametrize(
    "value, expected",
    [
        (True, True),
        (False, False),
        ("true", True),
        ("false", False),
        ("1", True),
        ("0", False),
        (1, True),
        (0, False),
    ],
)
def test_parse_boolean(value, expected):
    assert parse_boolean(value, "is_kev") is expected


def test_parse_boolean_rejects_invalid_values():
    with pytest.raises(ValueError):
        parse_boolean("unknown", "is_kev")


def test_risk_explanation_is_generated():
    row = make_row(cvss_v3=8.0, epss=0.5)

    result = calculate_risk(row)

    assert result["risk_explanation"]
    assert "CVSS_V3" in result["risk_explanation"]
    assert "EPSS" in result["risk_explanation"]
