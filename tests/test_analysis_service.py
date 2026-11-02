import pytest

from src.services.analysis_service import AnalysisService
from src.services.enrichment_adapter import (
    EnrichmentAdapter,
    EnrichmentNotConfiguredError,
)


DEPENDENCIES = [
    {"ecosystem": "PyPI", "name": "requests", "version": "2.31.0"},
]

VULNERABILITIES = [
    {"id": "CVE-2024-0001", "package": "requests"},
]


def test_analysis_service_orchestrates_enrichment_and_optional_components():
    calls = []

    def enrich(dependencies):
        calls.append(("enrichment", dependencies))
        return VULNERABILITIES

    def score(vulnerabilities):
        calls.append(("risk", vulnerabilities))
        return {"level": "high"}

    def predict(vulnerabilities):
        calls.append(("ml", vulnerabilities))
        return {"label": "exploitable"}

    service = AnalysisService(
        enrichment_adapter=EnrichmentAdapter(enrich),
        risk_scorer=score,
        ml_predictor=predict,
    )

    result = service.analyze(" scan-123 ", DEPENDENCIES)

    assert result.scan_id == "scan-123"
    assert result.vulnerabilities == VULNERABILITIES
    assert result.risk_assessment == {"level": "high"}
    assert result.ml_prediction == {"label": "exploitable"}
    assert [call[0] for call in calls] == ["enrichment", "risk", "ml"]
    assert result.to_dict()["scan_id"] == "scan-123"


def test_analysis_service_allows_unavailable_future_components():
    service = AnalysisService(EnrichmentAdapter(lambda _: VULNERABILITIES))

    result = service.analyze("scan-123", DEPENDENCIES)

    assert result.risk_assessment is None
    assert result.ml_prediction is None


def test_enrichment_adapter_reports_missing_integration():
    service = AnalysisService(EnrichmentAdapter())

    with pytest.raises(EnrichmentNotConfiguredError, match="not configured"):
        service.analyze("scan-123", DEPENDENCIES)


@pytest.mark.parametrize(
    ("scan_id", "dependencies", "message"),
    [
        ("", DEPENDENCIES, "scan_id"),
        ("scan-123", [], "At least one dependency"),
        (
            "scan-123",
            [{"ecosystem": "PyPI", "name": "requests"}],
            "version",
        ),
    ],
)
def test_analysis_service_rejects_invalid_scan_input(
    scan_id,
    dependencies,
    message,
):
    service = AnalysisService(EnrichmentAdapter(lambda _: VULNERABILITIES))

    with pytest.raises(ValueError, match=message):
        service.analyze(scan_id, dependencies)


def test_enrichment_adapter_rejects_invalid_result_shape():
    service = AnalysisService(EnrichmentAdapter(lambda _: {"id": "CVE-1"}))

    with pytest.raises(TypeError, match="must return a list"):
        service.analyze("scan-123", DEPENDENCIES)