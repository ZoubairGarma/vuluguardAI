import pytest

from src.database.queries import get_scan_details
from src.streaming.consumer import analyze_scan_event


class FakeAnalysisResult:
    def __init__(self, scan_id):
        self.scan_id = scan_id

    def to_dict(self):
        return {
            "scan_id": self.scan_id,
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2025-1234",
                    "risk": {"score": 80, "level": "HIGH"},
                }
            ],
            "risk_assessment": None,
            "ml_prediction": None,
            "unresolved": [],
        }


class FakeAnalysisService:
    def analyze(self, scan_id, dependencies):
        assert dependencies
        return FakeAnalysisResult(scan_id)


class FailingAnalysisService:
    def analyze(self, scan_id, dependencies):
        raise RuntimeError("sample analysis failure")


def test_consumer_persists_findings_and_marks_scan_analyzed(
    test_database,
    sample_event,
):
    result = analyze_scan_event(sample_event, FakeAnalysisService())

    assert result["scan_id"] == sample_event["scan_id"]
    assert test_database.get_scan_status(sample_event["scan_id"]) == "ANALYZED"

    details = get_scan_details(sample_event["scan_id"])
    assert details["analysis_result"]["vulnerabilities"][0]["cve_id"] == "CVE-2025-1234"
    assert [entry["status"] for entry in details["status_history"]] == [
        "RECEIVED",
        "WAITING_ANALYSIS",
        "ANALYZED",
    ]


def test_consumer_marks_analysis_failure_as_failed(
    test_database,
    sample_event,
):
    with pytest.raises(RuntimeError, match="sample analysis failure"):
        analyze_scan_event(sample_event, FailingAnalysisService())

    assert test_database.get_scan_status(sample_event["scan_id"]) == "FAILED"
    details = get_scan_details(sample_event["scan_id"])
    assert details["analysis_result"] is None
    assert details["status_history"][-1]["status"] == "FAILED"


def test_consumer_does_not_repeat_analyzed_scan(
    test_database,
    sample_event,
):
    analyze_scan_event(sample_event, FakeAnalysisService())

    class UnexpectedAnalysisService:
        def analyze(self, scan_id, dependencies):
            pytest.fail("An already analyzed scan must not run twice.")

    skipped = analyze_scan_event(sample_event, UnexpectedAnalysisService())

    assert skipped["status"] == "ANALYZED"
    assert skipped["skipped"] is True