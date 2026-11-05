
from datetime import datetime, timezone

from src.database.db import initialize_database, get_scan_status
from src.database.queries import get_scan_details
from src.services.analysis_service import AnalysisService
from src.services.enrichment_adapter import EnrichmentAdapter
from src.services.risk_scoring_adapter import RiskScoringAdapter
from src.streaming.consumer import analyze_scan_event


def main():
    initialize_database()

    scan_id = "real-risk-integration-001"

    event = {
        "event_type": "scan_request",
        "scan_id": scan_id,
        "project_name": "VulnGuard Integration Test",
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "dependencies": [
            {
                "name": "pyload-ng",
                "version": "0.5.0",
                "ecosystem": "PyPI",
            }
        ],
    }

    analysis_service = AnalysisService(
        enrichment_adapter=EnrichmentAdapter.from_intelligence_engine(),
        risk_scorer=RiskScoringAdapter(),
    )

    result = analyze_scan_event(event, analysis_service)

    print("\n--- PIPELINE RESULT ---")
    print("Scan ID:", result["scan_id"])
    print("Findings:", len(result["vulnerabilities"]))
    print("Risk assessment:", result["risk_assessment"])

    details = get_scan_details(scan_id)

    print("\n--- SQLITE VERIFICATION ---")
    print("Scan status:", get_scan_status(scan_id))

    analysis = details["analysis_result"]

    if analysis is None:
        raise RuntimeError("No analysis result was saved in SQLite.")

    print("Saved findings:", len(analysis["vulnerabilities"]))
    print("Saved risk assessments:", analysis["risk_assessment"])

    assert len(analysis["vulnerabilities"]) == 3
    assert analysis["risk_assessment"] is not None
    assert get_scan_status(scan_id) == "ANALYZED"

    print("\nSUCCESS: Real analysis and risk scoring persisted in SQLite.")


if __name__ == "__main__":
    main()
