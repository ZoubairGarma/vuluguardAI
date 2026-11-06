"""Local application-path integration from scan event through verification."""

from src.agents.approved_test_agent import ApprovedTestAgent
from src.agents.security_test_executor import SecurityTestExecutor
from src.agents.security_workflow_graph import run_security_workflow
from src.database.queries import get_scan_details
from src.services.analysis_service import AnalysisService
from src.services.enrichment_adapter import EnrichmentAdapter
from src.streaming.consumer import analyze_scan_event
from src.streaming.producer import build_scan_event


class StubExplainer:
    def explain(self, finding):
        return {
            "cve_id": finding["cve_id"],
            "explanation": "The scanned version is in the supplied affected range.",
            "verified_facts": {
                "cve_id": finding["cve_id"],
                "risk": finding.get("risk", {}),
                "affected_packages": finding["affected_packages"],
                "recommendations": finding.get("recommendations", []),
            },
            "validation_warnings": [],
        }


class MetadataVerifierBoundary:
    """Replace Docker only; the real executor still evaluates all checks."""

    def verify(self, package_name, version):
        return {
            "installed_version": version,
            "requested_version": version,
            "version_source": "DOCKER_ISOLATED_WHEEL_INSTALL",
            "verification": "WHEEL_INSTALLED_METADATA_ONLY",
            "container_network_access": False,
            "project_code_executed": False,
            "package_code_executed": False,
        }


def test_local_scan_to_approved_declarative_verification(test_database):
    finding = {
        "cve_id": "CVE-2025-12345",
        "description": "A sample package vulnerability.",
        "risk": {"score": 65, "level": "HIGH", "is_kev": False},
        "affected_packages": [{
            "package_name": "requests",
            "ecosystem": "PyPI",
            "installed_version": "2.31.0",
            "version_status": "AFFECTED",
            "affected_ranges": [{
                "type": "ECOSYSTEM",
                "events": [{"introduced": "0"}, {"fixed": "3.0.0"}],
            }],
            "fixed_versions": ["3.0.0"],
            "osv_ids": ["GHSA-example"],
        }],
        "recommendations": ["Upgrade to 3.0.0 or later."],
    }
    event = build_scan_event(
        "local-e2e-project",
        [{"ecosystem": "PyPI", "name": "requests", "version": "2.31.0"}],
    )
    service = AnalysisService(
        enrichment_adapter=EnrichmentAdapter(lambda _: [finding]),
        llm_explainer=StubExplainer(),
    )

    analysis = analyze_scan_event(event, service)

    assert analysis["schema_version"] == "1.0"
    assert test_database.get_scan_status(event["scan_id"]) == "ANALYZED"
    pending_plan = test_database.get_scan_test_plan(
        event["scan_id"], finding["cve_id"]
    )
    assert pending_plan["approval_status"] == "PENDING_APPROVAL"
    assert pending_plan["execution_status"] == "NOT_STARTED"

    test_database.update_scan_status(event["scan_id"], "WAITING_APPROVAL")
    approval = run_security_workflow(
        {
            "scan_id": event["scan_id"],
            "finding": finding,
            "explanation": analysis["llm_explanations"][0],
            "test_plan": pending_plan,
            "approval_decision": "APPROVE",
            "reviewer": "local-reviewer",
            "stop_after_approval": True,
        }
    )
    approved_plan = approval["test_plan"]
    assert approved_plan["approval"]["reviewer"] == "local-reviewer"
    test_database.save_scan_test_plan(
        event["scan_id"], finding["cve_id"], approved_plan
    )
    test_database.update_scan_status(event["scan_id"], "APPROVED")

    test_database.update_scan_status(event["scan_id"], "TESTING")
    completed = run_security_workflow(
        {
            "scan_id": event["scan_id"],
            "finding": finding,
            "explanation": analysis["llm_explanations"][0],
            "test_plan": approved_plan,
        },
        execution_agent=ApprovedTestAgent(
            SecurityTestExecutor(isolated_verifier=MetadataVerifierBoundary())
        ),
    )

    final_plan = completed["test_plan"]
    test_database.save_scan_test_plan(
        event["scan_id"], finding["cve_id"], final_plan
    )
    test_database.update_scan_status(event["scan_id"], "COMPLETED")
    analysis["security_test_plans"][0] = final_plan
    analysis["final_reports"][0] = completed["final_report"]
    test_database.save_scan_analysis_result(event["scan_id"], analysis)

    stored = get_scan_details(event["scan_id"])
    assert test_database.get_scan_status(event["scan_id"]) == "COMPLETED"
    assert final_plan["execution_status"] == "COMPLETED"
    assert completed["final_report"]["verification"]["passed"] is True
    assert [item["status"] for item in final_plan["execution_results"][0]["checks"]] == [
        "PASSED",
        "PASSED",
        "PASSED",
    ]
    assert stored["analysis_result"]["final_reports"][0]["workflow_status"] == "COMPLETED"
