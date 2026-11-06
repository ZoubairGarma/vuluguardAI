from copy import deepcopy
import json

from src.agents.security_test_generator import SecurityTestGenerator
from src.agents.security_workflow_graph import run_security_workflow


class FakeReportAgent:
    def __init__(self, validation_warnings=None):
        self.validation_warnings = validation_warnings or []

    def run(self, finding):
        plan = SecurityTestGenerator().generate(finding)
        return {
            "explanation": {
                "cve_id": finding["cve_id"],
                "explanation": "A grounded test explanation.",
                "verified_facts": {
                    "cve_id": finding["cve_id"],
                    "risk": finding.get("risk", {}),
                    "affected_packages": finding["affected_packages"],
                    "recommendations": finding.get("recommendations", []),
                },
                "validation_warnings": self.validation_warnings,
            },
            "test_plan": plan,
        }


class FakeExecutionAgent:
    def __init__(self):
        self.calls = 0

    def run(self, approved_plan, on_status_change=None):
        self.calls += 1
        assert approved_plan["approval_status"] == "APPROVED"
        running = deepcopy(approved_plan)
        running["execution_status"] = "RUNNING"
        if on_status_change:
            on_status_change(running)

        result_plan = deepcopy(running)
        execution_results = []
        for test in result_plan["tests"]:
            target = test["target"]
            result = {
                "test_id": test["test_id"],
                "package_name": target["package_name"],
                "installed_version": target["installed_version"],
                "version_source": "SCAN_DECLARED_DEPENDENCY",
                "execution_status": "COMPLETED",
                "version_status": "AFFECTED",
                "checks": [
                    {
                        "check_id": check_id,
                        "status": "PASSED",
                        "passed": True,
                        "detail": "Test boundary returned success.",
                    }
                    for check_id in test.get("checks", [])
                ],
                "message": "Declared version matches the affected range.",
            }
            test["execution_status"] = "COMPLETED"
            test["execution_result"] = result
            execution_results.append(result)

        result_plan["execution_results"] = execution_results
        result_plan["execution_status"] = "COMPLETED"
        if on_status_change:
            on_status_change(result_plan)
        return result_plan


def sample_finding():
    return {
        "cve_id": "CVE-2025-12345",
        "risk": {"score": 75, "level": "HIGH", "is_kev": False},
        "description": "Sample finding.",
        "affected_packages": [
            {
                "package_name": "sample-package",
                "ecosystem": "PyPI",
                "installed_version": "1.0.0",
                "version_status": "AFFECTED",
                "affected_ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
                    }
                ],
                "fixed_versions": ["2.0.0"],
                "osv_ids": ["GHSA-example"],
            }
        ],
        "recommendations": ["Upgrade to the supplied fixed version."],
    }


def test_graph_stops_for_human_approval_without_execution():
    executor = FakeExecutionAgent()

    result = run_security_workflow(
        {"scan_id": "scan-1", "finding": sample_finding()},
        report_agent=FakeReportAgent(),
        execution_agent=executor,
    )

    assert result["workflow_status"] == "WAITING_APPROVAL"
    assert result["test_plan"]["approval_status"] == "PENDING_APPROVAL"
    assert result["test_plan"]["execution_status"] == "NOT_STARTED"
    assert result["final_report"]["workflow_status"] == "WAITING_APPROVAL"
    assert executor.calls == 0


def test_approval_runs_second_agent_then_verifies_results():
    executor = FakeExecutionAgent()
    observed_states = []

    prepared = run_security_workflow(
        {"scan_id": "scan-2", "finding": sample_finding()},
        report_agent=FakeReportAgent(),
        execution_agent=executor,
    )
    approved = run_security_workflow(
        {
            "scan_id": "scan-2",
            "finding": sample_finding(),
            "explanation": prepared["explanation"],
            "test_plan": prepared["test_plan"],
            "approval_decision": "APPROVE",
            "reviewer": "reviewer-1",
        },
        report_agent=FakeReportAgent(),
        execution_agent=executor,
        on_status_change=lambda plan: observed_states.append(
            plan["execution_status"]
        ),
    )

    assert approved["test_plan"]["approval_status"] == "APPROVED"
    assert approved["test_plan"]["execution_status"] == "COMPLETED"
    assert approved["workflow_status"] == "COMPLETED"
    assert approved["final_report"]["verification"]["passed"] is True
    assert approved["final_report"]["approval"]["reviewer"] == "reviewer-1"
    assert observed_states == ["RUNNING", "COMPLETED"]
    assert executor.calls == 1


def test_rejection_never_calls_execution_agent():
    executor = FakeExecutionAgent()
    prepared = run_security_workflow(
        {"scan_id": "scan-3", "finding": sample_finding()},
        report_agent=FakeReportAgent(),
        execution_agent=executor,
    )

    rejected = run_security_workflow(
        {
            "scan_id": "scan-3",
            "finding": sample_finding(),
            "explanation": prepared["explanation"],
            "test_plan": prepared["test_plan"],
            "approval_decision": "REJECT",
            "reviewer": "reviewer-2",
            "rejection_reason": "Plan needs revision.",
        },
        report_agent=FakeReportAgent(),
        execution_agent=executor,
    )

    assert rejected["workflow_status"] == "REJECTED"
    assert rejected["test_plan"]["approval_status"] == "REJECTED"
    assert rejected["test_plan"]["execution_status"] == "NOT_STARTED"
    assert rejected["final_report"]["workflow_status"] == "REJECTED"
    assert executor.calls == 0


def test_final_report_withholds_ai_explanation_with_fact_warnings():
    result = run_security_workflow(
        {"scan_id": "scan-4", "finding": sample_finding()},
        report_agent=FakeReportAgent(["Risk score contradiction."]),
        execution_agent=FakeExecutionAgent(),
    )

    assert result["final_report"]["ai_explanation"] is None
    assert result["final_report"]["ai_output_withheld"] is True
    assert result["final_report"]["ai_validation_warnings"] == [
        "Risk score contradiction."
    ]


def test_final_report_can_be_attached_to_plan_and_serialized():
    result = run_security_workflow(
        {"scan_id": "scan-5", "finding": sample_finding()},
        report_agent=FakeReportAgent(),
        execution_agent=FakeExecutionAgent(),
    )
    plan = result["test_plan"]
    plan["final_report"] = result["final_report"]

    serialized = json.dumps(plan)

    assert '"workflow_status": "WAITING_APPROVAL"' in serialized
