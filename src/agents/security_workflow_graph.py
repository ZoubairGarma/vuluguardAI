"""LangGraph orchestration for report, human review, and approved checks."""

from collections.abc import Callable
from copy import deepcopy
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph
from packaging.version import InvalidVersion, Version

from src.agents.approved_test_agent import ApprovedTestAgent
from src.agents.human_approval import HumanApprovalManager
from src.agents.report_and_plan_agent import ReportAndPlanAgent


class SecurityWorkflowState(TypedDict, total=False):
    scan_id: str
    finding: dict
    explanation: dict
    test_plan: dict
    approval_decision: str | None
    stop_after_approval: bool
    reviewer: str | None
    rejection_reason: str | None
    workflow_status: str
    verification: dict
    final_report: dict


def _build_final_report(state: SecurityWorkflowState) -> dict:
    finding = state.get("finding", {})
    explanation = state.get("explanation", {})
    plan = state.get("test_plan", {})
    verification = state.get("verification")
    approval = plan.get("approval", {}) if isinstance(plan, dict) else {}
    validation_warnings = explanation.get("validation_warnings", [])
    plan_summary = {
        "cve_id": plan.get("cve_id"),
        "approval_status": plan.get("approval_status"),
        "execution_status": plan.get("execution_status"),
        "approval": deepcopy(approval),
        "tests": deepcopy(plan.get("tests", [])),
    }

    return {
        "scan_id": state.get("scan_id"),
        "cve_id": finding.get("cve_id"),
        "workflow_status": state.get("workflow_status", "WAITING_APPROVAL"),
        "verified_facts": explanation.get("verified_facts", {
            "cve_id": finding.get("cve_id"),
            "risk": finding.get("risk", {}),
            "affected_packages": finding.get("affected_packages", []),
            "recommendations": finding.get("recommendations", []),
        }),
        "ai_explanation": (
            None if validation_warnings else explanation.get("explanation")
        ),
        "ai_output_withheld": bool(validation_warnings),
        "ai_validation_warnings": validation_warnings,
        "approval": approval,
        "test_plan": plan_summary,
        "execution_results": plan.get("execution_results", []),
        "verification": verification,
    }


def build_security_workflow_graph(
    report_agent: Any | None = None,
    approval_manager: Any | None = None,
    execution_agent: Any | None = None,
    on_status_change: Callable[[dict], None] | None = None,
):
    """Compile a graph that stops for approval and never bypasses the gate."""

    report_agent = report_agent or ReportAndPlanAgent()
    approval_manager = approval_manager or HumanApprovalManager()
    execution_agent = execution_agent or ApprovedTestAgent()

    def prepare_report_and_plan(state: SecurityWorkflowState) -> dict:
        if state.get("explanation") and state.get("test_plan"):
            return {}

        prepared = report_agent.run(state["finding"])
        return {
            "explanation": prepared["explanation"],
            "test_plan": prepared["test_plan"],
        }

    def process_human_decision(state: SecurityWorkflowState) -> dict:
        plan = state.get("test_plan")
        if not isinstance(plan, dict):
            raise ValueError("A test plan is required before human review.")

        decision = (state.get("approval_decision") or "").strip().upper()
        if not decision:
            if plan.get("approval_status") == "PENDING_APPROVAL":
                return {"workflow_status": "WAITING_APPROVAL"}
            return {"workflow_status": plan.get("approval_status", "FAILED")}

        reviewer = state.get("reviewer") or ""
        if decision in {"APPROVE", "APPROVED", "YES"}:
            approved = approval_manager.approve(plan, reviewer=reviewer)
            return {
                "test_plan": approved,
                "workflow_status": "APPROVED",
            }
        if decision in {"REJECT", "REJECTED", "NO"}:
            rejected = approval_manager.reject(
                plan,
                reviewer=reviewer,
                reason=state.get("rejection_reason") or "",
            )
            return {
                "test_plan": rejected,
                "workflow_status": "REJECTED",
            }

        raise ValueError("approval_decision must be APPROVE or REJECT.")

    def route_after_review(state: SecurityWorkflowState) -> str:
        plan = state.get("test_plan", {})
        if state.get("stop_after_approval") and state.get("approval_decision"):
            return "report"
        if plan.get("approval_status") == "APPROVED":
            if plan.get("execution_status") == "NOT_STARTED":
                return "execute"
            if plan.get("execution_status") in {"COMPLETED", "FAILED"}:
                return "verify"
        return "report"

    def execute_approved_checks(state: SecurityWorkflowState) -> dict:
        plan = execution_agent.run(
            state["test_plan"],
            on_status_change=on_status_change,
        )
        return {"test_plan": plan}

    def verify_execution(state: SecurityWorkflowState) -> dict:
        plan = state.get("test_plan", {})
        tests = plan.get("tests", [])
        results = plan.get("execution_results", [])
        expected_ids = {test.get("test_id") for test in tests}
        result_ids = {result.get("test_id") for result in results}
        errors = []

        if plan.get("approval_status") != "APPROVED":
            errors.append("Execution plan is not approved.")
        if not expected_ids or expected_ids != result_ids:
            errors.append("Execution results do not match every planned test.")

        for test, result in zip(tests, results):
            target = test.get("target", {})
            if result.get("package_name") != target.get("package_name"):
                errors.append(f"Target mismatch for {test.get('test_id')}.")
            version_source = result.get("version_source")
            if version_source == "SCAN_DECLARED_DEPENDENCY":
                if result.get("installed_version") != target.get("installed_version"):
                    errors.append(f"Declared version mismatch for {test.get('test_id')}.")
            elif version_source == "DOCKER_ISOLATED_WHEEL_INSTALL":
                try:
                    matches_pin = Version(result.get("installed_version")) == Version(
                        target.get("installed_version")
                    )
                except (InvalidVersion, TypeError):
                    matches_pin = False
                if not matches_pin:
                    errors.append(f"Container metadata does not match the pin for {test.get('test_id')}.")
            if version_source == "NOT_VERIFIED":
                if result.get("execution_status") == "COMPLETED":
                    errors.append(f"Version source is unverified for {test.get('test_id')}.")
            elif version_source not in {
                "SCAN_DECLARED_DEPENDENCY",
                "DOCKER_ISOLATED_WHEEL_INSTALL",
            }:
                errors.append(f"Unexpected version source for {test.get('test_id')}.")
            if result.get("execution_status") != "COMPLETED":
                errors.append(f"Check did not complete for {test.get('test_id')}.")
            declared_checks = test.get("checks", [])
            if declared_checks:
                result_checks = result.get("checks", [])
                if not isinstance(result_checks, list):
                    result_checks = []
                by_id = {
                    item.get("check_id"): item
                    for item in result_checks
                    if isinstance(item, dict)
                }
                if (
                    len(result_checks) != len(declared_checks)
                    or set(by_id) != set(declared_checks)
                ):
                    errors.append(
                        f"Declarative check results do not match the plan for {test.get('test_id')}."
                    )
                for check_id in declared_checks:
                    check_result = by_id.get(check_id, {})
                    if (
                        check_result.get("status") != "PASSED"
                        or check_result.get("passed") is not True
                    ):
                        errors.append(
                            f"Declarative check {check_id} did not pass for {test.get('test_id')}."
                        )

        passed = not errors and plan.get("execution_status") == "COMPLETED"
        sources = {
            result.get("version_source")
            for result in results
            if isinstance(result, dict)
        }
        if plan.get("execution_status") != "COMPLETED":
            note = (
                "One or more verification steps did not complete. Review each test's "
                "execution error before relying on its version classification."
            )
        elif sources == {"DOCKER_ISOLATED_WHEEL_INSTALL"}:
            note = (
                "The exact pinned binary wheel was installed from a read-only local mount "
                "in a network-disabled container. Distribution metadata was inspected and "
                "the supplied OSV ranges were checked. Package and project code were not run."
            )
        else:
            note = (
                "The scan-declared version was compared with supplied OSV ranges. "
                "No package code was imported or run."
            )
        return {
            "verification": {
                "passed": passed,
                "checked_test_count": len(results),
                "errors": errors,
                "note": note,
            },
            "workflow_status": "COMPLETED" if passed else "FAILED",
        }

    def finalize_report(state: SecurityWorkflowState) -> dict:
        return {"final_report": _build_final_report(state)}

    graph = StateGraph(SecurityWorkflowState)
    graph.add_node("prepare_report_and_plan", prepare_report_and_plan)
    graph.add_node("human_approval_gate", process_human_decision)
    graph.add_node("execute_approved_checks", execute_approved_checks)
    graph.add_node("verify_results", verify_execution)
    graph.add_node("final_report", finalize_report)

    graph.add_edge(START, "prepare_report_and_plan")
    graph.add_edge("prepare_report_and_plan", "human_approval_gate")
    graph.add_conditional_edges(
        "human_approval_gate",
        route_after_review,
        {
            "execute": "execute_approved_checks",
            "verify": "verify_results",
            "report": "final_report",
        },
    )
    graph.add_edge("execute_approved_checks", "verify_results")
    graph.add_edge("verify_results", "final_report")
    graph.add_edge("final_report", END)

    return graph.compile()


def run_security_workflow(
    state: SecurityWorkflowState,
    *,
    report_agent: Any | None = None,
    approval_manager: Any | None = None,
    execution_agent: Any | None = None,
    on_status_change: Callable[[dict], None] | None = None,
) -> SecurityWorkflowState:
    """Run or resume workflow state; caller persists plans and report data."""

    if not isinstance(state, dict) or not isinstance(state.get("finding"), dict):
        raise ValueError("Workflow state must include a vulnerability finding.")
    if not state["finding"].get("cve_id"):
        raise ValueError("Workflow finding must include a CVE ID.")

    workflow = build_security_workflow_graph(
        report_agent=report_agent,
        approval_manager=approval_manager,
        execution_agent=execution_agent,
        on_status_change=on_status_change,
    )
    return workflow.invoke(state)
