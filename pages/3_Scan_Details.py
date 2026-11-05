
import importlib
import streamlit as st
from src.agents.llm_explanation import LLMExplanationAgent
from src.agents.security_test_generator import SecurityTestGenerator
from src.agents.human_approval import HumanApprovalManager
from src.agents.security_test_executor import SecurityTestExecutor
from src.database.queries import (
    get_scan_history,
    get_scan_details
)
from src.database.db import get_scan_test_plan, save_scan_test_plan
from src.utils import ui

importlib.reload(ui)


st.set_page_config(
    page_title="Scan Details | VulnGuard AI",
    page_icon="🛡️",
    layout="wide"
)

ui.apply_app_styles()
ui.render_page_header(
    "Scan details",
    "Review the request, its dependencies, and the status history recorded for this scan.",
)

st.divider()


# --------------------------------------------------
# 1. LOAD AVAILABLE SCANS
# --------------------------------------------------

scans = get_scan_history(limit=500)

if not scans:

    st.info(
        "No scans are available yet. "
        "Submit a new scan from the New Scan page."
    )

    st.stop()


# --------------------------------------------------
# 2. SELECT A SCAN
# --------------------------------------------------

scan_ids = [
    scan["scan_id"]
    for scan in scans
]


# Prepare readable labels for the selectbox
scan_labels = {
    scan["scan_id"]: (
        f"{scan['project_name']} | "
        f"{scan['scan_id'][:8]} | "
        f"{scan['status']}"
    )
    for scan in scans
}


selected_scan_id = st.selectbox(
    "Select a scan",
    options=scan_ids,
    format_func=lambda scan_id: scan_labels[scan_id]
)


# --------------------------------------------------
# 3. GET SCAN DETAILS
# --------------------------------------------------

details = get_scan_details(selected_scan_id)

if details is None:

    st.error("The selected scan could not be found.")

    st.stop()


scan = details["scan"]
dependencies = details["dependencies"]
history = details["status_history"]
event = details["event"]
analysis_result = details.get("analysis_result")


# --------------------------------------------------
# 4. SUMMARY AND DETAIL SECTIONS
# --------------------------------------------------

status = scan["status"]
status_col, dependency_col, history_col = st.columns(3)
status_col.metric("Current status", status.replace("_", " ").title())
dependency_col.metric("Dependencies", len(dependencies))
history_col.metric("Status changes", len(history))

overview_tab, dependencies_tab, analysis_tab, workflow_tab, event_tab = st.tabs(
    ["Overview", "Dependencies", "Analysis", "Workflow", "Original event"]
)

with overview_tab:
    st.subheader(scan["project_name"])
    st.caption("Scan identifier")
    st.code(scan["scan_id"], language=None)

    info_col, time_col = st.columns(2, gap="large")
    with info_col:
        st.markdown("**Current status**")
        if status == "COMPLETED":
            st.success(status.replace("_", " ").title())
        elif status == "FAILED":
            st.error(status.replace("_", " ").title())
        elif status == "REJECTED":
            st.warning(status.replace("_", " ").title())
        else:
            st.info(status.replace("_", " ").title())
    with time_col:
        st.markdown("**Submitted**")
        st.write(scan["submitted_at"])
        st.markdown("**Received**")
        st.write(scan["received_at"])
        st.markdown("**Last updated**")
        st.write(scan["updated_at"])

with dependencies_tab:
    st.subheader("Packages included in this request")
    if dependencies:
        dependency_table = [
            {
                "Package": dependency["name"],
                "Version": dependency["version"],
                "Ecosystem": dependency["ecosystem"],
            }
            for dependency in dependencies
        ]
        st.dataframe(
            dependency_table,
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No dependencies recorded for this scan.")

with analysis_tab:
    st.subheader("Vulnerability analysis")

    if analysis_result is None:
        st.info(
            "Analysis results are not available yet. "
            "The scan may still be waiting for analysis."
        )
    elif "error" in analysis_result:
        st.error(analysis_result["error"])
    else:
        findings = analysis_result.get("vulnerabilities", [])
        unresolved = analysis_result.get("unresolved", [])
        st.caption(f"Analyzed at: {analysis_result.get('analyzed_at', 'Unknown')}")

        result_col, unresolved_col = st.columns(2)
        result_col.metric("Affected CVEs", len(findings))
        unresolved_col.metric("Unresolved entries", len(unresolved))

        if findings:
            for index, finding in enumerate(findings, start=1):
                risk = finding.get("risk", {})
                cve_id = finding.get("cve_id", "Unknown CVE")
                title = (
                    f"{index}. {cve_id} · "
                    f"{risk.get('level', 'UNKNOWN')} · "
                    f"{risk.get('score', 'N/A')}/100"
                )

                with st.expander(title):
                    st.write(finding.get("description") or "No description available.")
                    st.markdown("**Risk assessment**")
                    st.json(risk)
                    explanation_key = (
                        f"ai_explanation_{selected_scan_id}_{cve_id}"
                    )

                    if st.button(
                        "Explain with AI",
                        key=f"explain_{selected_scan_id}_{cve_id}",
                    ):
                        try:
                            with st.spinner("Generating explanation..."):
                                result = LLMExplanationAgent().explain(finding)

                            st.session_state[explanation_key] = result
                        except Exception as error:
                            st.error(f"Could not generate the explanation: {error}")

                    if explanation_key in st.session_state:
                        explanation_result = st.session_state[explanation_key]
                        st.markdown("**AI explanation**")
                        warnings = explanation_result.get("validation_warnings", [])
                        if warnings:
                            st.warning(
                                "The explanation failed fact validation and is withheld. "
                                "Use the deterministic findings below as the source of truth."
                            )
                            for warning in warnings:
                                st.write(f"- {warning}")
                            with st.expander("View untrusted AI output"):
                                st.write(explanation_result["explanation"])
                        else:
                            st.write(explanation_result["explanation"])
                            st.caption(
                                "AI-generated text can still be inaccurate. "
                                "The deterministic findings remain the source of truth."
                            )

                    packages = finding.get("affected_packages", [])
                    if packages:
                        st.markdown("**Affected package versions**")
                        st.dataframe(
                            [
                                {
                                    "Package": package.get("package_name"),
                                    "Ecosystem": package.get("ecosystem"),
                                    "Installed version": package.get("installed_version"),
                                    "Version status": package.get("version_status"),
                                    "Fixed versions": ", ".join(package.get("fixed_versions", [])),
                                }
                                for package in packages
                            ],
                            use_container_width=True,
                            hide_index=True,
                        )

                    for explanation in finding.get("analysis", []):
                        st.write(f"• {explanation}")

                    recommendations = finding.get("recommendations", [])
                    if recommendations:
                        st.markdown("**Recommendations**")
                        for recommendation in recommendations:
                            st.write(f"- {recommendation}")

                    st.markdown("**Optional security test plan**")
                    st.caption(
                        "This rule-based plan is generated from verified analysis data. "
                        "It is not executed unless you approve it and explicitly run it."
                    )

                    plan_key = f"test_plan_{selected_scan_id}_{cve_id}"
                    test_plan = st.session_state.get(plan_key)
                    if test_plan is None:
                        test_plan = get_scan_test_plan(selected_scan_id, cve_id)
                        if test_plan is not None:
                            st.session_state[plan_key] = test_plan

                    if test_plan and test_plan.get("execution_status") == "RUNNING":
                        test_plan["execution_status"] = "FAILED"
                        test_plan["execution_error"] = (
                            "The application stopped while this check was running. "
                            "Review the plan before generating a new one."
                        )
                        for test in test_plan.get("tests", []):
                            if test.get("execution_status") in {"NOT_STARTED", "RUNNING"}:
                                test["execution_status"] = "FAILED"
                                test["execution_result"] = {
                                    "execution_status": "FAILED",
                                    "message": test_plan["execution_error"],
                                }
                        save_scan_test_plan(selected_scan_id, cve_id, test_plan)
                        st.session_state[plan_key] = test_plan

                    if st.button(
                        "Generate test plan",
                        key=f"generate_plan_{selected_scan_id}_{cve_id}",
                    ):
                        try:
                            st.session_state[plan_key] = SecurityTestGenerator().generate(
                                finding
                            )
                            save_scan_test_plan(
                                selected_scan_id,
                                cve_id,
                                st.session_state[plan_key],
                            )
                            st.rerun()
                        except Exception as error:
                            st.error(f"Could not generate the test plan: {error}")

                    test_plan = st.session_state.get(plan_key)
                    if test_plan:
                        st.write(f"Approval status: {test_plan['approval_status']}")
                        st.write(f"Execution status: {test_plan['execution_status']}")
                        if test_plan["approval_status"] == "REJECTED":
                            st.warning("The plan was rejected and cannot be executed.")
                        elif test_plan["approval_status"] == "APPROVED":
                            if test_plan["execution_status"] == "NOT_STARTED":
                                st.success(
                                    f"Approved by {test_plan['approval']['reviewer']}. "
                                    "Execution has not started."
                                )
                            elif test_plan["execution_status"] == "RUNNING":
                                st.info("The approved check is running.")
                            elif test_plan["execution_status"] == "COMPLETED":
                                st.success("The approved check completed.")
                            elif test_plan["execution_status"] == "FAILED":
                                st.error(
                                    "The approved check failed: "
                                    + test_plan.get("execution_error", "See execution results below.")
                                )

                        if not test_plan.get("tests"):
                            st.info("No package-version checks could be generated for this finding.")
                        else:
                            for test in test_plan["tests"]:
                                with st.expander(
                                    f"{test['title']} — {test['target']['package_name']}"
                                ):
                                    st.write(test["objective"])
                                    st.write(
                                        "Target: "
                                        f"{test['target'].get('package_name')} "
                                        f"({test['target'].get('ecosystem')})"
                                    )
                                    st.write("Steps:")
                                    for step in test["steps"]:
                                        st.write(f"- {step}")
                                    st.write(f"Expected result: {test['expected_result']}")

                            if test_plan["approval_status"] == "PENDING_APPROVAL":
                                reviewer = st.text_input(
                                    "Reviewer name",
                                    key=f"reviewer_{selected_scan_id}_{cve_id}",
                                )
                                rejection_reason = st.text_input(
                                    "Reason for rejection (required to reject)",
                                    key=f"reject_reason_{selected_scan_id}_{cve_id}",
                                )
                                approve_col, reject_col = st.columns(2)

                                if approve_col.button(
                                    "Approve plan",
                                    key=f"approve_plan_{selected_scan_id}_{cve_id}",
                                ):
                                    if not reviewer.strip():
                                        st.error("Enter a reviewer name before approving.")
                                    else:
                                        try:
                                            st.session_state[plan_key] = (
                                                HumanApprovalManager().approve(
                                                    test_plan,
                                                    reviewer=reviewer,
                                                )
                                            )
                                            save_scan_test_plan(
                                                selected_scan_id,
                                                cve_id,
                                                st.session_state[plan_key],
                                            )
                                            st.rerun()
                                        except Exception as error:
                                            st.error(f"Could not approve the plan: {error}")

                                if reject_col.button(
                                    "Reject plan",
                                    key=f"reject_plan_{selected_scan_id}_{cve_id}",
                                ):
                                    if not reviewer.strip() or not rejection_reason.strip():
                                        st.error(
                                            "Enter both a reviewer name and a rejection reason."
                                        )
                                    else:
                                        try:
                                            st.session_state[plan_key] = (
                                                HumanApprovalManager().reject(
                                                    test_plan,
                                                    reviewer=reviewer,
                                                    reason=rejection_reason,
                                                )
                                            )
                                            save_scan_test_plan(
                                                selected_scan_id,
                                                cve_id,
                                                st.session_state[plan_key],
                                            )
                                            st.rerun()
                                        except Exception as error:
                                            st.error(f"Could not reject the plan: {error}")

                            elif test_plan["approval_status"] == "APPROVED":
                                st.warning(
                                    "This check compares the dependency version declared in the scan "
                                    "with OSV data. It does not inspect the project's runtime environment."
                                )
                                if test_plan["execution_status"] == "NOT_STARTED" and st.button(
                                    "Run approved package-version check",
                                    key=f"execute_plan_{selected_scan_id}_{cve_id}",
                                ):
                                    try:
                                        with st.spinner("Running approved check..."):
                                            st.session_state[plan_key] = (
                                                SecurityTestExecutor().execute(
                                                    test_plan,
                                                    on_status_change=lambda updated_plan: save_scan_test_plan(
                                                        selected_scan_id,
                                                        cve_id,
                                                        updated_plan,
                                                    ),
                                                )
                                            )
                                            save_scan_test_plan(
                                                selected_scan_id,
                                                cve_id,
                                                st.session_state[plan_key],
                                            )
                                        st.rerun()
                                    except Exception as error:
                                        st.error(f"Could not execute the approved check: {error}")

                            if test_plan.get("execution_results"):
                                st.markdown("**Execution results**")
                                st.dataframe(
                                    test_plan["execution_results"],
                                    use_container_width=True,
                                    hide_index=True,
                                )
        else:
            st.success("No affected vulnerabilities were confirmed for this scan.")

        if unresolved:
            with st.expander("Review unresolved entries"):
                st.dataframe(unresolved, use_container_width=True, hide_index=True)

with workflow_tab:
    st.subheader("Status timeline")
    if history:
        for index, record in enumerate(history):
            st.markdown(f"**{index + 1:02d} · {record['status'].replace('_', ' ').title()}**")
            st.caption(record["changed_at"])
            if record["details"]:
                st.write(record["details"])
            if index < len(history) - 1:
                st.divider()
    else:
        st.info("No status history available.")

with event_tab:
    st.caption("The original request message received from Kafka.")
    st.json(event)

st.caption("Scan information is retrieved from the local SQLite database.")
