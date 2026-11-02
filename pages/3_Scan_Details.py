
import importlib
import streamlit as st

from src.database.queries import (
    get_scan_history,
    get_scan_details
)
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


# --------------------------------------------------
# 4. SUMMARY AND DETAIL SECTIONS
# --------------------------------------------------

status = scan["status"]
status_col, dependency_col, history_col = st.columns(3)
status_col.metric("Current status", status.replace("_", " ").title())
dependency_col.metric("Dependencies", len(dependencies))
history_col.metric("Status changes", len(history))

overview_tab, dependencies_tab, workflow_tab, event_tab = st.tabs(
    ["Overview", "Dependencies", "Workflow", "Original event"]
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
