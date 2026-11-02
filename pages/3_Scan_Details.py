
import streamlit as st

from src.database.queries import (
    get_scan_history,
    get_scan_details
)


st.set_page_config(
    page_title="Scan Details | VulnGuard AI",
    page_icon="🛡️",
    layout="wide"
)

st.title("Scan Details")

st.markdown(
    """
    View detailed information about a dependency scan,
    including its dependencies, current status,
    workflow history and original Kafka event.
    """
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
# 4. GENERAL INFORMATION
# --------------------------------------------------

st.subheader("General Information")

col1, col2 = st.columns(2)

with col1:

    st.markdown("**Project Name**")
    st.write(scan["project_name"])

    st.markdown("**Scan ID**")
    st.code(scan["scan_id"])

    st.markdown("**Submitted At**")
    st.write(scan["submitted_at"])


with col2:

    st.markdown("**Current Status**")

    status = scan["status"]

    if status == "COMPLETED":
        st.success(status)

    elif status == "FAILED":
        st.error(status)

    elif status == "REJECTED":
        st.warning(status)

    else:
        st.info(status)

    st.markdown("**Received At**")
    st.write(scan["received_at"])

    st.markdown("**Last Updated**")
    st.write(scan["updated_at"])


st.divider()


# --------------------------------------------------
# 5. SCAN METRICS
# --------------------------------------------------

st.subheader("Scan Metrics")

col1, col2 = st.columns(2)

col1.metric(
    "Total Dependencies",
    len(dependencies)
)

col2.metric(
    "Recorded Status Changes",
    len(history)
)


st.divider()


# --------------------------------------------------
# 6. DEPENDENCY DETAILS
# --------------------------------------------------

st.subheader("Dependencies")

if dependencies:

    dependency_table = [
        {
            "Package": dependency["name"],
            "Version": dependency["version"],
            "Ecosystem": dependency["ecosystem"]
        }
        for dependency in dependencies
    ]

    st.dataframe(
        dependency_table,
        use_container_width=True,
        hide_index=True
    )

else:

    st.info("No dependencies recorded for this scan.")


st.divider()


# --------------------------------------------------
# 7. STATUS HISTORY
# --------------------------------------------------

st.subheader("Workflow History")

if history:

    for index, record in enumerate(history):

        st.markdown(
            f"**{index + 1}. {record['status']}**"
        )

        st.caption(record["changed_at"])

        if record["details"]:
            st.write(record["details"])

        if index < len(history) - 1:
            st.divider()

else:

    st.info("No status history available.")


st.divider()


# --------------------------------------------------
# 8. ORIGINAL KAFKA EVENT
# --------------------------------------------------

st.subheader("Original Kafka Event")

with st.expander("View original JSON message"):

    st.json(event)


st.caption(
    "The information displayed on this page "
    "is retrieved from the local SQLite database."
)
