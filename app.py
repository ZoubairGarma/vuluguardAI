
import importlib
import streamlit as st
from src.database.queries import get_scan_history, get_scan_summary
from src.utils import ui

importlib.reload(ui)


st.set_page_config(
    page_title="VulnGuard AI",
    page_icon="🛡️",
    layout="wide"
)

ui.apply_app_styles()

ui.render_page_header(
    "VulnGuard AI",
    "A clear view of dependency scan activity and processing status.",
)

st.write("")
summary = get_scan_summary()

metric_columns = st.columns(4)
metric_columns[0].metric("Total scans", summary["total"])
metric_columns[1].metric("Waiting analysis", summary["WAITING_ANALYSIS"])
metric_columns[2].metric("Completed", summary["COMPLETED"])
metric_columns[3].metric("Failed", summary["FAILED"])

st.divider()

recent_scans = get_scan_history(limit=8)
left, right = st.columns([1.7, 1], gap="large")

with left:
    st.subheader("Recent scans")
    st.caption("The latest scan requests recorded by this workspace.")

    if recent_scans:
        st.dataframe(
            [
                {
                    "Project": scan["project_name"],
                    "Dependencies": scan["dependency_count"],
                    "Status": scan["status"],
                    "Received": scan["received_at"],
                }
                for scan in recent_scans
            ],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No scans yet. Start by submitting a pinned requirements.txt file.")

with right:
    st.subheader("Scan lifecycle")
    st.caption("Current workflow foundation")
    st.markdown(
        """
        **01 · Submitted**  
        Requirements are parsed and sent to Kafka.

        **02 · Queued**  
        The consumer stores the request in SQLite.

        **03 · Analysis**  
        Vulnerability analysis is the next workflow stage.
        """
    )

st.divider()
st.caption(
    "Vulnerability findings, risk scoring, and remediation workflows are still in development. "
    "This dashboard currently reports scan intake and tracking data."
)
