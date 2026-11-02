
import importlib

import streamlit as st

from src.database.queries import (
    get_recent_failures,
    get_scan_history,
    get_scan_summary,
    get_system_health,
)
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

st.subheader("System Health")
st.caption("Live status of the local processing pipeline.")
health = get_system_health()
health_columns = st.columns(3)

health_style = {
    "Healthy": "healthy",
    "Listening": "healthy",
    "Waiting for DB": "warning",
    "Unavailable": "danger",
    "Offline": "danger",
    "Not monitored": "neutral",
}

for column, label in zip(health_columns, ["Kafka", "SQLite", "Consumer"]):
    value = health[label.lower()]
    tone = health_style.get(value, "neutral")
    column.markdown(
        f"""
        <div class="vg-panel">
            <div class="vg-panel-title">{label}</div>
            <div class="vg-health-value">{value}</div>
            <div class="vg-status-pill vg-pill-{tone}">{value}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

st.divider()

st.subheader("Scan Statistics")
st.caption("Breakdown of scans by status.")
status_counts = {
    key: value
    for key, value in summary.items()
    if key != "total"
}
status_data = {
    "Status": list(status_counts.keys()),
    "Count": list(status_counts.values()),
}
st.bar_chart(status_data, x="Status", y="Count")

st.divider()

recent_scans = get_scan_history(limit=8)
errors = get_recent_failures(limit=5)
left, right = st.columns([1.7, 1], gap="large")

with left:
    st.subheader("Recent Activity")
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
    st.subheader("Errors")
    st.caption("Recent failed or rejected events.")

    if errors:
        errors_display = [
            {
                "Status": item["status"],
                "Changed at": item["changed_at"],
                "Detail": item["details"] or "No details available",
            }
            for item in errors
        ]
        st.dataframe(
            errors_display,
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.success("No recent errors detected.")

st.divider()
st.caption(
    "Vulnerability findings, risk scoring, and remediation workflows are still in development. "
    "This dashboard currently reports scan intake, health, and lifecycle monitoring data."
)
