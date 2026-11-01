
import streamlit as st


st.set_page_config(
    page_title="VulnGuard AI",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ VulnGuard AI")

st.subheader(
    "Real-Time Dependency Risk Intelligence"
)

st.markdown(
    """
    Welcome to VulnGuard AI.

    Our platform aims to:

    - Monitor open-source dependencies.
    - Identify known vulnerabilities.
    - Prioritize security risks using Machine Learning.
    - Generate remediation and testing plans using AI agents.
    - Execute approved tests under human supervision.
    """
)

st.divider()

st.subheader("Project Architecture")

col1, col2, col3 = st.columns(3)

col1.metric(
    "Data Sources",
    "3",
    "OSV / EPSS / CISA KEV"
)

col2.metric(
    "Streaming Engine",
    "Kafka",
    "Local development"
)

col3.metric(
    "Dashboard",
    "Streamlit",
    "Prototype"
)

st.info(
    "Start by opening the New Scan page from the sidebar "
    "and uploading a pinned requirements.txt file."
)
