
import importlib
import streamlit as st

from src.utils.requirements_parser import parse_requirements_text
from src.streaming.producer import publish_scan_request
from src.utils import ui
from src.utils.vulnerability_result_view import render_vulnerability_result

importlib.reload(ui)


st.set_page_config(
    page_title="New Scan | VulnGuard AI",
    page_icon="🛡️",
    layout="wide",
)

ui.apply_app_styles()
ui.render_page_header(
    "Start a dependency scan",
    "Upload a Python requirements file to review its pinned packages and submit a scan request.",
)

st.divider()

project_col, upload_col = st.columns([1, 1.35], gap="large")

with project_col:
    st.subheader("1. Identify the project")
    project_name = st.text_input(
        "Project name",
        placeholder="my-python-project",
        help="A name to help you recognize this scan in the history.",
    )

with upload_col:
    st.subheader("2. Add dependencies")
    uploaded_file = st.file_uploader(
        "Upload requirements.txt",
        type=["txt"],
        help="For this prototype, dependencies must use exact versions, such as requests==2.31.0.",
    )
    st.caption("Exact version pins (==) are required for this scan prototype.")

if uploaded_file is not None:

    try:
        content = uploaded_file.getvalue().decode("utf-8-sig")

        result = parse_requirements_text(content)

        dependencies = result["dependencies"]
        skipped = result["skipped"]

        st.divider()
        st.subheader("3. Review detected dependencies")
        st.caption("Check the parsed package list before submitting the request.")

        col1, col2 = st.columns(2)

        col1.metric(
            "Valid dependencies",
            len(dependencies)
        )

        col2.metric(
            "Skipped lines",
            len(skipped)
        )

        # Display valid dependencies
        if dependencies:

            st.success(
                f"{len(dependencies)} dependencies successfully extracted."
            )

            st.dataframe(
                dependencies,
                use_container_width=True
            )

        else:
            st.warning(
                "No exact pinned dependencies were found."
            )

        # Explain skipped lines
        if skipped:

            with st.expander("View unsupported lines"):

                for item in skipped:
                    st.warning(
                        f"Line {item['line_number']}: "
                        f"{item['line']} — {item['reason']}"
                    )

        st.divider()

        # Explicit confirmation for partial scans
        allow_partial = True

        if dependencies and skipped:

            allow_partial = st.checkbox(
                "I understand that unsupported dependencies "
                "will not be included in this scan."
            )

        scan_allowed = (
            bool(project_name.strip())
            and bool(dependencies)
            and allow_partial
        )

        if st.button(
            "Submit scan request",
            type="primary",
            disabled=not scan_allowed
        ):

            try:

                with st.spinner("Publishing scan request to Kafka..."):

                    event = publish_scan_request(
                        project_name=project_name.strip(),
                        dependencies=dependencies
                    )

                st.session_state["last_scan_event"] = event

                st.success(
                    "Scan request successfully published to Kafka!"
                )

                st.subheader("Published Event")

                st.json(event)

            except Exception as error:

                st.error(
                    f"Unable to publish scan request: {error}"
                )

    except UnicodeDecodeError:

        st.error(
            "The uploaded file must be encoded in UTF-8."
        )
