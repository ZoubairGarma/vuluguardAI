
import streamlit as st

from src.utils.requirements_parser import parse_requirements_text
from src.streaming.producer import publish_scan_request


st.title("New Dependency Scan")

st.markdown(
    """
    Upload your Python project's `requirements.txt`.
    VulnGuard AI will extract the dependencies and
    submit a scan request to Kafka.
    """
)

st.divider()

# Project information
project_name = st.text_input(
    "Project name",
    placeholder="my-python-project"
)

# Upload requirements file
uploaded_file = st.file_uploader(
    "Upload requirements.txt",
    type=["txt"]
)

if uploaded_file is not None:

    try:
        content = uploaded_file.getvalue().decode("utf-8-sig")

        result = parse_requirements_text(content)

        dependencies = result["dependencies"]
        skipped = result["skipped"]

        st.subheader("Dependency Analysis")

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
            "Start Scan",
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
