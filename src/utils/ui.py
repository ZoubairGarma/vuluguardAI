import streamlit as st


def apply_app_styles():
    """Apply the shared visual style used by every Streamlit page."""
    st.markdown(
        """
        <style>
        :root {
            --vg-ink: #172033;
            --vg-muted: #68758a;
            --vg-line: #e4eaf2;
            --vg-blue: #2563eb;
            --vg-teal: #0f9f92;
            --vg-panel: #ffffff;
        }

        .stApp {
            background: #f4f7fb;
            color: var(--vg-ink);
        }

        [data-testid="stHeader"] {
            background: rgba(244, 247, 251, 0.88);
        }

        [data-testid="stSidebar"] {
            background: #111827;
            border-right: 1px solid #263244;
        }

        [data-testid="stSidebar"] * {
            color: #e5edf8;
        }

        [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {
            color: #aab8ca;
        }

        [data-testid="stMainBlockContainer"] {
            max-width: 1280px;
            padding-top: 2rem;
            padding-bottom: 3rem;
        }

        .vg-title {
            color: #111827;
            font-size: clamp(2rem, 3.2vw, 2.65rem);
            font-weight: 800;
            letter-spacing: -0.045em;
            line-height: 1.12;
            margin: 0;
        }

        .vg-subtitle {
            color: var(--vg-muted);
            font-size: 1rem;
            line-height: 1.6;
            margin: 0.55rem 0 0 0;
            max-width: 760px;
        }

        [data-testid="stMetric"] {
            background: var(--vg-panel);
            border: 1px solid var(--vg-line);
            border-radius: 14px;
            padding: 1rem 1.1rem;
            box-shadow: 0 3px 12px rgba(27, 44, 75, 0.035);
        }

        [data-testid="stMetricLabel"] {
            color: var(--vg-muted);
            font-size: 0.82rem;
            font-weight: 600;
        }

        [data-testid="stMetricValue"] {
            color: var(--vg-ink);
            font-weight: 750;
        }

        div.stButton > button,
        div[data-testid="stFormSubmitButton"] > button {
            border-radius: 9px;
            font-weight: 650;
            min-height: 2.65rem;
            transition: all 140ms ease;
        }

        div.stButton > button[kind="primary"],
        div[data-testid="stFormSubmitButton"] > button[kind="primary"] {
            background: var(--vg-blue);
            border-color: var(--vg-blue);
        }

        [data-testid="stDataFrame"] {
            border: 1px solid var(--vg-line);
            border-radius: 12px;
            overflow: hidden;
        }

        [data-testid="stFileUploader"] section {
            background: #fff;
            border: 1px dashed #b8c5d8;
            border-radius: 12px;
        }

        [data-testid="stExpander"] {
            background: rgba(255, 255, 255, 0.72);
            border: 1px solid var(--vg-line);
            border-radius: 10px;
        }

        [data-testid="stTabs"] [role="tab"] {
            font-weight: 650;
        }

        hr {
            border-color: var(--vg-line);
        }

        @media (max-width: 700px) {
            [data-testid="stMainBlockContainer"] {
                padding: 1.25rem 1rem 2rem;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_page_header(title, subtitle):
    """Render a consistent title block at the top of a page."""
    st.markdown(
        f"""
        <h1 class="vg-title">{title}</h1>
        <p class="vg-subtitle">{subtitle}</p>
        """,
        unsafe_allow_html=True,
    )