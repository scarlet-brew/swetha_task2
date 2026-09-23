"""Entry point: `streamlit run app/main.py`.

Four surfaces, registered explicitly through `st.navigation` rather than by
dropping files in a `pages/` directory. Two reasons. The order and the icons
are part of the design (SS9.4 lists the surfaces in the order a reader should
meet them), and `st.navigation` is the primitive that makes that order
something this file states rather than something a filename sort implies. The
second reason is negative: D-06 rejected Chainlit specifically because it has
no multipage primitive, and using the one Streamlit has is the return on that
decision.

The `sys.path` bootstrap is deliberate and unavoidable. The project is never
installed -- setuptools is outside design SS10.1's frozen dependency set and a
`pip install` at demo time is an NFR-02 failure -- so the repository root and
`src/` go on the path here, once, before anything under `app/` or
`siem_investigator` is imported. `tests/_env.py` does the same thing for the
same reason.
"""

from __future__ import annotations

import sys
from pathlib import Path

#: app/main.py -> app -> repository root
ROOT = Path(__file__).resolve().parents[1]

for entry in (ROOT, ROOT / "src"):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

import streamlit as st  # noqa: E402  -- must follow the path bootstrap

from app import theme  # noqa: E402

st.set_page_config(
    page_title="Incident INC-2026-0610-001",
    page_icon=":material/folder_open:",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# The two stylesheets config.toml cannot express (SS9.2's measure and tabular
# figures, and SS9.4's print sheet). Injected once per run, before any surface
# renders, so nothing paints unstyled first.
theme.inject_chrome()

SURFACES = [
    st.Page(
        "views/chat.py",
        title="Ask",
        icon=":material/forum:",
        url_path="chat",
        default=True,
    ),
    st.Page(
        "views/overview.py",
        title="Overview",
        icon=":material/summarize:",
        url_path="overview",
    ),
    st.Page(
        "views/timeline.py",
        title="Timeline",
        icon=":material/timeline:",
        url_path="timeline",
    ),
    st.Page(
        "views/impact.py",
        title="Impact",
        icon=":material/lan:",
        url_path="impact",
    ),
    st.Page(
        "views/pipeline.py",
        title="Pipeline",
        icon=":material/account_tree:",
        url_path="pipeline",
    ),
]

with st.sidebar:
    st.markdown("### Deloitte Cyber Engineering")
    st.markdown("**INC-2026-0610-001**")
    st.caption("Meridian Health Partners")
    st.caption("72-hour window · synthetic dataset")

st.navigation(SURFACES).run()
