"""Surface 4 of SS9.4: the pipeline, the gap report and the working.

The six stages as `st.status(type="step")`, each expandable to its artifacts and
its verification result. Unlike the other three surfaces this one has real
content at T07, because artifact existence is a fact about the tree rather than
a conclusion from the data -- and "stage 3 has not run" is exactly what a
reader needs to know before believing anything on the other pages.

It also carries the theme audit. Design SS9.1's contrast figures are a claim
like any other, so they are measured here from `.streamlit/config.toml` and
shown rather than asserted in a comment. That table is simultaneously the
`st.dataframe`-over-pyarrow surface SS10.1 left unmeasured.
"""

from __future__ import annotations

import streamlit as st

from siem_investigator import paths

from app import artifacts, theme
from app.components import citation, evidence_table, support_badge


def _render_stages() -> None:
    st.subheader("The six stages")
    st.caption(
        "State is read from the artifacts on disk, not from a build log. A "
        "stage is `complete` only when every artifact it publishes exists."
    )
    for stage in artifacts.STAGES:
        state = stage.state
        # A stage that runs at question time is neither complete nor unbuilt.
        status = {
            "complete": "complete",
            "partial": "error",
            "not built": "running",
            "live at query time": "complete",
        }[state]
        with st.status(
            f"Stage {stage.number} · {stage.name} — {state}",
            state=status,  # type: ignore[arg-type]
            type="step",
            expanded=(state != "complete"),
        ):
            st.caption(f"Determinism: {stage.determinism}")
            if not stage.artifacts:
                st.caption(
                    "Publishes no build artifact. Stage 6 writes one answer "
                    "record per question under `outputs/answers/`, which is a "
                    "projection of the graph and not part of the build."
                )
                continue
            evidence_table.render_table(
                artifacts.artifact_rows(stage),
                columns=("artifact", "present", "bytes"),
            )


def _render_theme_audit() -> None:

    st.header("Citation layout specimen")
    st.warning(
        "This is a **layout specimen**, not incident data -- every value in it is "
        "synthetic. Kept as the render proof: three citations open at once as siblings "
        "of the answer body, with no nested expander.",
        icon=":material/science:",
    )
    from app.specimen import SPECIMEN_RECORDS, specimen_payload

    report = citation.render_answer(
        specimen_payload(), records=SPECIMEN_RECORDS, key_prefix="pipeline::specimen"
    )
    st.caption(
        f"{report.claims} claims, {report.citations} citations, "
        f"{len(report.unresolved)} unresolved."
    )

    st.header("Support labels")
    for state in support_badge.SUPPORT_STATES:
        support_badge.render(state)
    support_badge.render("single_sourced", ["resolution_dependent"])
    evidence_table.render_table(
        support_badge.legend_rows(), columns=("kind", "badge", "name", "means")
    )

    st.subheader("Palette audit")
    st.caption(
        "Design SS9.1's contrast figures, recomputed from the hex values in "
        "`.streamlit/config.toml` at render time. Ratios are WCAG 2.x against "
        "the panel surface, which is what the ink actually sits on."
    )
    light, dark = st.columns(2)
    with light:
        st.markdown("**Parchment (light)**")
        evidence_table.render_table(
            theme.audit("light"),
            columns=("role", "hex", "ratio_vs_panel", "clears"),
        )
    with dark:
        st.markdown("**Selected dark**")
        evidence_table.render_table(
            theme.audit("dark"),
            columns=("role", "hex", "ratio_vs_panel", "clears"),
        )

    st.markdown("**Status palette — unthemed, and below the colour floor**")
    st.caption(
        "Three of the four support colours sit under 3:1, which is why every "
        "badge carries an icon and the word. Colour never carries a state on "
        "its own, here or in print."
    )
    evidence_table.render_table(
        theme.status_audit(),
        columns=(
            "support_state",
            "hex",
            "colour_family",
            "ratio_vs_panel",
            "colour_alone_sufficient",
        ),
    )


def render() -> None:
    st.title("Pipeline")
    st.caption(
        "What the system did, stage by stage, with each stage's artifacts and "
        "the gaps it found. R10.1-R10.3: the working is inspectable, not "
        "summarised."
    )

    _render_stages()

    st.divider()
    handover = paths.OUTPUTS / "handover.md"
    if handover.is_file():
        st.subheader("Handover report")
        st.caption(
            "The self-contained document the CISO forwards. No links back into this tool, "
            "no node id without the record behind it -- someone reading it in an email "
            "thread with no access to this repository can follow it and check it."
        )
        text = handover.read_text(encoding="utf-8")
        st.download_button(
            "Download handover.md",
            data=text,
            file_name="handover.md",
            mime="text/markdown",
            icon=":material/download:",
        )
        with st.expander(f"Preview ({len(text):,} bytes)"):
            truncated = len(text) > 6000
            note = "\n\n*... truncated; download for the whole document.*"
            st.markdown(text[:6000] + (note if truncated else ""))
    st.info(
        "The gap report is published by stage 5 and the rejection log by "
        "stage 3; neither exists yet. Each gap will appear beside the "
        "hypothesis that went looking for it (R3.6), so an absent source is "
        "visible as something the system searched for and did not find rather "
        "than as something it never considered.",
        icon=":material/pending:",
    )

    st.divider()
    _render_theme_audit()


render()
