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

from app import artifacts, theme
from app.components import evidence_table


def _render_stages() -> None:
    st.subheader("The six stages")
    st.caption(
        "State is read from the artifacts on disk, not from a build log. A "
        "stage is `complete` only when every artifact it publishes exists."
    )
    for stage in artifacts.STAGES:
        state = stage.state
        status = {"complete": "complete", "partial": "error", "not built": "running"}[state]
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
    st.subheader("Coverage gaps and the rejection log")
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
