"""Surface 2 of SS9.4: the timeline.

A typed table, expandable per row, not a chart. SS9.3 is explicit about why:
the timeline's job is to be *read* in order with the evidence opened beside
each step, and a Gantt-shaped picture of 22 events cannot be read that way.

At T07 the table has no rows, because stage 5 has not run. The page says so and
names the artifact it is waiting for. T37 fills it in, reusing this page's
sibling-expander pattern for the per-row drill-down.
"""

from __future__ import annotations

import streamlit as st
from siem_investigator import paths

from app import artifacts
from app.components import evidence_table, support_badge


def render() -> None:
    st.title("Timeline")
    st.caption(
        "One time-ordered sequence from first to last observed activity, each "
        "step carrying its technique, the structure of its support, and its "
        "citations. Recorded times are shown exactly as they appear in the "
        "data, with the zone stated."
    )

    notice = artifacts.absent_notice(paths.TIMELINE)
    if notice:
        st.info(notice, icon=":material/pending:")
        st.subheader("The shape this table will have")
        st.caption(
            "Columns only — no rows. The column list is the contract stage 5 "
            "has to satisfy, so it is worth reviewing before it is built."
        )
        evidence_table.render_table(
            [
                {
                    "column": column,
                    "serves": serves,
                }
                for column, serves in (
                    ("step", "R1.1 — one time-ordered sequence"),
                    ("recorded_time", "R7.5 — as recorded, zone stated"),
                    ("entity", "R1.2 — the host or account involved"),
                    ("activity", "R1.1 — what the records show happened"),
                    ("technique", "R4.1 — ATT&CK id and official name"),
                    ("support", "R3.2 — Corroborated / Single-sourced / Absence-based"),
                    ("flags", "R3.3 — resolution-dependent, conflicted"),
                    ("citations", "R2.2, R2.3 — the records and the named basis"),
                )
            ],
            columns=("column", "serves"),
        )

        st.subheader("Support labels this table will carry")
        st.markdown(
            "  ".join(
                support_badge.badge_markup(name)
                for name in support_badge.SUPPORT_STATES
            )
        )
        evidence_table.render_table(
            support_badge.legend_rows(), columns=("kind", "badge", "name", "means")
        )
        return

    # T37 renders the real table here, over the committed artifact, using
    # citation.py's sibling pattern for each row's drill-down.
    st.error(
        f"`{paths.relative(paths.TIMELINE)}` exists but this surface is not "
        "built yet (T37). Nothing is rendered rather than something partial.",
        icon=":material/construction:",
    )


render()
