"""Surface 3 of SS9.4: impact -- hosts, accounts, assets.

An enumeration, so a table (SS9.3). Three columns of it carry the requirements
that are easiest to fudge and hardest to defend: first and last involvement
(R5.2), confirmed compromise separated from mere observation (R5.3, AS-04), and
what cannot be ruled out (R3.12, AS-07) -- including hosts that appear in the
incident but about which a relevant source records nothing.

At T07 stage 5 has not run, so the page names the artifact it waits for and
shows the column contract instead. T37 fills it in.
"""

from __future__ import annotations

import streamlit as st
from siem_investigator import paths

from app import artifacts
from app.components import evidence_table


def render() -> None:
    st.title("Impact")
    st.caption(
        "Every host and account the incident touched, with first and last "
        "involvement, whether compromise is confirmed or merely observed, and "
        "what the data cannot rule out."
    )

    notice = artifacts.absent_notice(paths.SCOPE)
    if notice:
        st.info(notice, icon=":material/pending:")
        st.subheader("The shape this table will have")
        evidence_table.render_table(
            [
                {"column": column, "serves": serves}
                for column, serves in (
                    ("entity", "R5.1 — every affected host and account"),
                    ("entity_kind", "R5.1 — host, account or asset"),
                    ("first_involvement", "R5.2 — as recorded, zone stated"),
                    ("last_involvement", "R5.2 — as recorded, zone stated"),
                    ("assessment", "R5.3 — confirmed compromise vs observed only"),
                    ("assets", "R5.4 — what was accessed, and the volume"),
                    ("coverage_gaps", "R3.12 — sources that record nothing for it"),
                    ("cannot_rule_out", "AS-07 — stated, not implied"),
                    ("citations", "R2.2, R2.3 — records and the named basis"),
                )
            ],
            columns=("column", "serves"),
        )
        st.caption(
            "R1.10 and AS-04 constrain one column in particular: an account "
            "with no ordinary activity to compare against is a limitation on "
            "the assessment, never grounds for it. The absence of a baseline "
            "is not evidence of compromise."
        )
        return

    # T37 renders the real enumeration here.
    st.error(
        f"`{paths.relative(paths.SCOPE)}` exists but this surface is not built "
        "yet (T37). Nothing is rendered rather than something partial.",
        icon=":material/construction:",
    )


render()
