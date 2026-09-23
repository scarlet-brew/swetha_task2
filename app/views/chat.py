"""Surface 1 of SS9.4: the chat.

At T07 this is the skeleton plus the render constraint it exists to prove. The
answer stage is T31 and the wiring is T36, so the ten evaluation questions
appear as the presets they will become and the input is explicitly disabled --
an input that accepted a question and returned nothing would be a worse lie
than one that says it is not connected yet.

The specimen render below is the day-one proof: three citations open at once,
as siblings of the answer body, with no nested expander anywhere.
"""

from __future__ import annotations

import streamlit as st

from app.components import citation, evidence_table, support_badge
from app.specimen import SPECIMEN_RECORDS, specimen_payload

#: Requirements SS6, verbatim. These are the ten scenarios the system is graded
#: on, so they are copied rather than paraphrased -- a reworded evaluation
#: question is a different question.
EVALUATION_QUESTIONS: tuple[tuple[str, str], ...] = (
    ("AS-01", "Walk me through the full attack timeline from initial access to last observed activity."),
    ("AS-02", "What was the initial access vector and what evidence supports that conclusion?"),
    ("AS-03", "Which MITRE ATT&CK techniques did the attacker use? List them with technique IDs."),
    ("AS-04", "Which user accounts were compromised or used by the attacker?"),
    ("AS-05", "Which internal hosts did the attacker move to after the initial foothold?"),
    ("AS-06", "Is there evidence of data exfiltration? If so, what was accessed and when?"),
    ("AS-07", "What is the blast radius — list every affected host and account."),
    ("AS-08", "Where are the gaps in our log coverage that limit your confidence in this reconstruction?"),
    ("AS-09", "Give me a 3-sentence executive summary suitable for a board briefing."),
    ("AS-10", "What should the incident response team do in the next 2 hours to contain this?"),
)


def render() -> None:
    st.title("Chat")
    st.caption(
        "Ask about the incident. Every statement carries the records behind it, "
        "and the support label says what kind of support that is."
    )

    st.subheader("The ten evaluation questions")
    st.caption(
        "Presets, adopted verbatim from requirements SS6. They become buttons "
        "when the answer stage is wired (T31, T36)."
    )
    evidence_table.render_table(
        [
            {"scenario": scenario, "question": question}
            for scenario, question in EVALUATION_QUESTIONS
        ],
        columns=("scenario", "question"),
    )

    st.chat_input(
        "The answer stage is not wired yet (T31, T36).",
        disabled=True,
    )

    st.divider()
    st.subheader("Support labels")
    st.caption(
        "R3.2-R3.5 replace a confidence score with the structure of the "
        "support. Three of the four colours sit below 3:1 on parchment "
        "(design SS9.1), so every badge carries an icon and the word."
    )
    for state in support_badge.SUPPORT_STATES:
        # Rendered one per line, coloured, so the parchment and dark palettes
        # can both be eyeballed here -- and so the icon-plus-word rule is
        # visible rather than asserted.
        support_badge.render(state)
    support_badge.render("single_sourced", ["resolution_dependent"])
    evidence_table.render_table(
        support_badge.legend_rows(), columns=("kind", "badge", "name", "means")
    )

    st.divider()
    st.warning(
        "Below is a **layout specimen**, not an answer about the incident. Every "
        "value in it is synthetic. It is here so the citation layout can be "
        "reviewed before the answer stage exists.",
        icon=":material/science:",
    )
    report = citation.render_answer(
        specimen_payload(),
        records=SPECIMEN_RECORDS,
        key_prefix="chat::specimen",
    )
    st.caption(
        f"Specimen rendered {report.claims} claims and {report.citations} "
        f"citations; {len(report.expanded)} expanded, "
        f"{len(report.unresolved)} unresolved."
    )


render()
