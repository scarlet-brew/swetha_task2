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

from siem_investigator import paths
from siem_investigator.agent import answer

from app.components import citation

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


def _render_result(result: dict, *, key_prefix: str) -> None:
    """Render an answer, or say plainly why it was withheld.

    R2.9: an answer whose citations do not resolve is withheld and the failing
    check reported. Showing it without the evidence would be the fabrication the
    whole design exists to prevent, and a silent failure would be worse than a
    visible one.
    """
    if result.get("withheld"):
        st.error(
            f"**Answer withheld.** {result.get('reason', 'no reason given')}",
            icon=":material/block:",
        )
        for failure in result.get("failures", []):
            st.markdown(f"- {failure}")
        return

    citation.render_answer(
        result["payload"],
        records=citation.records_from_file(paths.RECORDS),
        key_prefix=key_prefix,
    )


def render() -> None:
    st.title("Chat")
    st.caption("Every statement carries the records behind it. Support labels are on the Overview tab.")

    ready = paths.FINDINGS.is_file() and paths.TIMELINE.is_file()
    if not ready:
        st.info(
            "No committed artifacts yet. Run `python -m siem_investigator.build` first -- "
            "the app only reads what the build produced, and computes nothing at question "
            "time that could mint a claim (NFR-01).",
            icon=":material/pending:",
        )

    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []

    st.caption("Click a question, or type your own.")
    for row in range(0, len(EVALUATION_QUESTIONS), 2):
        columns = st.columns(2)
        for column, (scenario, question) in zip(
            columns, EVALUATION_QUESTIONS[row : row + 2]
        ):
            if column.button(
                f"{scenario}  {question[:58]}{'...' if len(question) > 58 else ''}",
                key=f"preset::{scenario}",
                disabled=not ready,
                use_container_width=True,
            ):
                st.session_state.pending_question = question

    typed = st.chat_input(
        "Ask about the incident" if ready else "Run the build first",
        disabled=not ready,
    )
    question = typed or st.session_state.pop("pending_question", None)

    for entry in st.session_state.chat_history:
        with st.chat_message("user"):
            st.markdown(entry["question"])
        _render_result(entry["result"], key_prefix=entry["key"])

    if question:
        with st.chat_message("user"):
            st.markdown(question)
        with st.spinner("Reading the committed graph..."):
            result = answer.ask(question)
        key = f"chat::{len(st.session_state.chat_history)}"
        st.session_state.chat_history.append(
            {"question": question, "result": result, "key": key}
        )
        _render_result(result, key_prefix=key)


render()
