"""The conversation. This is the app.

Deliberately plain: a centred column, your question, the answer, and one quiet
toggle holding the records behind it. Everything else that used to be on this
page -- claim cards, support badges, `kind` labels, an expander per citation,
ten full-width preset buttons, a synthetic layout specimen -- has been taken
off. It was structure I added for my own benefit and it buried the answer.

The evidence is still one click away and every claim is still checked by the
citation gate before it renders. What changed is that the reader sees prose
first, with `[EVT-0221]` references they can actually look up, and reaches for
the source table only when they want it.
"""

from __future__ import annotations

import streamlit as st
from siem_investigator import paths
from siem_investigator.agent import answer

from app.components import citation, evidence_table

#: The brief's own example queries, verbatim. Shown as starters on an empty
#: conversation and gone as soon as there is one.
STARTERS: tuple[str, ...] = (
    "Walk me through the attack timeline.",
    "What was the initial access vector?",
    "Which ATT&CK techniques did the attacker use?",
    "Is there evidence of data exfiltration?",
    "What is the blast radius?",
    "Where are the gaps in our log coverage?",
)

ALL_QUESTIONS: tuple[str, ...] = STARTERS + (
    "Which user accounts were compromised or used by the attacker?",
    "Which internal hosts did the attacker move to after the initial foothold?",
    "Give me a 3-sentence executive summary suitable for a board briefing.",
    "What should the incident response team do in the next 2 hours to contain this?",
)


def _sources(payload: dict) -> list[dict]:
    """Every cited record across the answer, deduplicated, in time order.

    One list for the whole answer rather than one per claim. A reader checking
    an answer wants "what is this built on"; they do not want to open seven
    toggles to find out.
    """
    seen: dict[str, dict] = {}
    for claim in payload.get("claims") or []:
        for row in claim.get("citations") or []:
            event = row.get("event_id")
            if not event or event in seen:
                continue
            seen[event] = {
                "event": event,
                "source": row.get("source_type"),
                "recorded": row.get("timestamp"),
                "field": row.get("field"),
                "value": str(row.get("asserted_value") or "")[:80],
                "record_id": row.get("record_id"),
            }
    return sorted(seen.values(), key=lambda row: (str(row["recorded"]), row["event"]))


def _render_answer(result: dict, *, key: str) -> None:
    if result.get("withheld"):
        with st.chat_message("assistant"):
            st.markdown(f"**I'm not showing an answer for this.** {result.get('reason', '')}")
            for failure in result.get("failures", []):
                st.caption(failure)
        return

    payload = result["payload"]
    with st.chat_message("assistant"):
        st.markdown(payload["body"])

        for gap in payload.get("gaps") or []:
            st.caption(f"Not settled by the logs: {gap.get('statement', gap)}")

        rows = _sources(payload)
        if rows:
            with st.expander(f"Sources — {len(rows)} log events"):
                evidence_table.render_table(
                    rows, columns=("event", "source", "recorded", "field", "value")
                )
                records = citation.records_from_file(paths.RECORDS)
                chosen = st.selectbox(
                    "Open a record",
                    [row["event"] for row in rows],
                    key=f"{key}::record",
                )
                match = next((row for row in rows if row["event"] == chosen), None)
                if match and match["record_id"] in records:
                    st.json(records[match["record_id"]].get("payload", {}), expanded=2)


#: A reading measure, applied to this page only.
#:
#: The other surfaces are tables and want the width; a conversation does not.
#: Long lines are the biggest readability cost in prose, and Streamlit's default
#: block runs the full window, which is what made the first answers feel like a
#: wall even after the node ids came out of them.
_CHAT_WIDTH = """
<style>
  .main .block-container { max-width: 780px; }
  [data-testid="stChatMessage"] { background: transparent; padding: 0.35rem 0; }
  [data-testid="stChatMessage"] p { line-height: 1.65; }
  [data-testid="stExpander"] summary { font-size: 0.8rem; }
</style>
"""


def render() -> None:
    st.markdown(_CHAT_WIDTH, unsafe_allow_html=True)

    if not (paths.FINDINGS.is_file() and paths.TIMELINE.is_file()):
        st.title("Incident assistant")
        st.info(
            "No investigation has been built yet. Run `python -m siem_investigator.build`.",
            icon=":material/pending:",
        )
        return

    history = st.session_state.setdefault("chat_history", [])

    if not history:
        st.title("Incident assistant")
        st.caption(
            "Ask about incident INC-2026-0610-001. Answers come from the reconstructed "
            "log evidence, and every one shows the records behind it."
        )
        columns = st.columns(2)
        for index, starter in enumerate(STARTERS):
            if columns[index % 2].button(starter, key=f"starter::{index}", width="stretch"):
                st.session_state.pending_question = starter

    for entry in history:
        with st.chat_message("user"):
            st.markdown(entry["question"])
        _render_answer(entry["result"], key=entry["key"])

    typed = st.chat_input("Ask about the incident")
    question = typed or st.session_state.pop("pending_question", None)

    if question:
        with st.chat_message("user"):
            st.markdown(question)
        with st.spinner("Checking the evidence..."):
            result = answer.ask(question)
        key = f"chat::{len(history)}"
        history.append({"question": question, "result": result, "key": key})
        _render_answer(result, key=key)


render()
