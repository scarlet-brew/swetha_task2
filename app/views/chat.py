"""Surface 2: ask a question, get an answer with its evidence attached.

One job, and everything not serving it has been taken off this page. The
example questions are folded away, the support-label legend lives on Overview,
and the citation specimen lives on Pipeline -- a synthetic answer sitting beside
real ones was the most confusing thing in the first version of this surface.

The answer body is plain English with no node ids in it. The ids are attached to
each claim as evidence instead, which is where a reader can act on them.
"""

from __future__ import annotations

import streamlit as st
from siem_investigator import paths
from siem_investigator.agent import answer

from app.components import citation, evidence_table, support_badge

#: The brief's own example queries, verbatim. A reworded evaluation question is
#: a different question, so they are copied rather than paraphrased.
EXAMPLE_QUESTIONS: tuple[str, ...] = (
    "Walk me through the full attack timeline from initial access to last observed activity.",
    "What was the initial access vector and what evidence supports that conclusion?",
    "Which MITRE ATT&CK techniques did the attacker use? List them with technique IDs.",
    "Which user accounts were compromised or used by the attacker?",
    "Which internal hosts did the attacker move to after the initial foothold?",
    "Is there evidence of data exfiltration? If so, what was accessed and when?",
    "What is the blast radius — list every affected host and account.",
    "Where are the gaps in our log coverage that limit your confidence in this reconstruction?",
    "Give me a 3-sentence executive summary suitable for a board briefing.",
    "What should the incident response team do in the next 2 hours to contain this?",
)


def _render_claim(claim: dict, records: dict, *, key: str) -> None:
    """One claim: the sentence, its support, and its evidence behind one toggle.

    Deliberately one expander per claim rather than one per citation. Seven
    separate toggles under a single claim was noise; the reader wants "show me
    what this rests on", once.
    """
    label = claim["support"]["label"]
    st.markdown(
        f"**{claim['text']}**  \n"
        f"{support_badge.support_markup(label, claim['support'].get('flags', ()))}"
        f" · `{claim['kind']}`"
    )

    citations = claim.get("citations") or []
    if not citations:
        st.error("This claim cites nothing. Under R2.2 that is a bug.", icon=":material/error:")
        return

    with st.expander(f"Evidence — {len(citations)} record(s)"):
        evidence_table.render_table(
            [
                {
                    "event": row.get("event_id"),
                    "source": row.get("source_type"),
                    "recorded": row.get("timestamp"),
                    "field": row.get("field"),
                    "value": str(row.get("asserted_value"))[:70],
                }
                for row in citations
            ],
            columns=("event", "source", "recorded", "field", "value"),
        )
        shown = set()
        for row in citations:
            record_id = row.get("record_id")
            if record_id in records and record_id not in shown:
                shown.add(record_id)
                st.caption(f"{row.get('event_id')} as recorded")
                st.json(records[record_id].get("payload", records[record_id]), expanded=1)
            if len(shown) >= 3:
                break


def _render_result(result: dict, *, key_prefix: str) -> None:
    """Render an answer, or say plainly why it was withheld.

    R2.9: an answer whose citations do not resolve is withheld and the failing
    check reported. Showing it without the evidence would be the fabrication the
    whole design exists to prevent.
    """
    if result.get("withheld"):
        st.error(f"**Answer withheld.** {result.get('reason', '')}", icon=":material/block:")
        for failure in result.get("failures", []):
            st.markdown(f"- {failure}")
        return

    payload = result["payload"]
    records = citation.records_from_file(paths.RECORDS)

    with st.chat_message("assistant"):
        st.markdown(payload["body"])

        claims = payload.get("claims") or []
        if claims:
            st.markdown("---")
            for index, claim in enumerate(claims, start=1):
                _render_claim(claim, records, key=f"{key_prefix}::{index}")

        gaps = payload.get("gaps") or []
        if gaps:
            st.info(
                "**What this cannot settle**\n\n"
                + "\n".join(f"- {gap.get('statement', gap)}" for gap in gaps),
                icon=":material/help:",
            )


def render() -> None:
    st.title("Ask")
    st.caption("Answers come from the committed investigation graph. Every claim shows its records.")

    ready = paths.FINDINGS.is_file() and paths.TIMELINE.is_file()
    if not ready:
        st.info(
            "No committed artifacts yet. Run `python -m siem_investigator.build`.",
            icon=":material/pending:",
        )
        return

    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []

    # Folded away by default. Ten buttons filling the screen above the
    # conversation buried the thing the page is for.
    with st.expander("Example questions"):
        picked = st.radio(
            "Pick one",
            EXAMPLE_QUESTIONS,
            index=None,
            label_visibility="collapsed",
            key="example_question",
        )
        if picked and st.button("Ask this", type="primary"):
            st.session_state.pending_question = picked

    for entry in st.session_state.chat_history:
        with st.chat_message("user"):
            st.markdown(entry["question"])
        _render_result(entry["result"], key_prefix=entry["key"])

    typed = st.chat_input("Ask about the incident")
    question = typed or st.session_state.pop("pending_question", None)

    if question:
        with st.chat_message("user"):
            st.markdown(question)
        with st.spinner("Reading the investigation graph..."):
            result = answer.ask(question)
        key = f"chat::{len(st.session_state.chat_history)}"
        st.session_state.chat_history.append(
            {"question": question, "result": result, "key": key}
        )
        _render_result(result, key_prefix=key)


render()
