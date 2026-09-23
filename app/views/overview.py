"""Surface 1: the overview -- the CISO's three questions, answered at a glance.

The brief's evaluation criterion is *Communication*: "can you clearly explain
what your system found, what it is uncertain about, and why?" This page exists
to answer that in one screen, before any drill-down.

Three questions, in the order the brief asks them: which systems were
compromised, what did the attacker do, what is the blast radius -- plus the one
the brief says matters most, what cannot be confirmed.
"""

from __future__ import annotations

import json

import streamlit as st
from siem_investigator import paths

from app.components import support_badge


def _load(path):
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def render() -> None:
    st.title("Incident overview")

    ingest = _load(paths.INGEST_REPORT)
    timeline = _load(paths.TIMELINE)
    scope = _load(paths.SCOPE)
    gaps = _load(paths.GAPS)
    enrich = _load(paths.ENRICH_REPORT)
    correlate = _load(paths.CORRELATE_REPORT)
    privilege = _load(paths.PRIVILEGE)

    if not timeline:
        st.info("No build yet. Run `python -m siem_investigator.build`.", icon=":material/pending:")
        return

    steps = timeline.get("steps", [])
    window = ingest.get("collection_window", {})
    st.caption(
        f"{ingest.get('incident_ref', '')} · "
        f"{ingest.get('counts', {}).get('records_out', 0)} records · "
        f"{len(ingest.get('counts', {}).get('by_source_type', {}))} sources · "
        f"{str(window.get('start'))[:16]} to {str(window.get('end'))[:16]}"
    )

    columns = st.columns(4)
    columns[0].metric("Steps reconstructed", len(steps))
    columns[1].metric("Entities implicated", len(scope.get("involved", [])))
    columns[2].metric("ATT&CK techniques", len(enrich.get("techniques", [])))
    columns[3].metric(
        "Cannot be confirmed",
        len([g for g in gaps.get("from_hypotheses", []) if g["outcome"] != "found"]),
    )

    # ---- what happened ---------------------------------------------------
    st.header("What happened")
    if not steps:
        st.warning(
            "No sequence was reconstructed. A result, not a failure: the relationships "
            "were computed and none supported an accepted finding.",
            icon=":material/info:",
        )
    else:
        stages: list[str] = []
        for step in steps:
            if step["stage"] not in stages:
                stages.append(step["stage"])
        st.markdown(
            "  →  ".join(f"**{stage}**" for stage in stages)
            + f"\n\nFirst observed {steps[0]['first_recorded_time'][:19]}, "
            f"last {steps[-1]['last_recorded_time'][:19]}."
        )

        st.markdown("###### The corroborated steps")
        st.caption("Two or more independent log sources agree. Full sequence on the Timeline tab.")
        for step in [s for s in steps if s["support"]["label"] == "corroborated"][:6]:
            techniques = ", ".join(t["technique_id"] for t in step["techniques"]) or "unmapped"
            st.markdown(
                f"- `{step['first_recorded_time'][:19]}`  **{step['stage']}** · {techniques}  \n"
                f"  {step['statement'][:230]}"
            )

    # ---- blast radius ----------------------------------------------------
    st.header("Blast radius")
    involved = scope.get("involved", [])
    hosts = [row for row in involved if row["entity_type"] == "host"]
    accounts = [row for row in involved if row["entity_type"] == "account"]
    left, right = st.columns(2)
    with left:
        st.markdown(f"###### Hosts involved ({len(hosts)})")
        st.markdown(
            "\n".join(f"- `{row['value']}` — {row['finding_count']} steps" for row in hosts[:12])
            or "- none"
        )
    with right:
        st.markdown(f"###### Accounts involved ({len(accounts)})")
        st.markdown(
            "\n".join(f"- `{row['value']}` — {row['finding_count']} steps" for row in accounts[:12])
            or "- none"
        )

    unimplicated = scope.get("cannot_be_ruled_out", {}).get(
        "hosts_observed_but_not_implicated", []
    )
    if unimplicated:
        st.caption(
            f"{len(unimplicated)} further hosts appear in the data but are cited by no "
            "finding. Not the same as clear — coverage is uneven."
        )

    # ---- the limits, stated plainly --------------------------------------
    st.header("What cannot be confirmed")
    st.caption("Limits of the available sources, not of the analysis. They bound everything above.")
    for gap in gaps.get("structural", []):
        if gap.get("verified"):
            st.markdown(f"- **{gap['statement']}** {gap['limits'].capitalize()}.")

    uncoverable = [g for g in gaps.get("from_hypotheses", []) if g["outcome"] == "not_covered"]
    not_found = [g for g in gaps.get("from_hypotheses", []) if g["outcome"] == "not_found"]
    if uncoverable:
        st.markdown(
            f"- **{len(uncoverable)} predictions could not be tested at all** — no source "
            "covers the entity and event kind. Their absence says nothing."
        )
    if not_found:
        st.markdown(
            f"- **{len(not_found)} predictions were tested and not confirmed** in a source "
            "that does cover them."
        )
    escalation = privilege.get("exploit_based_escalation", {})
    if privilege and not escalation.get("evidenced", True):
        st.markdown(
            "- **No exploit-based privilege escalation is evidenced.** Privilege rises through "
            "credentials and service execution. "
            f"{', '.join(escalation.get('techniques_deliberately_not_mapped', []))} is "
            "deliberately not claimed."
        )

    # ---- how to read the labels ------------------------------------------
    st.header("How to read the support labels")
    st.caption("Counted from the evidence, never estimated. There are no confidence scores.")
    support = correlate.get("support_distribution", {})
    for label in ("corroborated", "single_sourced", "absence_based", "conflicted"):
        count = support.get(label, 0)
        spec = support_badge.spec(label)
        st.markdown(f"- {support_badge.badge_markup(label)} — {spec.meaning} · **{count}**")


render()
