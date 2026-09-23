"""Surface 2 of SS9.4: the timeline.

A typed table, expandable per row, not a chart. SS9.3 is explicit about why: the
timeline's job is to be *read* in order with the evidence opened beside each
step, and a Gantt-shaped picture of 22 events cannot be read that way.

Every expander is opened at this level, so several steps can be open at once --
the flat layout SS9.4 requires, with no expander inside another.
"""

from __future__ import annotations

import json

import streamlit as st
from siem_investigator import paths

from app import artifacts
from app.components import evidence_table, support_badge


def _load(path):
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _index(path):
    if not path.is_file():
        return {}
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            out[row["id"]] = row
    return out


def render() -> None:
    st.title("Timeline")
    st.caption(
        "One time-ordered sequence from first to last observed activity, each step "
        "carrying its technique, the structure of its support, and its citations. "
        "Recorded times are shown exactly as they appear in the data, with the zone stated."
    )

    notice = artifacts.absent_notice(paths.TIMELINE)
    if notice:
        st.info(notice, icon=":material/pending:")
        st.caption("Run `python -m siem_investigator.build` to produce it.")
        return

    timeline = _load(paths.TIMELINE)
    steps = timeline.get("steps", [])

    if timeline.get("no_reconstruction") or not steps:
        # The honest empty case. It has to read as a *result*, not a broken
        # page: "no intrusion reconstructed" is a valid outcome.
        st.warning(
            "The build accepted no findings, so there is no sequence to show. That is a "
            "result rather than an error -- the relationships and the coverage report on "
            "the other surfaces still stand.",
            icon=":material/info:",
        )
        return

    window = timeline.get("window", {})
    left, right = st.columns(2)
    left.metric("Steps", len(steps))
    right.metric(
        "Span",
        f"{str(window.get('first'))[:19]} -> {str(window.get('last'))[:19]}",
    )

    evidence_table.render_table(
        [
            {
                "step": index,
                "recorded_time": step["first_recorded_time"],
                "stage": step["stage"],
                "technique": ", ".join(t["technique_id"] for t in step["techniques"]) or "unmapped",
                "support": support_badge.badge_text(step["support"]["label"]),
                "flags": ", ".join(step["support"]["flags"]) or "-",
                "sources": ", ".join(step["source_types"]),
                "events": ", ".join(step["event_ids"][:6]),
            }
            for index, step in enumerate(steps, start=1)
        ],
        columns=(
            "step",
            "recorded_time",
            "stage",
            "technique",
            "support",
            "flags",
            "sources",
            "events",
        ),
    )

    st.subheader("Each step, with its evidence")
    st.caption(
        "Open as many as you like -- the citations are siblings, not nested, so nothing "
        "collapses when another opens."
    )

    observations = _index(paths.OBSERVATIONS)
    records = _index(paths.RECORDS)

    for index, step in enumerate(steps, start=1):
        with st.expander(f"{index}. [{step['stage']}] {step['statement'][:110]}"):
            st.markdown(
                f"`{step['stage']}`  "
                + support_badge.support_markup(step["support"]["label"], step["support"]["flags"])
            )
            st.markdown(step["statement"])

            if step["techniques"]:
                for technique in step["techniques"]:
                    st.caption(
                        f"**{technique['technique_id']}** {technique['technique_name']} "
                        f"· tactics: {', '.join(technique['tactics'])}"
                    )
            else:
                st.caption(
                    "Technique attribution is reported as **unmapped** rather than omitted "
                    "(NFR-02)."
                )

            evidence_table.render_table(
                [
                    {
                        "observation": obs,
                        "event_id": observations.get(obs, {}).get("event_id"),
                        "source_type": observations.get(obs, {}).get("source_type"),
                        "timestamp": observations.get(obs, {}).get("recorded_time"),
                        "field": observations.get(obs, {}).get("field"),
                        "asserted_value": str(observations.get(obs, {}).get("normalised_value")),
                    }
                    for obs in step["cites_observations"]
                ],
                columns=(
                    "observation",
                    "event_id",
                    "source_type",
                    "timestamp",
                    "field",
                    "asserted_value",
                ),
                empty_message="No citations on this step -- under R2.2 that is a bug.",
            )

            shown = set()
            for obs in step["cites_observations"]:
                record_id = observations.get(obs, {}).get("record")
                if record_id in records and record_id not in shown:
                    shown.add(record_id)
                    st.caption(f"raw record behind `{obs}`")
                    st.json(records[record_id]["payload"], expanded=2)
                if len(shown) >= 4:
                    break


render()
