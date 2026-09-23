"""Surface 3 of SS9.4: impact -- hosts, accounts, assets.

An enumeration, so a table (SS9.3). Three things here carry the requirements
that are easiest to fudge and hardest to defend: first and last involvement
(R5.2), confirmed compromise separated from mere observation (R5.3), and **what
cannot be ruled out** (R3.12) -- including hosts that appear in the incident but
about which a relevant source records nothing.

R1.10 constrains one column in particular: an account with no ordinary activity
to compare against is a *limitation on the assessment*, never grounds for it.
The absence of a baseline is not evidence of compromise.
"""

from __future__ import annotations

import json

import streamlit as st
from siem_investigator import paths

from app import artifacts
from app.components import evidence_table


def _load(path):
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def render() -> None:
    st.title("Impact")
    st.caption(
        "Every host and account the incident touched, with first and last involvement, "
        "whether compromise is confirmed or merely observed, and what the data cannot "
        "rule out."
    )

    notice = artifacts.absent_notice(paths.SCOPE)
    if notice:
        st.info(notice, icon=":material/pending:")
        st.caption("Run `python -m siem_investigator.build` to produce it.")
        return

    scope = _load(paths.SCOPE)
    rows = scope.get("involved", [])
    gaps = _load(paths.GAPS)
    privilege = _load(paths.PRIVILEGE)

    if not rows:
        st.warning(
            "No accepted finding cites any entity, so the scope is empty. A result "
            "rather than an error.",
            icon=":material/info:",
        )
        return

    counts = scope.get("counts", {})
    if counts:
        columns = st.columns(len(counts))
        for column, (kind, count) in zip(columns, sorted(counts.items())):
            column.metric(kind.replace("_", " ").title(), count)

    evidence_table.render_table(
        [
            {
                "entity": str(row["value"]),
                "kind": row["entity_type"],
                "assessment": "confirmed - cited by an accepted finding",
                "findings": row["finding_count"],
                "first_involvement": row["first_involvement"],
                "last_involvement": row["last_involvement"],
                "sources": ", ".join(row["source_types"]),
                "absent_from_sources": ", ".join(row["absent_from_sources"]) or "-",
                "events": ", ".join(row["event_ids"][:6]),
            }
            for row in rows
        ],
        columns=(
            "entity",
            "kind",
            "assessment",
            "findings",
            "first_involvement",
            "last_involvement",
            "sources",
            "absent_from_sources",
            "events",
        ),
    )

    st.subheader("What cannot be ruled out")
    cannot = scope.get("cannot_be_ruled_out", {})
    st.markdown(
        "Stated rather than implied. These hosts appear in the data but are cited by no "
        "accepted finding, which is **not** the same as being clear."
    )
    evidence_table.render_table(
        [
            {"host": host, "status": "observed, not implicated by any finding"}
            for host in cannot.get("hosts_observed_but_not_implicated", [])
        ],
        columns=("host", "status"),
        empty_message="Every observed host is cited by at least one finding.",
    )
    if cannot.get("_note"):
        st.caption(cannot["_note"])

    if gaps.get("uneven_host_coverage"):
        st.subheader("Uneven source coverage")
        st.caption(
            "A host absent from a source is invisible to it. That is why an absence of "
            "records is reported as a limit on the assessment rather than as evidence."
        )
        evidence_table.render_table(
            [
                {
                    "host": row["host"],
                    "absent_from": ", ".join(row["absent_from"]),
                    "observed_on_in": ", ".join(row["observed_on_in"]) or "-",
                }
                for row in gaps["uneven_host_coverage"]
            ],
            columns=("host", "absent_from", "observed_on_in"),
        )

    if privilege:
        st.subheader("Privilege")
        escalation = privilege.get("exploit_based_escalation", {})
        st.markdown(
            f"Exploit-based escalation evidenced: **{escalation.get('evidenced')}**. "
            "Deliberately not mapped: "
            + ", ".join(escalation.get("techniques_deliberately_not_mapped", []) or ["-"])
            + "."
        )
        if escalation.get("_why"):
            st.caption(escalation["_why"])
        evidence_table.render_table(
            [
                {
                    "host": host["host"],
                    "highest_observed": host["highest"],
                    "rises": len(host["rises"]),
                    "levels": " -> ".join(level["level"] for level in host["levels_observed"]),
                }
                for host in privilege.get("per_host", [])
            ],
            columns=("host", "highest_observed", "rises", "levels"),
            empty_message="No integrity level is recorded anywhere in the data.",
        )


render()
