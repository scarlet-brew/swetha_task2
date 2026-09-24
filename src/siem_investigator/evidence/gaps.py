"""The coverage-gap report (T27).

Split out because it answers a different question from the timeline and the
scope. Those say what happened; this says what the sources could not settle --
and the brief is explicit that a correct "I cannot confirm this because the
logs are absent" beats a fabricated conclusion.

Derived from the hypothesis ledger rather than written by hand: each gap sits
beside the prediction that went looking for it, so a reader sees what was
asked and what came back.
"""

from __future__ import annotations

from typing import Any

#: The gaps CLAUDE.md requires any honest answer to surface. Each is a claim
#: *about the sources*, checked against what was actually ingested rather than
#: hard-coded as prose.
STRUCTURAL_GAPS = (
    {
        "id": "no_mail_source",
        "statement": "No email or mail-gateway source is present.",
        "limits": "the delivery vector cannot be evidenced, only inferred from process lineage",
        "check": ("source_type_absent", "email"),
    },
    {
        "id": "no_dns_source",
        "statement": "No DNS source is present.",
        "limits": "command-and-control is an address with no domain or resolution chain",
        "check": ("source_type_absent", "dns"),
    },
    {
        "id": "no_block_signal",
        "statement": "Every firewall record is an allow.",
        "limits": "there is no block or deny signal to corroborate or contradict any transfer",
        "check": ("all_actions_allowed", "network"),
    },
)




def gaps(
    hypotheses: list[dict],
    entities: list[dict],
    records: list[dict],
    findings: list[dict],
) -> dict[str, Any]:
    """The coverage-gap report -- **derived**, not asserted (T27).

    The unconfirmed and uncoverable hypothesis sets *are* the report: each gap
    appears beside the hypothesis that went looking for it, so a reader can see
    what was predicted and what the search returned. Plus the structural gaps,
    each checked against what was actually ingested.
    """
    source_types = {record["source_type"] for record in records}
    actions = {
        record["payload"].get("action")
        for record in records
        if record["source_type"] == "network"
    }

    structural = []
    for gap in STRUCTURAL_GAPS:
        kind, argument = gap["check"]
        if kind == "source_type_absent":
            holds = argument not in source_types
        elif kind == "all_actions_allowed":
            holds = actions <= {"allowed"}
        else:
            holds = False
        structural.append(
            {
                "id": gap["id"],
                "statement": gap["statement"],
                "limits": gap["limits"],
                "verified": holds,
                "basis": f"{kind}({argument})",
            }
        )

    from_hypotheses = [
        {
            "hypothesis": hypothesis["id"],
            "status": hypothesis["status"],
            "outcome": hypothesis["outcome"],
            "predicted": {
                "entity": hypothesis.get("predicted_entity"),
                "event_kind": hypothesis.get("predicted_event_kind"),
                "source_type": hypothesis.get("predicted_source_type"),
            },
            "statement": (
                f"No {hypothesis.get('predicted_event_kind')} record for "
                f"{hypothesis.get('predicted_entity')} was found"
                + (
                    " -- and no source covers it, so its absence says nothing about the estate."
                    if hypothesis["outcome"] == "not_covered"
                    else " in a source that does cover it."
                )
            ),
            "premised_on": hypothesis["premises"],
        }
        for hypothesis in hypotheses
        if hypothesis["status"] in ("unconfirmed", "uncoverable")
    ]

    host_coverage = [
        {
            "host": entity["value"],
            "absent_from": entity["coverage"]["absent_from"],
            "observed_on_in": entity["coverage"]["observed_on_in"],
        }
        for entity in entities
        if entity["entity_type"] == "host" and entity["coverage"]["absent_from"]
    ]

    return {
        "structural": structural,
        "from_hypotheses": from_hypotheses,
        "uneven_host_coverage": host_coverage,
        "counts": {
            "structural": len(structural),
            "unconfirmed_or_uncoverable_hypotheses": len(from_hypotheses),
            "hosts_with_partial_coverage": len(host_coverage),
        },
        "_note": (
            "Derived from the hypothesis ledger rather than written by hand. A gap here is "
            "something the investigation predicted and did not find, which is why each one "
            "names the hypothesis that went looking."
        ),
    }


# The two standards-based exports live in `exports.py`: re-expressing a
# conclusion in someone else's vocabulary is a different concern from computing
# it. Re-exported so callers need one import.
from .exports import attack_flow, navigator_layer  # noqa: E402,F401

__all__ = [
    "attack_flow",
    "gaps",
    "navigator_layer",
    "privilege_report",
    "scope",
    "timeline",
]
