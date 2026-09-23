"""Stage 5 SYNTHESISE -- deterministic projections of the closed graph (T24, T26, T27).

Timeline, scope of compromise, the coverage-gap report, the privilege report,
the Attack Flow export and the Navigator layer. All **projections** under SS8.3:
derived, never authoritative, always regenerable.

**Absence-based conclusions are computed only here**, after the graph closes.
They cannot be emitted during the loop, because a later iteration may find what
an earlier one declared unobserved, and closed-world claims are not monotone
under a growing accepted set.
"""

from __future__ import annotations

from collections import Counter, defaultdict
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


def timeline(findings: list[dict], observations: list[dict], mappings: list[dict]) -> dict[str, Any]:
    """One row per finding, in recorded-time order, with its evidence and technique."""
    by_id = {observation["id"]: observation for observation in observations}
    mapping_by_finding: dict[str, list[dict]] = defaultdict(list)
    for mapping in mappings:
        mapping_by_finding[mapping["finding"]].append(mapping)

    rows = []
    for finding in findings:
        cited = [by_id[obs] for obs in finding["cites_observations"] if obs in by_id]
        if not cited:
            continue
        times = sorted(observation["recorded_time"] for observation in cited)
        rows.append(
            {
                "finding": finding["id"],
                "stage": finding["stage"],
                "statement": finding["statement"],
                "support": finding["support"],
                "first_recorded_time": times[0],
                "last_recorded_time": times[-1],
                "event_ids": finding["event_ids"],
                "source_types": finding["source_types"],
                "techniques": [
                    {
                        "technique_id": mapping["technique_id"],
                        "technique_name": mapping["technique_name"],
                        "tactics": mapping["tactics"],
                    }
                    for mapping in mapping_by_finding.get(finding["id"], [])
                ],
                "cites_observations": finding["cites_observations"],
                "cites_edges": finding["cites_edges"],
            }
        )

    rows.sort(key=lambda row: (row["first_recorded_time"], row["finding"]))
    return {
        "steps": rows,
        "count": len(rows),
        "window": {
            "first": rows[0]["first_recorded_time"] if rows else None,
            "last": rows[-1]["last_recorded_time"] if rows else None,
        },
        # The honest empty case: no intrusion reconstructed is a valid result,
        # and must read as one rather than as an empty page.
        "no_reconstruction": not rows,
    }


def scope(findings: list[dict], observations: list[dict], entities: list[dict]) -> dict[str, Any]:
    """Which accounts, hosts and assets the reconstruction touches.

    `confirmed` means an accepted finding cites an observation naming it.
    `observed` means it appears in the data at all. The difference is the whole
    point: what cannot be ruled out is stated, not folded into the confirmed set.
    """
    by_id = {observation["id"]: observation for observation in observations}
    by_record: dict[str, list[dict]] = defaultdict(list)
    for observation in observations:
        by_record[observation["record"]].append(observation)
    involved: dict[str, dict[str, Any]] = {}

    for finding in findings:
        # Scope walks from the cited observation to its *record*, then to every
        # named entity on that record. A finding citing a process image on
        # WKSTN-07 implicates WKSTN-07 -- the host is in the blast radius even
        # though the finding cited the process, and reading only the exact
        # cited observation would report an empty scope for a real finding.
        cited_records = {
            by_id[obs]["record"] for obs in finding["cites_observations"] if obs in by_id
        }
        for observation in (o for record in cited_records for o in by_record[record]):
            if observation["entity_type"] is None:
                continue
            if observation["entity_type"] not in ("account", "host", "address", "file", "bucket", "service"):
                continue
            key = f"{observation['entity_type']}:{observation['normalised_value']}"
            entry = involved.setdefault(
                key,
                {
                    "entity_type": observation["entity_type"],
                    "value": observation["normalised_value"],
                    "findings": set(),
                    "event_ids": set(),
                    "source_types": set(),
                    "first": observation["recorded_time"],
                    "last": observation["recorded_time"],
                },
            )
            entry["findings"].add(finding["id"])
            entry["event_ids"].add(observation["event_id"])
            entry["source_types"].add(observation["source_type"])
            entry["first"] = min(entry["first"], observation["recorded_time"])
            entry["last"] = max(entry["last"], observation["recorded_time"])

    coverage_by_value = {entity["value"]: entity["coverage"] for entity in entities}
    rows = []
    for entry in involved.values():
        rows.append(
            {
                "entity_type": entry["entity_type"],
                "value": entry["value"],
                "confirmed": True,
                "finding_count": len(entry["findings"]),
                "findings": sorted(entry["findings"]),
                "event_ids": sorted(entry["event_ids"]),
                "source_types": sorted(entry["source_types"]),
                "first_involvement": entry["first"],
                "last_involvement": entry["last"],
                "absent_from_sources": coverage_by_value.get(entry["value"], {}).get("absent_from", []),
            }
        )
    rows.sort(key=lambda row: (row["entity_type"], row["value"]))

    all_hosts = sorted(
        entity["value"] for entity in entities if entity["entity_type"] == "host"
    )
    confirmed_hosts = sorted(row["value"] for row in rows if row["entity_type"] == "host")
    return {
        "involved": rows,
        "counts": dict(sorted(Counter(row["entity_type"] for row in rows).items())),
        "cannot_be_ruled_out": {
            "hosts_observed_but_not_implicated": [
                host for host in all_hosts if host not in confirmed_hosts
            ],
            "_note": (
                "Observed in the data but cited by no accepted finding. Not exonerated -- "
                "endpoint coverage is uneven, so further spread cannot be ruled out."
            ),
        },
    }


def privilege_report(findings: list[dict], observations: list[dict], mappings: list[dict]) -> dict[str, Any]:
    """How privilege changed, as a deterministic projection (T24).

    The dataset contains **no exploit-based escalation**. Integrity rises
    medium -> high -> SYSTEM through stolen credentials and service execution,
    so the report names those mechanisms and explicitly records that T1068 is
    not evidenced. A report that inferred an exploit from rising integrity would
    be closing a gap with inference.
    """
    levels = [
        observation
        for observation in observations
        if observation["field"] == "integrity_level"
    ]
    by_host: dict[str, list[dict]] = defaultdict(list)
    host_of: dict[str, str] = {}
    for observation in observations:
        if observation["field"] == "hostname":
            host_of[observation["record"]] = str(observation["normalised_value"])
    for observation in levels:
        host = host_of.get(observation["record"], "unknown")
        by_host[host].append(observation)

    rank = {"low": 0, "medium": 1, "high": 2, "system": 3}
    transitions = []
    for host, group in sorted(by_host.items()):
        group.sort(key=lambda o: o["recorded_time"])
        seen = []
        for observation in group:
            level = str(observation["normalised_value"])
            if not seen or seen[-1]["level"] != level:
                seen.append(
                    {
                        "level": level,
                        "rank": rank.get(level, -1),
                        "event_id": observation["event_id"],
                        "recorded_time": observation["recorded_time"],
                        "observation": observation["id"],
                    }
                )
        rises = [
            {"from": seen[i]["level"], "to": seen[i + 1]["level"], "at": seen[i + 1]["recorded_time"],
             "event_id": seen[i + 1]["event_id"], "observation": seen[i + 1]["observation"]}
            for i in range(len(seen) - 1)
            if seen[i + 1]["rank"] > seen[i]["rank"]
        ]
        if seen:
            transitions.append(
                {"host": host, "levels_observed": seen, "rises": rises, "highest": max(seen, key=lambda s: s["rank"])["level"]}
            )

    mapped = {mapping["technique_id"] for mapping in mappings}
    return {
        "per_host": transitions,
        "mechanisms_evidenced": sorted(
            mapped & {"T1078", "T1569.002", "T1134", "T1543.003"}
        ),
        "exploit_based_escalation": {
            "evidenced": False,
            "techniques_deliberately_not_mapped": ["T1068"],
            "_why": (
                "Integrity rises through stolen credentials and service execution, both of "
                "which are evidenced. No record shows exploitation of a vulnerability, and "
                "inferring one from rising integrity would close a gap with inference. "
                "T1068 is present in the catalogue and is deliberately absent from every "
                "mapping."
            ),
        },
        "t1068_absent_from_mappings": "T1068" not in mapped,
    }


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
