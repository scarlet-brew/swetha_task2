"""Close the graph: support labels, the two flags, check 6 (T25).

**Labels are computed, never asserted.** Corroborated / Single-sourced /
Absence-based come from the count of distinct source types across a finding's
supporting observations. A model-asserted support label would be an opinion
wearing the clothes of a measurement, and R3.4 forbids the numbers that would
otherwise creep in. Recomputing also means mutating a label in an artifact and
regenerating restores it.

**Check 6 runs only at close**, because mutual incompatibility is a *set-level*
property: two findings can each be individually valid and jointly inconsistent.
It reports the incompatibility citing every record on both sides rather than
silently preferring one.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

#: The four support states (SS9.1). Words, not scores.
LABELS = ("corroborated", "single_sourced", "absence_based", "conflicted")

#: Fields whose values contradict each other if two observations of the same
#: record-entity disagree. Used by the conflict flag.
_SINGLE_VALUED = ("result", "integrity_level", "action")


def label_for(finding: dict, observations: dict[str, dict]) -> tuple[str, list[str]]:
    """`(label, flags)` for one finding, from the evidence structure alone."""
    cited = [observations[obs] for obs in finding["cites_observations"] if obs in observations]
    sources = {observation["source_type"] for observation in cited}

    flags: list[str] = []

    # `resolution_dependent`: the finding leans on an address-to-host
    # association that has more than one candidate.
    if finding.get("resolution_dependent"):
        flags.append("resolution_dependent")

    # `conflicted`: two cited observations of the same single-valued field
    # disagree.
    by_field: dict[str, set[Any]] = defaultdict(set)
    for observation in cited:
        if observation["field"] in _SINGLE_VALUED:
            by_field[observation["field"]].add(observation["normalised_value"])
    conflicted = any(len(values) > 1 for values in by_field.values())
    if conflicted:
        flags.append("conflicted")

    if finding.get("absence_based"):
        return "absence_based", flags
    if conflicted:
        return "conflicted", flags
    if len(sources) >= 2:
        return "corroborated", flags
    return "single_sourced", flags


def apply_labels(findings: list[dict], observations: list[dict]) -> list[dict]:
    by_id = {observation["id"]: observation for observation in observations}
    out = []
    for finding in findings:
        label, flags = label_for(finding, by_id)
        out.append({**finding, "support": {"label": label, "flags": flags}})
    return out


def incompatibilities(findings: list[dict]) -> list[dict]:
    """Check 6 -- pairs of accepted findings that cannot both hold.

    Two findings are treated as incompatible when they assign the *same* cited
    observation set to different stages: one body of evidence cannot be two
    stages of the intrusion at once. Reported with every record on both sides.
    """
    by_evidence: dict[tuple[str, ...], list[dict]] = defaultdict(list)
    for finding in findings:
        by_evidence[tuple(sorted(finding["cites_observations"]))].append(finding)

    reports = []
    for evidence, group in sorted(by_evidence.items()):
        stages = {finding["stage"] for finding in group}
        if len(stages) > 1:
            reports.append(
                {
                    "kind": "same_evidence_different_stage",
                    "stages": sorted(stages),
                    "findings": [
                        {"id": f["id"], "stage": f["stage"], "statement": f["statement"]}
                        for f in group
                    ],
                    "cited_observations": list(evidence),
                    "event_ids": sorted({e for f in group for e in f["event_ids"]}),
                    "_note": (
                        "Reported, not resolved. Preferring one silently would hide a "
                        "genuine inconsistency in the reconstruction (R3.11)."
                    ),
                }
            )
    return reports


def close(findings: list[dict], observations: list[dict]) -> dict[str, Any]:
    labelled = apply_labels(findings, observations)
    conflicts = incompatibilities(labelled)
    from collections import Counter

    return {
        "findings": labelled,
        "check_6_mutual_compatibility": {
            "incompatibilities": conflicts,
            "holds": not conflicts,
            "_when": "at close only -- compatibility is a set-level property",
        },
        "support_distribution": dict(
            sorted(Counter(finding["support"]["label"] for finding in labelled).items())
        ),
        "flags": dict(
            sorted(
                Counter(
                    flag for finding in labelled for flag in finding["support"]["flags"]
                ).items()
            )
        ),
    }
