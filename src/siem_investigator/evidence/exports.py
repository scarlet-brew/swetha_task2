"""The two standards-based exports (D-04, T45).

Split from `synthesise.py` because they are a different kind of thing. The
timeline, the scope and the gap report are what the system *concluded*; these
two are that conclusion re-expressed in someone else's vocabulary so other
tools can read it.

Both are **projections** under SS8.3: the export comes from the graph, and the
graph is never reconstructed from an export. That is the property that makes
"delete every export, regenerate, get byte-identical output" a meaningful test
-- a failure means something authoritative leaked into a projection.

Attack Flow is a projection here and deliberately not the internal model.
Three of the five node kinds and all ten factual relations have no equivalent
in it, its edges cannot express "these two observations share a value", and
every published corpus entry was hand-authored after the fact by someone who
already knew the answer. Adopting it internally would shape the investigation
around how the conclusion gets published.
"""

from __future__ import annotations

from collections import Counter
from typing import Any


def attack_flow(findings: list[dict], mappings: list[dict], attack_version: str) -> dict[str, Any]:
    """Vanilla Attack Flow plus an `evidence_refs` extension (D-04).

    A **projection**: the export comes from the graph and the graph is never
    reconstructed from the export. Ids are content-derived rather than STIX
    uuidv4, which is the one place this deviates deliberately -- uuidv4 would
    forfeit content-hash immutability and destroy diffability.
    """
    mapping_by_finding = {mapping["finding"]: mapping for mapping in mappings}
    objects: list[dict] = [
        {
            "type": "attack-flow",
            "spec_version": "2.1",
            "id": "attack-flow--" + ("0" * 8) + "-0000-4000-8000-" + ("0" * 12),
            "name": "INC-2026-0610-001 reconstruction",
            "description": (
                "Projection of the investigation graph. Derived, never authoritative; "
                "regenerable from data/derived/03_findings.jsonl."
            ),
            "start_refs": [],
            "attack_version": attack_version,
        }
    ]
    for finding in findings:
        mapping = mapping_by_finding.get(finding["id"])
        objects.append(
            {
                "type": "attack-action",
                "spec_version": "2.1",
                "id": f"attack-action--{finding['id']}",
                "name": finding["statement"][:120],
                "tactic_id": finding["stage"],
                **(
                    {
                        "technique_id": mapping["technique_id"],
                        "technique_ref": mapping["technique_ref"],
                    }
                    if mapping
                    else {}
                ),
                # The extension: every action points back at the evidence.
                "evidence_refs": {
                    "finding": finding["id"],
                    "observations": finding["cites_observations"],
                    "edges": finding["cites_edges"],
                    "event_ids": finding["event_ids"],
                    "support": finding["support"],
                },
            }
        )
    return {"type": "bundle", "id": "bundle--attack-flow-projection", "objects": objects}


def navigator_layer(mappings: list[dict], attack_version: str) -> dict[str, Any]:
    """An ATT&CK Navigator layer (format 4.5). Projection only."""
    counts = Counter(mapping["technique_id"] for mapping in mappings)
    return {
        "name": "INC-2026-0610-001",
        "versions": {"layer": "4.5", "navigator": "5.1.0", "attack": attack_version},
        "domain": "enterprise-attack",
        "description": "Techniques mapped from accepted findings. Derived projection.",
        "techniques": [
            {
                "techniqueID": technique_id,
                "score": count,
                "comment": "; ".join(
                    sorted(
                        {
                            mapping["technique_name"]
                            for mapping in mappings
                            if mapping["technique_id"] == technique_id
                        }
                    )
                ),
            }
            for technique_id, count in sorted(counts.items())
        ],
        "gradient": {"colors": ["#F0E6D2", "#453D34"], "minValue": 0, "maxValue": max(counts.values(), default=1)},
    }
