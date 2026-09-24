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


def _stix_id(kind: str, seed: str) -> str:
    """A STIX-shaped identifier derived deterministically from content.

    D-04 chose content-derived ids to keep the export diffable and noted that
    STIX's `<type>--<uuidv4>` forfeits that. Both hold at once here: the uuid is
    a uuid**5** over the seed, so it is a valid STIX identifier *and* a pure
    function of the content. Regenerate and the bytes are identical; change a
    finding and only its object's id moves.
    """
    import uuid

    return f"{kind}--{uuid.uuid5(uuid.NAMESPACE_URL, f'siem-investigator:{kind}:{seed}')}"


#: Attack Flow's own extension-definition id, from the published specification.
#: An extension must be declared under `extensions` keyed by this; a bare
#: top-level property fails `unevaluatedProperties` on every object, which is
#: exactly how all 26 objects in the first version of this export failed.
_FLOW_EXTENSION = "extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4"

#: Our own extension, for the evidence pointers. Declared the same way, so the
#: export stays vanilla Attack Flow plus a declared extension rather than
#: Attack-Flow-shaped JSON with extra fields bolted on.
_EVIDENCE_EXTENSION = "extension-definition--" + "6f8d9a51-3c4e-5b2a-9d7f-1e2c3b4a5d6e"


def attack_flow(findings: list[dict], mappings: list[dict], attack_version: str) -> dict[str, Any]:
    """Vanilla Attack Flow plus a declared `evidence_refs` extension (D-04).

    A **projection** under SS8.3: the export comes from the graph and the graph
    is never reconstructed from the export. `tests/test_projections.py`
    validates every object against the vendored schema with its `$ref` closure
    preloaded, so the "validates against the vendored schema" claim is checked
    rather than asserted -- it was false for a while, and unnoticed because
    nothing checked it.

    Timestamps are fixed rather than current: a `created` of "now" would make
    the export differ on every run and break the byte-identical invariant.
    """
    mapping_by_finding = {mapping.get("action_id", mapping["finding"]): mapping
                          for mapping in sorted(mappings,key=lambda m:(m['technique_id'],m['id']))}
    # A presentation group may contain several mapped actions. Export each one
    # instead of silently choosing whichever mapping happened to be read last.
    units = []
    for finding in findings:
        for atomic in finding.get('actions') or [finding]:
            units.append({**finding, **atomic, 'parent_finding':finding['id'],
                'event_ids': sorted(set(atomic.get('subject_event_ids', finding['event_ids']) + atomic.get('context_event_ids', [])))})
    stamp = "2026-06-10T08:00:00.000Z"

    actions: list[dict[str, Any]] = []
    for finding in sorted(units, key=lambda row: (row.get('first_recorded_time',''),row["id"])):
        mapping = mapping_by_finding.get(finding["id"])
        action: dict[str, Any] = {
            "type": "attack-action",
            "spec_version": "2.1",
            "id": _stix_id("attack-action", finding["id"]),
            "created": stamp,
            "modified": stamp,
            "name": finding["statement"][:120],
            "tactic_id": finding["stage"],
            "extensions": {
                _FLOW_EXTENSION: {"extension_type": "new-sdo"},
                _EVIDENCE_EXTENSION: {
                    "extension_type": "property-extension",
                    "evidence_refs": {
                        "finding": finding["parent_finding"],
                        "observations": finding["cites_observations"],
                        "edges": finding["cites_edges"],
                        "event_ids": finding["event_ids"],
                        "support": finding["support"],
                    },
                },
            },
        }
        if mapping:
            action["technique_id"] = mapping["technique_id"]
            action["technique_ref"] = mapping["technique_ref"]
        actions.append(action)

    flow = {
        "type": "attack-flow",
        "spec_version": "2.1",
        "id": _stix_id("attack-flow", "INC-2026-0610-001"),
        "created": stamp,
        "modified": stamp,
        "name": "INC-2026-0610-001 reconstruction",
        "description": (
            "Projection of the investigation graph. Derived, never authoritative; "
            "regenerable from data/derived/03_findings.jsonl."
        ),
        "scope": "incident",
        # Every action, in time order where the graph knows it. Attack Flow
        # wants the causal spine; this export is honest that it publishes the
        # accepted set rather than an inferred causal chain, and `start_refs`
        # names the earliest action rather than claiming a root cause.
        "flow_refs": [action["id"] for action in actions],
        "start_refs": [actions[0]["id"]] if actions else [],
        "extensions": {_FLOW_EXTENSION: {"extension_type": "new-sdo"}},
        "external_references": [
            {"source_name": "mitre-attack", "external_id": f"ATT&CK v{attack_version}"}
        ],
    }

    author = {
        "type": "identity",
        "spec_version": "2.1",
        "id": _stix_id("identity", "siem-investigator"),
        "created": stamp,
        "modified": stamp,
        "name": "siem-investigator",
        "identity_class": "system",
    }

    return {
        "type": "bundle",
        "id": _stix_id("bundle", "INC-2026-0610-001"),
        "objects": [flow, author, *actions],
    }


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
