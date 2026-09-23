"""Direct observations -- the bottom of the evidence chain (T13).

An observation asserts that a **normalised value appears at a named field of a
named record**, and carries the transform that produced it. That is the whole
claim: nothing interpretive, and invariant 4 (grounding) is decidable by
re-reading the record.

Observations are the only node kind that cites a record, and records cite
nothing -- which is what makes invariant 2 (termination) hold by construction
rather than by check.
"""

from __future__ import annotations

from typing import Any

from .. import ids


def build(records: list[dict], provenance: list[dict], references: list[dict]) -> list[dict]:
    """Join provenance (how a value was produced) with references (what it means).

    Kept as a join rather than emitted in one pass because the two carry
    different kinds of fact: provenance is about reproducibility, the reference
    is about role and entity type. A value can have provenance and no entity
    role -- the record timestamp, for instance -- and that is not a defect.
    """
    record_by_id = {record["id"]: record for record in records}
    role_by_key: dict[tuple[str, str], dict[str, str]] = {
        (reference["record"], reference["field"]): reference for reference in references
    }

    observations = []
    for entry in provenance:
        record = record_by_id[entry["record"]]
        reference = role_by_key.get((entry["record"], entry["field"]))
        observations.append(
            {
                "id": ids.observation_id(
                    record=entry["record"],
                    field=entry["field"],
                    normalised_value=entry["normalised_value"],
                    transform=entry["transform"],
                ),
                "layer": "observation",
                "record": entry["record"],
                "event_id": record["event_id"],
                "source_type": record["source_type"],
                "event_name": record["event_name"],
                "kind": record["kind"],
                "field": entry["field"],
                "raw_value": entry["raw_value"],
                "transform": entry["transform"],
                "normalised_value": entry["normalised_value"],
                "entity_type": reference["entity_type"] if reference else None,
                "role": reference["role"] if reference else None,
                "recorded_time": record["recorded_time"],
            }
        )
    return observations


def grounding_failures(observations: list[dict], records: list[dict]) -> list[str]:
    """Invariant 4: every asserted value appears at a named field of a cited record.

    Checked by re-reading the record rather than by trusting the pipeline that
    produced the observation.
    """
    record_by_id = {record["id"]: record for record in records}
    failures = []
    for observation in observations:
        record = record_by_id.get(observation["record"])
        if record is None:
            failures.append(f"{observation['id']}: cites missing record {observation['record']}")
            continue
        field = observation["field"]
        if field == "timestamp":
            present = record["recorded_time"]
        elif field in record["payload"]:
            present = record["payload"][field]
        else:
            failures.append(f"{observation['id']}: field {field!r} absent from {record['event_id']}")
            continue
        if present != observation["raw_value"]:
            failures.append(
                f"{observation['id']}: raw value {observation['raw_value']!r} is not what "
                f"{record['event_id']}.{field} holds ({present!r})"
            )
    return failures


def index_by_value(observations: list[dict]) -> dict[tuple[str, Any], list[dict]]:
    """`{(entity_type, normalised value): observations}` -- the relation index.

    Only observations carrying an entity type are indexed; a port number or a
    firewall rule is a property of an event rather than a thing to pivot on.
    """
    index: dict[tuple[str, Any], list[dict]] = {}
    for observation in observations:
        if observation["entity_type"] is None:
            continue
        index.setdefault((observation["entity_type"], observation["normalised_value"]), []).append(
            observation
        )
    return index
