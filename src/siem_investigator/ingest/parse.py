"""Stage 2b -- role-tagged entities, computed coverage, ambiguous resolution (T12).

**Roles, not a flat host field.** Two of the four sources are directional: an
`auth` event has a source host and a dest host, a `network` flow has both ends.
Flattening either into one `host` would destroy the direction the whole
reconstruction depends on. So every entity reference carries a role --
`actor`, `observed_on`, `origin`, `target` -- over a typed entity.

`observed_on` stays distinct from `actor` because it is what makes **coverage
computable** rather than asserted: "which source types carry records *about*
this host" is a different question from "which account acted".

**Address resolution returns candidates, never one answer.** Measured in this
dataset: `WKSTN-01` and `WKSTN-06` each appear with 9 different addresses, and
`10.0.3.78` maps to both `WKSTN-04` and `WKSTN-10`. Only the three compromised
hosts have a single stable address -- which is itself a fact a resolver must not
be allowed to exploit, since preferring unambiguous mappings would rediscover
the intrusion by construction. Every resolution carries its full candidate set
and an `ambiguous` flag.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .. import ids, jsonl, paths
from . import transforms

#: `(field, entity type, role, transform)` per source type.
#:
#: The transform is part of the mapping rather than inferred from the value,
#: because two fields holding the same-looking string can mean different things
#: -- `process_name` is already a basename, `process_path` is not.
FIELD_ROLES: dict[str, tuple[tuple[str, str, str, str], ...]] = {
    "endpoint": (
        ("username", "account", "actor", "lower"),
        ("hostname", "host", "observed_on", "lower"),
        ("process_name", "process", "target", "lower"),
        ("parent_process", "process", "origin", "lower"),
        # A process image, not a data file: typing it `file` would make `same_file`
        # collide every svchost.exe in the estate (measured: 1,299 pairs) and drown
        # the one cross-source file relation that matters.
        # A path, kept as a path. Its basename is *not* a process identity:
        # many background records carry a directory only, so `C:\Program
        # Files\Slack\` became the "process" `slack` and a later stage read the
        # name/path mismatch as masquerading. A directory is not a process image
        # and must not be typed as one.
        ("process_path", "path", "target", "basename"),
        ("file_path", "file", "target", "basename"),
        ("file_size_bytes", "size", "target", "integer"),
        ("service_name", "service", "target", "lower"),
        ("service_path", "file", "target", "basename"),
        ("target_process", "process", "target", "lower"),
        ("command_line", "command", "target", "identity"),
        ("pid", "pid", "target", "integer"),
        ("target_pid", "pid", "target", "integer"),
        ("integrity_level", "integrity", "target", "lower"),
        # The only non-empty field in the dataset with no observation at all,
        # and it happens to be the one that says what a process asked LSASS
        # for. Its absence weakened the credential-access evidence.
        ("access_rights", "access_rights", "target", "lower"),
    ),
    "auth": (
        ("username", "account", "actor", "lower"),
        ("source_host", "host", "origin", "lower"),
        ("dest_host", "host", "target", "lower"),
        ("source_ip", "address", "origin", "ipv4_canonical"),
        ("dest_ip", "address", "target", "ipv4_canonical"),
        ("logon_type", "logon_type", "target", "lower"),
        ("result", "result", "target", "lower"),
    ),
    "network": (
        ("src_ip", "address", "origin", "ipv4_canonical"),
        ("dst_ip", "address", "target", "ipv4_canonical"),
        ("src_host", "host", "origin", "lower"),
        ("dst_host", "host", "target", "lower"),
        ("dst_port", "port", "target", "integer"),
        ("protocol", "protocol", "target", "lower"),
        ("bytes_sent", "size", "target", "integer"),
        ("bytes_recv", "size", "target", "integer"),
        ("action", "action", "target", "lower"),
        ("firewall_rule", "rule", "target", "lower"),
    ),
    "cloud_storage": (
        ("username", "account", "actor", "lower"),
        ("source_host", "host", "origin", "lower"),
        ("source_ip", "address", "origin", "ipv4_canonical"),
        ("bucket", "bucket", "target", "lower"),
        # An ownership *classification* in this dataset (`EXTERNAL`), not a
        # named principal. Typed as an account, it appeared in the blast radius
        # as a compromised user called "external".
        ("bucket_owner", "owner_class", "target", "lower"),
        ("file_name", "file", "target", "basename"),
        ("file_size_bytes", "size", "target", "integer"),
        ("action", "action", "target", "lower"),
        ("user_agent", "user_agent", "target", "identity"),
    ),
}

#: Entity types that name a thing in the estate, as opposed to a property of an
#: event. Coverage and resolution are computed over these only -- "which
#: sources cover port 445" is not a meaningful question.
NAMED_ENTITY_TYPES = frozenset({"account", "host", "address", "process", "file", "bucket", "service"})

#: Fields that pair a host with an address *within one record*, which is the
#: only evidence in this dataset for an address-to-host mapping.
ADDRESS_HOST_PAIRS: dict[str, tuple[tuple[str, str], ...]] = {
    "auth": (("source_ip", "source_host"), ("dest_ip", "dest_host")),
    "cloud_storage": (("source_ip", "source_host"),),
    "network": (("src_ip", "src_host"), ("dst_ip", "dst_host")),
}


def parse_records(records: list[dict[str, Any]]) -> tuple[list[dict], list[dict], list[dict]]:
    """`(events, provenance entries, entity references)`.

    One event per record, carrying its role-tagged references. Provenance is
    emitted for every value, `identity` included.
    """
    events: list[dict] = []
    provenance: list[dict] = []
    references: list[dict] = []

    for record in records:
        payload = record["payload"]
        mapping = FIELD_ROLES.get(record["source_type"], ())

        # The recorded time goes through `utc_instant` like any other value, so
        # the mixed precisions in the source become one comparable scale with
        # the transform that did it on the record.
        normalised_time = transforms.apply("utc_instant", record["recorded_time"])
        provenance.append(
            {
                "id": ids.node_id(
                    "obs",
                    {
                        "record": record["id"],
                        "field": "timestamp",
                        "normalised_value": normalised_time,
                        "transform": "utc_instant",
                    },
                ),
                "record": record["id"],
                "field": "timestamp",
                "raw_value": record["recorded_time"],
                "transform": "utc_instant",
                "normalised_value": normalised_time,
            }
        )

        event_references = []
        for field, entity_type, role, transform_name in mapping:
            if field not in payload:
                continue
            raw_value = payload[field]
            if raw_value is None or raw_value == "":
                # Present but empty is a fact about the source, not a value to
                # assert. Recorded in the ingest census; no observation here.
                continue
            normalised = transforms.apply(transform_name, raw_value)
            if normalised is None:
                # The transform could not normalise it. The observation is
                # withheld rather than guessed at.
                continue

            provenance.append(
                {
                    "id": ids.node_id(
                        "obs",
                        {
                            "record": record["id"],
                            "field": field,
                            "normalised_value": normalised,
                            "transform": transform_name,
                        },
                    ),
                    "record": record["id"],
                    "field": field,
                    "raw_value": raw_value,
                    "transform": transform_name,
                    "normalised_value": normalised,
                }
            )
            reference = {
                "record": record["id"],
                "event_id": record["event_id"],
                "source_type": record["source_type"],
                "field": field,
                "entity_type": entity_type,
                "role": role,
                "value": normalised,
            }
            event_references.append(reference)
            references.append(reference)

        events.append(
            {
                "id": record["id"],
                "event_id": record["event_id"],
                "source_type": record["source_type"],
                "event_name": record["event_name"],
                "kind": record["kind"],
                "recorded_time": record["recorded_time"],
                "normalised_time": normalised_time,
                "references": [
                    {k: v for k, v in reference.items() if k in ("field", "entity_type", "role", "value")}
                    for reference in event_references
                ],
            }
        )

    return events, provenance, references


def entities(references: list[dict]) -> list[dict]:
    """One node per named entity, with its **computed** source coverage.

    Coverage is derived from which source types carry a reference to the entity
    in any role, plus which carry it as `observed_on`. The second is the
    stronger notion: a host that only ever appears as the far end of a flow is
    mentioned, not covered.
    """
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for reference in references:
        if reference["entity_type"] not in NAMED_ENTITY_TYPES:
            continue
        key = (reference["entity_type"], reference["value"])
        entry = grouped.setdefault(
            key,
            {
                "entity_type": reference["entity_type"],
                "value": reference["value"],
                "mentioned_in": set(),
                "observed_on_in": set(),
                "roles": set(),
                "records": set(),
            },
        )
        entry["mentioned_in"].add(reference["source_type"])
        entry["roles"].add(reference["role"])
        entry["records"].add(reference["record"])
        if reference["role"] == "observed_on":
            entry["observed_on_in"].add(reference["source_type"])

    all_sources = sorted({reference["source_type"] for reference in references})
    out = []
    for (entity_type, value), entry in grouped.items():
        mentioned = sorted(entry["mentioned_in"])
        out.append(
            {
                "id": ids.node_id("obs", {"entity_type": entity_type, "value": value}),
                "entity_type": entity_type,
                "value": value,
                "roles": sorted(entry["roles"]),
                "record_count": len(entry["records"]),
                "coverage": {
                    "mentioned_in": mentioned,
                    "observed_on_in": sorted(entry["observed_on_in"]),
                    # What makes NOT_FOUND meaningful: without this, "no record"
                    # conflates absence from the estate with blindness of the
                    # source.
                    "absent_from": [source for source in all_sources if source not in mentioned],
                },
            }
        )
    return sorted(out, key=lambda row: (row["entity_type"], row["value"]))


def resolve_addresses(references: list[dict]) -> list[dict]:
    """Address-to-host candidates, with ambiguity stated.

    Built only from records that name an address and a host *together*, which
    is the only evidence available. Every entry keeps its full candidate set:
    the resolver never collapses to one answer, because in this dataset doing so
    would be wrong
    for most hosts and would accidentally single out the compromised ones.
    """
    by_record: dict[str, dict[str, str]] = defaultdict(dict)
    source_of: dict[str, str] = {}
    for reference in references:
        by_record[reference["record"]][reference["field"]] = reference["value"]
        source_of[reference["record"]] = reference["source_type"]

    pairs: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for record, fields in by_record.items():
        for address_field, host_field in ADDRESS_HOST_PAIRS.get(source_of[record], ()):
            address = fields.get(address_field)
            host = fields.get(host_field)
            if address and host:
                pairs[address][host].add(record)

    out = []
    for address in sorted(pairs):
        candidates = pairs[address]
        rows = [
            {"host": host, "evidence_records": sorted(records), "record_count": len(records)}
            for host, records in sorted(candidates.items())
        ]
        out.append(
            {
                "id": ids.node_id("obs", {"resolution_for": address}),
                "address": address,
                "candidates": rows,
                "candidate_count": len(rows),
                "ambiguous": len(rows) > 1,
            }
        )
    return out


def parse_report(events: list[dict], provenance: list[dict], entity_nodes: list[dict], resolution: list[dict]) -> dict:
    from collections import Counter

    invariant_failures = transforms.check_all(provenance)
    return {
        "counts": {
            "events": len(events),
            "provenance_entries": len(provenance),
            "entities": len(entity_nodes),
            "addresses_resolved": len(resolution),
        },
        "invariant_5_reproducibility": {
            "checked": len(provenance),
            "failures": invariant_failures,
            "holds": not invariant_failures,
        },
        "transforms_used": dict(sorted(Counter(p["transform"] for p in provenance).items())),
        "entities_by_type": dict(sorted(Counter(e["entity_type"] for e in entity_nodes).items())),
        "address_resolution": {
            "total": len(resolution),
            "ambiguous": sum(1 for row in resolution if row["ambiguous"]),
            "unambiguous": sum(1 for row in resolution if not row["ambiguous"]),
            "max_candidates": max((row["candidate_count"] for row in resolution), default=0),
            "_note": (
                "Only three hosts have a single stable address, and those are the "
                "compromised ones. Preferring unambiguous mappings would therefore "
                "rediscover the intrusion by construction, which is why every "
                "resolution keeps its full candidate set."
            ),
        },
        "coverage_gaps": [
            {"entity_type": entity["entity_type"], "value": entity["value"], "absent_from": entity["coverage"]["absent_from"]}
            for entity in entity_nodes
            if entity["entity_type"] == "host" and entity["coverage"]["absent_from"]
        ],
    }


def run(records: list[dict], *, write: bool = True) -> dict[str, Any]:
    events, provenance, references = parse_records(records)
    entity_nodes = entities(references)
    resolution = resolve_addresses(references)
    report = parse_report(events, provenance, entity_nodes, resolution)
    if write:
        jsonl.write(paths.EVENTS, events)
        jsonl.write(paths.ENTITIES, entity_nodes)
        jsonl.write(paths.RESOLUTION, resolution)
        jsonl.write_json(paths.PARSE_REPORT, report)
    return {
        "events": events,
        "provenance": provenance,
        "references": references,
        "entities": entity_nodes,
        "resolution": resolution,
        "report": report,
    }
