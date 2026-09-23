"""Stage 1 INGEST -- verbatim load, `note` stripped at the boundary (T10).

Two properties matter here and nothing else does.

**`note` is removed at the parse boundary**, not filtered downstream. It is the
dataset's answer key (22 of 242 events carry it, and they are exactly the 22
intrusion events), so anything that can see it can score perfectly while
demonstrating nothing. Stripping it here means no later stage -- deterministic
or model -- *can* read it, rather than being trusted not to.

**Field presence is data, not a parse error.** There are 14 logical
`source_type`/`event_name` kinds, but shapes vary *within* a kind through
optional fields: `network_connection` alone has three key-set sizes (80 records
at 12 keys, 3 at 14, 1 at 15). A strict one-schema-per-kind parser would reject
the 4 richest records -- which are the only ones naming their hosts outright,
and so the only ones needing no address resolution at all. So the per-kind
schema names required fields and *inventories* the rest.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from .. import ids, jsonl, paths

#: Present on every record, whatever the source.
UNIVERSAL_FIELDS = ("event_id", "source_type", "timestamp", "event_name")

#: The developer annotation. Removed here and nowhere else.
ANNOTATION_FIELD = "note"

#: Required per source type. Everything else a record carries is optional and
#: recorded in the census rather than demanded.
REQUIRED_BY_SOURCE: dict[str, tuple[str, ...]] = {
    "network": ("src_ip", "dst_ip", "dst_port", "protocol"),
    "endpoint": ("hostname",),
    "auth": ("username", "result"),
    "cloud_storage": ("username", "bucket", "action"),
}

#: Internal address space, from the dataset's own metadata.
INTERNAL_PREFIX = "10."


class IngestError(ValueError):
    """A record cannot be loaded at all -- a missing universal field."""


def classify_address(value: str | None) -> str | None:
    """`internal` / `external` for an IPv4 string, or None if absent.

    Derived from the dataset's own stated address space rather than from a
    guess about what looks private.
    """
    if not value:
        return None
    return "internal" if value.startswith(INTERNAL_PREFIX) else "external"


def strip_annotation(event: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """`(record without `note`, whether one was present)`."""
    if ANNOTATION_FIELD not in event:
        return dict(event), False
    stripped = {key: value for key, value in event.items() if key != ANNOTATION_FIELD}
    return stripped, True


def load_raw(path: Path | None = None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    payload = jsonl.read_json(path or paths.RAW_LOGS)
    return payload["metadata"], payload["events"]


def build_records(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One record node per event, `note` already gone.

    The payload is retained byte-for-byte apart from the annotation, so a
    citation can always be resolved back to what the source actually said.
    """
    records = []
    for event in events:
        missing = [field for field in UNIVERSAL_FIELDS if field not in event]
        if missing:
            raise IngestError(f"{event.get('event_id', '<no id>')}: missing {missing}")

        payload, had_annotation = strip_annotation(event)
        source_type = payload["source_type"]
        records.append(
            {
                "id": ids.record_id(
                    source_type=source_type, event_id=payload["event_id"], payload=payload
                ),
                "event_id": payload["event_id"],
                "source_type": source_type,
                "event_name": payload["event_name"],
                "recorded_time": payload["timestamp"],
                "kind": f"{source_type}/{payload['event_name']}",
                "payload": payload,
                "annotation_stripped": had_annotation,
                "address_class": {
                    field: classify_address(payload.get(field))
                    for field in ("src_ip", "dst_ip", "source_ip", "dest_ip")
                    if payload.get(field)
                },
            }
        )
    return records


def ingest_report(
    metadata: dict[str, Any], events: list[dict[str, Any]], records: list[dict[str, Any]]
) -> dict[str, Any]:
    keys = Counter()
    for record in records:
        keys.update(record["payload"].keys())

    kinds = Counter(record["kind"] for record in records)
    schema_notes = {}
    for kind in sorted(kinds):
        of_kind = [r for r in records if r["kind"] == kind]
        required = REQUIRED_BY_SOURCE.get(of_kind[0]["source_type"], ())
        present_everywhere = set(of_kind[0]["payload"])
        for record in of_kind[1:]:
            present_everywhere &= set(record["payload"])
        schema_notes[kind] = {
            "records": len(of_kind),
            "required_present_in_all": all(
                field in record["payload"] for record in of_kind for field in required
            ),
            "key_set_sizes": dict(sorted(Counter(len(r["payload"]) for r in of_kind).items())),
            "fields_in_every_record": sorted(present_everywhere),
        }

    return {
        "source": paths.relative(paths.RAW_LOGS),
        "incident_ref": metadata.get("incident_ref"),
        "collection_window": {
            "start": metadata.get("collection_window_start"),
            "end": metadata.get("collection_window_end"),
        },
        "counts": {
            "events_in": len(events),
            "records_out": len(records),
            "annotations_stripped": sum(1 for r in records if r["annotation_stripped"]),
            "by_source_type": dict(sorted(Counter(r["source_type"] for r in records).items())),
            "by_kind": dict(sorted(kinds.items())),
        },
        "field_census": {
            "distinct_keys": len(keys),
            "present": dict(sorted(keys.items())),
            "absent": {key: len(records) - n for key, n in sorted(keys.items())},
        },
        "absence_encodings": {
            # Three different facts, deliberately not collapsed.
            field: {
                "absent": sum(1 for r in records if field not in r["payload"]),
                "empty_string": sum(1 for r in records if r["payload"].get(field) == ""),
                "null": sum(
                    1 for r in records if field in r["payload"] and r["payload"][field] is None
                ),
                "valued": sum(1 for r in records if r["payload"].get(field)),
            }
            for field in ("command_line", "src_host", "dst_host", "file_size_bytes")
        },
        "per_kind_schema": schema_notes,
        "address_classes": dict(
            sorted(
                Counter(
                    cls
                    for record in records
                    for cls in record["address_class"].values()
                    if cls
                ).items()
            )
        ),
    }


def run(raw_path: Path | None = None, *, write: bool = True) -> tuple[list[dict], dict]:
    metadata, events = load_raw(raw_path)
    records = build_records(events)
    report = ingest_report(metadata, events, records)
    if write:
        jsonl.write(paths.RECORDS, records)
        jsonl.write_json(paths.INGEST_REPORT, report)
    return records, report
