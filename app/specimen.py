"""A layout specimen: the answer-payload shape, filled with nothing real.

Why this exists. T07 builds the render constraints on day one, before stage 6
exists (T31) and before the chat surface is wired to it (T36). A layout that
cannot be looked at cannot be reviewed, and the nested-expander question cannot
be answered by reading code.

Why it is safe. Every value below is visibly synthetic -- `SPECIMEN-HOST-01`,
`specimen_user`, a year-2000 timestamp, `specimen.invalid` -- and the app
banners it as a specimen wherever it appears. CLAUDE.md's ground rules forbid
inventing incident content, and a plausible-looking fake finding sitting in the
UI until T36 replaced it would be exactly that: a fabricated conclusion with a
citation shape around it. Nothing here can be mistaken for Meridian Health
Partners data, by anyone, at any point in the demo.

What it is for, concretely:

* it exercises all four SS9.1 support states and both R3.3 flags, so the badge
  palette is visible in both themes;
* its first claim carries three citations, which is the T07 check -- three
  citations expanded at once, no nested-expander exception;
* one citation deliberately points at a record id that is absent from the
  bundled records, so R2.9's unresolved-citation path is visible rather than
  theoretical;
* it is the worked example in `docs/specs/answer_payload.md`, so T31 has a
  concrete target rather than a field table alone.
"""

from __future__ import annotations

from typing import Any

#: The record bodies the specimen's citations resolve against. Shaped like a
#: raw record after T10's ingest -- `note` already stripped at the parse
#: boundary, which is why no annotation field appears anywhere here.
SPECIMEN_RECORDS: dict[str, dict[str, Any]] = {
    "rec_000000000001": {
        "id": "rec_000000000001",
        "source_type": "endpoint",
        "event_id": "EVT-9001",
        "timestamp": "2000-01-01T00:00:00.000000Z",
        "event_name": "specimen_process_create",
        "hostname": "SPECIMEN-HOST-01",
        "username": "specimen_user",
        "process_name": "SPECIMEN.EXE",
        "parent_process": "SPECIMEN-PARENT.EXE",
        "integrity_level": "medium",
    },
    "rec_000000000002": {
        "id": "rec_000000000002",
        "source_type": "cloud_storage",
        "event_id": "EVT-9002",
        "timestamp": "2000-01-01T00:05:00.000000Z",
        "event_name": "specimen_file_upload",
        "username": "specimen_user",
        "bucket": "specimen-bucket",
        "bucket_owner": "specimen.invalid",
        "file_name": "specimen_archive.zip",
        "file_size_bytes": 1024,
        "user_agent": "specimen-client/0.0",
    },
    "rec_000000000003": {
        "id": "rec_000000000003",
        "source_type": "network",
        "event_id": "EVT-9003",
        "timestamp": "2000-01-01T00:07:00.000000Z",
        "event_name": "specimen_network_connection",
        "src_ip": "10.255.255.1",
        "dst_ip": "203.0.113.1",
        "dst_port": 443,
        "protocol": "tcp",
        "bytes_sent": 1024,
        "action": "allowed",
    },
}


def specimen_payload() -> dict[str, Any]:
    """One answer payload matching `docs/specs/answer_payload.md`."""
    return {
        "answer_id": "ans_000000000000",
        "question": "(layout specimen) How does a cited answer render?",
        "asked_at": "2000-01-01T00:10:00.000000Z",
        "body": [
            "**This is a layout specimen, not an answer about the incident.** "
            "Every value in it is synthetic and every entity name begins with "
            "`SPECIMEN`. It is here so the citation layout, the four support "
            "states and the unresolved-citation path can be reviewed before "
            "stage 6 exists (T31) and before this surface is wired to it (T36).",
            "Each claim below shows the order the layout imposes: the "
            "statement, what kind of statement it is, the structure of its "
            "support in words, the named basis, then the citations as "
            "expandable siblings of this body.",
        ],
        "claims": [
            {
                "claim_id": "clm_specimen_1",
                "text": (
                    "A claim with three citations drawn from two log sources, "
                    "so its support is Corroborated. Open all three at once: "
                    "they are siblings of this answer body, not children of "
                    "one another."
                ),
                "kind": "finding",
                "support": {
                    "label": "corroborated",
                    "flags": [],
                    "source_types": ["endpoint", "cloud_storage", "network"],
                    "counts": {"observations": 3, "findings": 0, "edges": 2},
                },
                "basis": {
                    "name": "specimen_basis",
                    "requires": "at least two observations from distinct source types",
                    "applies_because": "the three cited observations span three source types",
                },
                "citations": [
                    {
                        "node_id": "obs_000000000001",
                        "layer": "observation",
                        "record_id": "rec_000000000001",
                        "event_id": "EVT-9001",
                        "source_type": "endpoint",
                        "timestamp": "2000-01-01T00:00:00.000000Z",
                        "zone": "UTC",
                        "field": "process_name",
                        "asserted_value": "SPECIMEN.EXE",
                        "open_by_default": True,
                    },
                    {
                        "node_id": "obs_000000000002",
                        "layer": "observation",
                        "record_id": "rec_000000000002",
                        "event_id": "EVT-9002",
                        "source_type": "cloud_storage",
                        "timestamp": "2000-01-01T00:05:00.000000Z",
                        "zone": "UTC",
                        "field": "file_name",
                        "asserted_value": "specimen_archive.zip",
                        "open_by_default": True,
                    },
                    {
                        "node_id": "obs_000000000003",
                        "layer": "observation",
                        "record_id": "rec_000000000003",
                        "event_id": "EVT-9003",
                        "source_type": "network",
                        "timestamp": "2000-01-01T00:07:00.000000Z",
                        "zone": "UTC",
                        "field": "bytes_sent",
                        "asserted_value": 1024,
                        "open_by_default": True,
                    },
                ],
            },
            {
                "claim_id": "clm_specimen_2",
                "text": (
                    "A claim resting on one source type, so its support is "
                    "Single-sourced, and on an address with more than one "
                    "candidate host, so R3.3 adds Resolution-dependent."
                ),
                "kind": "finding",
                "support": {
                    "label": "single_sourced",
                    "flags": ["resolution_dependent"],
                    "source_types": ["network"],
                    "counts": {"observations": 1, "findings": 0, "edges": 0},
                },
                "basis": {
                    "name": "specimen_single_source",
                    "requires": "one observation and a resolved host",
                    "applies_because": "the address resolves to more than one candidate",
                },
                "citations": [
                    {
                        "node_id": "obs_000000000003",
                        "layer": "observation",
                        "record_id": "rec_000000000003",
                        "event_id": "EVT-9003",
                        "source_type": "network",
                        "timestamp": "2000-01-01T00:07:00.000000Z",
                        "zone": "UTC",
                        "field": "src_ip",
                        "asserted_value": "10.255.255.1",
                    }
                ],
            },
            {
                "claim_id": "clm_specimen_3",
                "text": (
                    "A claim whose basis reasons from records not being "
                    "present, so its support is Absence-based and R3.5 forbids "
                    "presenting it as observed fact."
                ),
                "kind": "finding",
                "support": {
                    "label": "absence_based",
                    "flags": [],
                    "source_types": ["endpoint"],
                    "counts": {"observations": 1, "findings": 0, "edges": 0},
                },
                "basis": {
                    "name": "specimen_absence",
                    "requires": "a source that would hold the record, and its absence",
                    "applies_because": "the specimen source type records nothing for this entity",
                },
                "citations": [
                    {
                        "node_id": "obs_000000000001",
                        "layer": "observation",
                        "record_id": "rec_000000000001",
                        "event_id": "EVT-9001",
                        "source_type": "endpoint",
                        "timestamp": "2000-01-01T00:00:00.000000Z",
                        "zone": "UTC",
                        "field": "hostname",
                        "asserted_value": "SPECIMEN-HOST-01",
                    }
                ],
            },
            {
                "claim_id": "clm_specimen_4",
                "text": (
                    "A claim with two citations that disagree, so R3.3 adds "
                    "Conflicted — and one of them points at a record id that "
                    "does not resolve, which is R2.9's failure path rendered "
                    "rather than described."
                ),
                "kind": "finding",
                "support": {
                    "label": "conflicted",
                    "flags": ["conflicted"],
                    "source_types": ["endpoint"],
                    "counts": {"observations": 2, "findings": 0, "edges": 1},
                },
                "basis": {
                    "name": "specimen_conflict",
                    "requires": "two observations of the same field of the same entity",
                    "applies_because": "the two cited observations assert different values",
                },
                "citations": [
                    {
                        "node_id": "obs_000000000001",
                        "layer": "observation",
                        "record_id": "rec_000000000001",
                        "event_id": "EVT-9001",
                        "source_type": "endpoint",
                        "timestamp": "2000-01-01T00:00:00.000000Z",
                        "zone": "UTC",
                        "field": "integrity_level",
                        "asserted_value": "medium",
                    },
                    {
                        "node_id": "obs_000000000099",
                        "layer": "observation",
                        "record_id": "rec_deliberately_absent",
                        "event_id": "EVT-9099",
                        "source_type": "endpoint",
                        "timestamp": "2000-01-01T00:09:00.000000Z",
                        "zone": "UTC",
                        "field": "integrity_level",
                        "asserted_value": "SYSTEM",
                    },
                ],
            },
        ],
        "gaps": [
            {
                "statement": "This specimen has no pipeline behind it.",
                "limits": "nothing in it may be read as a finding about the incident",
            }
        ],
        "provenance": {
            "software_version": "specimen",
            "catalogue_version": "specimen",
            "model_id": "none — no model produced this payload",
        },
    }
