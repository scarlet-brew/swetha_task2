"""Regenerate the three committed test fixtures from the raw dataset (T08).

Every number in these files is *measured here*, never typed in. That is the
whole point: several figures in the plan were written from recollection and two
of them were wrong -- `network_connection`'s larger key-sets are 14 and 15 keys,
not 13 and 14, and the derived ATT&CK catalogue is 1.4 MB rather than ~200 KB.
A fixture that is regenerated and diffed cannot carry that kind of error for
long.

    python scripts/regen_fixtures.py          # rewrite all three
    python scripts/regen_fixtures.py --check   # rewrite to memory and diff

The `--check` form is what `git diff --exit-code tests/fixtures/` verifies after
a plain run: regenerating must be a no-op.

**`ground_truth.json` is special.** It is derived from the `note` annotations,
which R7.2 admits for accuracy measurement *only*. Nothing under `src/` or
`app/` may read it -- a test asserts that with `git grep`, at this task and at
every later one. It exists so T30 can measure recall and precision against a
labelled set, and for no other purpose.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from collections import Counter
from itertools import combinations
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw" / "siem_logs.json"
FIXTURES = ROOT / "tests" / "fixtures"

BACKSLASH = chr(92)


def load_events() -> tuple[dict, list[dict]]:
    payload = json.loads(RAW.read_text(encoding="utf-8"))
    return payload["metadata"], payload["events"]


def instant(event: dict) -> dt.datetime:
    """Parse a raw timestamp.

    `fromisoformat` rather than a `strptime` format string, because the dataset
    mixes precisions: 220 events carry microseconds and 22 are written to whole
    seconds. A single format string fails on one group or the other -- which is
    how that fact came to light.
    """
    return dt.datetime.fromisoformat(event["timestamp"])


def basename(event: dict) -> str | None:
    """Normalised file basename, or None if the event names no file.

    Windows paths arrive with backslashes; `file_name` arrives bare. Both
    normalise to a lowercase basename, which is what a cross-source file
    relation can compare.
    """
    for field in ("file_name", "file_path"):
        value = event.get(field)
        if value:
            return value.replace(BACKSLASH, "/").rsplit("/", 1)[-1].lower()
    return None


def dataset_census(metadata: dict, events: list[dict]) -> dict:
    keys = Counter()
    for event in events:
        keys.update(event.keys())

    kinds = Counter((event["source_type"], event["event_name"]) for event in events)
    network = [event for event in events if event["event_name"] == "network_connection"]

    return {
        "_note": (
            "Measured from data/raw/siem_logs.json by scripts/regen_fixtures.py. Every figure "
            "here is computed, not transcribed. Regenerating must be a no-op."
        ),
        "total_events": len(events),
        "metadata_total_events": metadata["total_events"],
        "collection_window": {
            "start": metadata["collection_window_start"],
            "end": metadata["collection_window_end"],
        },
        "by_source_type": dict(sorted(Counter(e["source_type"] for e in events).items())),
        "event_kinds": {
            "count": len(kinds),
            "counts": {f"{source}/{name}": n for (source, name), n in sorted(kinds.items())},
        },
        "key_inventory": {
            "distinct_keys": len(keys),
            "present": dict(sorted(keys.items())),
            "absent": {key: len(events) - n for key, n in sorted(keys.items())},
        },
        "network_connection": {
            "events": len(network),
            # Three distinct shapes within one event kind. A strict parser that
            # demanded a single schema per kind would reject the 4 richest
            # records -- and those 4 are the only ones needing no address
            # resolution at all, because they already name their hosts.
            "key_set_sizes": dict(sorted(Counter(len(e) for e in network).items())),
            "without_src_host": sum(1 for e in network if "src_host" not in e),
            "without_dst_host": sum(1 for e in network if "dst_host" not in e),
        },
        "command_line_encoding": {
            # Three ways of saying "nothing here", and they are not the same
            # thing: absent means the source does not carry the field, empty
            # string means it carried it with no value. Field presence is data,
            # not a parse error.
            "absent": sum(1 for e in events if "command_line" not in e),
            "empty_string": sum(1 for e in events if e.get("command_line") == ""),
            "null": sum(1 for e in events if "command_line" in e and e["command_line"] is None),
            "valued": sum(1 for e in events if e.get("command_line")),
        },
        "timestamp_precision": {
            "sub_second": sum(1 for e in events if "." in e["timestamp"]),
            "whole_second": sum(1 for e in events if "." not in e["timestamp"]),
        },
    }


def ground_truth(events: list[dict]) -> dict:
    annotated = sorted(
        event["event_id"] for event in events if str(event.get("note", "")).startswith("ATTACK:")
    )
    numbers = sorted(int(eid.split("-")[1]) for eid in annotated)
    all_numbers = sorted(int(event["event_id"].split("-")[1]) for event in events)

    return {
        "_warning": (
            "GROUND TRUTH -- ACCURACY MEASUREMENT ONLY. R7.2 admits the `note` annotations for "
            "measuring recall and precision against a labelled set, and for nothing else. No "
            "module under src/ or app/ may read this file; tests/test_fixtures.py asserts that "
            "with git grep. Using it as detection signal would make the prototype worthless as "
            "a demonstration."
        ),
        "attack_event_ids": annotated,
        "count": len(annotated),
        "source_field": "note",
        "leaks_this_set_is_perfectly_correlated_with": {
            "_note": (
                "CLAUDE.md ground rule 1 lists three leaks. All three select exactly this set, "
                "so any of them scores 100% precision and 100% recall while demonstrating "
                "nothing. T20 and T30 have to show the pipeline does not ride on them."
            ),
            "note_annotation": (
                "the 22 events carrying a `note` key are exactly these 22; stripped at the "
                "parse boundary by T10"
            ),
            "whole_second_timestamps": (
                "`'.' not in timestamp` selects exactly these 22 of 242 -- a generator "
                "artifact, and the one leak that survives stripping `note`"
            ),
            "event_id_ordering": (
                f"these are the final {len(numbers)} ids, contiguous "
                f"{numbers[0]}..{numbers[-1]} of {all_numbers[0]}..{all_numbers[-1]}"
            ),
        },
    }


def relation_expectations(events: list[dict]) -> dict:
    by_id = {event["event_id"]: event for event in events}

    def pair(earlier_id: str, later_id: str) -> dict:
        first, second = by_id[earlier_id], by_id[later_id]
        delta = (instant(second) - instant(first)).total_seconds()
        both_sized = "file_size_bytes" in first and "file_size_bytes" in second
        return {
            "from": earlier_id,
            "to": later_id,
            "from_kind": f"{first['source_type']}/{first['event_name']}",
            "to_kind": f"{second['source_type']}/{second['event_name']}",
            "same_basename": basename(first) == basename(second),
            "basename": basename(first),
            "size_present": {earlier_id: "file_size_bytes" in first, later_id: "file_size_bytes" in second},
            "same_size": bool(both_sized and first["file_size_bytes"] == second["file_size_bytes"]),
            "size_bytes": first.get("file_size_bytes"),
            "delta_seconds": delta,
            "delta_human": _human(delta),
            "ordered_from_before_to": delta > 0,
        }

    named = [event for event in events if basename(event)]
    cross_source = []
    for left, right in combinations(named, 2):
        if left["source_type"] == right["source_type"] or basename(left) != basename(right):
            continue
        both_sized = "file_size_bytes" in left and "file_size_bytes" in right
        cross_source.append(
            {
                "pair": sorted([left["event_id"], right["event_id"]]),
                "basename": basename(left),
                "same_size": bool(both_sized and left["file_size_bytes"] == right["file_size_bytes"]),
            }
        )
    cross_source.sort(key=lambda row: row["pair"])

    return {
        "_note": (
            "Design SS10.2's measured relation spike, recomputed. SS3.6's central claim is that "
            "exact byte count carries the cross-source file relation and the basename alone does "
            "not. These numbers are what T09 and T16 assert against."
        ),
        "staging_to_upload": pair("EVT-0237", "EVT-0238"),
        # Two independent reasons this pair fails, and it is worth having both:
        # a relation set that only checked ordering would still reject it, and
        # so would one that only checked size, so neither check alone is
        # load-bearing for this case.
        "deletion_after_upload": pair("EVT-0239", "EVT-0238"),
        "events_naming_a_file": len(named),
        "cross_source_file_pairs": {
            "on_basename_alone": len(cross_source),
            "on_basename_and_exact_size": sum(1 for row in cross_source if row["same_size"]),
            "pairs": cross_source,
            "_why_this_matters": (
                "Basename alone yields 2 pairs, one of which is wrong -- a 50% false-positive "
                "rate. Basename plus exact size yields 1, and it is the right one. That is why "
                "`same_file` and `same_size` are separate atomic relations rather than one "
                "composite: the AI layer observes that both hold, and the deterministic layer "
                "never decides that the conjunction means exfiltration."
            ),
        },
    }


def _human(seconds: float) -> str:
    sign = "-" if seconds < 0 else ""
    hours, remainder = divmod(abs(seconds), 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{sign}{int(hours)}h {int(minutes)}m {int(secs)}s"


def build() -> dict[Path, dict]:
    metadata, events = load_events()
    return {
        FIXTURES / "dataset_census.json": dataset_census(metadata, events),
        FIXTURES / "ground_truth.json": ground_truth(events),
        FIXTURES / "relation_expectations.json": relation_expectations(events),
    }


def render(payload: dict) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="diff instead of writing")
    args = parser.parse_args(argv)

    differences = 0
    for path, payload in build().items():
        text = render(payload)
        label = path.relative_to(ROOT).as_posix()
        if args.check:
            current = path.read_text(encoding="utf-8") if path.exists() else None
            if current == text:
                print(f"ok       {label}")
            else:
                print(f"DIFFERS  {label}", file=sys.stderr)
                differences += 1
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8", newline="")
            print(f"wrote    {label}  {len(text):,} bytes")

    if differences:
        print(f"\n{differences} fixture(s) out of date; run without --check.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
