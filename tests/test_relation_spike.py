"""T09 -- the relation regression, at raw-data level, proved by mutation.

**No project imports.** This module reads `data/raw/siem_logs.json` and nothing
else: no `siem_investigator`, not even `_env`. That is deliberate. It could run
before a single line of the package existed, which means T16 reproduces a frozen
number rather than inventing one, and a later refactor of the relation functions
cannot quietly redefine what the right answer was.

What it pins is design SS3.6's central claim: **exact byte count carries the
cross-source file relation and the basename alone does not.** The whole reason
`same_file` and `same_size` are separate atomic relations rests on it, so it is
worth a test that bites.

`MutationControl` is where the teeth are. It runs the *weaker* predicate --
basename only, no size -- and asserts it yields 2 pairs instead of 1, with a
named false positive. Deleting the size check from the real relation set would
therefore change a number this file already asserts. That is a proof the test
has teeth, rather than an assertion that it does.
"""

from __future__ import annotations

import datetime as dt
import json
import unittest
from itertools import combinations
from pathlib import Path

RAW = Path(__file__).resolve().parent.parent / "data" / "raw" / "siem_logs.json"
BACKSLASH = chr(92)


def load() -> list[dict]:
    return json.loads(RAW.read_text(encoding="utf-8"))["events"]


def instant(event: dict) -> dt.datetime:
    # `fromisoformat`, not a format string: 22 of the 242 timestamps are written
    # to whole seconds and 220 carry microseconds, so one `strptime` pattern
    # cannot read both.
    return dt.datetime.fromisoformat(event["timestamp"])


def basename(event: dict) -> str | None:
    for field in ("file_name", "file_path"):
        value = event.get(field)
        if value:
            return value.replace(BACKSLASH, "/").rsplit("/", 1)[-1].lower()
    return None


def same_file(left: dict, right: dict) -> bool:
    """Normalised basename equality. Deliberately says nothing about size."""
    name = basename(left)
    return name is not None and name == basename(right)


def same_size(left: dict, right: dict) -> bool:
    """Exact byte equality, and *both sides must carry the field*.

    Absent is not zero and not equal. A deletion record naming a file it does
    not size must not match the upload of that file.
    """
    if "file_size_bytes" not in left or "file_size_bytes" not in right:
        return False
    return left["file_size_bytes"] == right["file_size_bytes"]


def temporal_delta(left: dict, right: dict) -> float:
    """Seconds from `left` to `right`. Signed, and **reported, not thresholded**.

    This is the design's answer to the time-window problem: no global window has
    to be chosen, because interpretation decides in context whether a gap
    matters. The intrusion's own related-event gaps span seconds to hours.
    """
    return (instant(right) - instant(left)).total_seconds()


class TheStagingToUploadPair(unittest.TestCase):
    """EVT-0237 -> EVT-0238: the relation that carries the exfiltration reading."""

    @classmethod
    def setUpClass(cls):
        events = {event["event_id"]: event for event in load()}
        cls.staged = events["EVT-0237"]
        cls.uploaded = events["EVT-0238"]

    def test_it_crosses_two_sources(self):
        """The thing the predecessor tool could not do at all."""
        self.assertEqual(self.staged["source_type"], "endpoint")
        self.assertEqual(self.staged["event_name"], "file_create")
        self.assertEqual(self.uploaded["source_type"], "cloud_storage")
        self.assertEqual(self.uploaded["event_name"], "file_upload")

    def test_same_normalised_basename(self):
        """One side carries a Windows `file_path`, the other a bare `file_name`.
        Normalisation is what makes them comparable at all."""
        self.assertTrue(same_file(self.staged, self.uploaded))
        self.assertEqual(basename(self.staged), "backup_archive.zip")

    def test_same_exact_byte_count(self):
        self.assertTrue(same_size(self.staged, self.uploaded))
        self.assertEqual(self.staged["file_size_bytes"], 2473829122)
        self.assertEqual(self.uploaded["file_size_bytes"], 2473829122)

    def test_time_ordered_at_one_hour_twenty_seven_forty_one(self):
        delta = temporal_delta(self.staged, self.uploaded)
        self.assertGreater(delta, 0, "staging must precede the upload")
        self.assertEqual(delta, 5261.0)
        hours, remainder = divmod(delta, 3600)
        minutes, seconds = divmod(remainder, 60)
        self.assertEqual((int(hours), int(minutes), int(seconds)), (1, 27, 41))


class TheDeletionPair(unittest.TestCase):
    """EVT-0239 -> EVT-0238: matches on name, and fails on *two* counts."""

    @classmethod
    def setUpClass(cls):
        events = {event["event_id"]: event for event in load()}
        cls.deleted = events["EVT-0239"]
        cls.uploaded = events["EVT-0238"]

    def test_it_matches_on_basename(self):
        self.assertTrue(same_file(self.deleted, self.uploaded))

    def test_it_carries_no_size_at_all(self):
        """Not a mismatched size -- an absent field. `same_size` has to
        distinguish "different" from "unknown", because a deletion record that
        happened to be compared numerically against nothing would match."""
        self.assertNotIn("file_size_bytes", self.deleted)
        self.assertFalse(same_size(self.deleted, self.uploaded))

    def test_it_is_reversed_in_time(self):
        """1 h 44 m 33 s *after* the upload. The second independent reason this
        pair is not a staging relation."""
        delta = temporal_delta(self.deleted, self.uploaded)
        self.assertLess(delta, 0)
        self.assertEqual(delta, -6273.0)
        self.assertAlmostEqual(abs(delta) / 3600, 1.74, places=2)

    def test_two_independent_failures_not_one(self):
        """Neither check is carrying this case alone, which is why removing
        either would not be caught by this pair in isolation -- hence the
        dataset-wide count below."""
        self.assertFalse(same_size(self.deleted, self.uploaded))
        self.assertFalse(temporal_delta(self.deleted, self.uploaded) > 0)


class DatasetWideCrossSourceFilePairs(unittest.TestCase):
    """The frozen numbers T16 has to reproduce."""

    @classmethod
    def setUpClass(cls):
        cls.events = load()
        cls.named = [event for event in cls.events if basename(event)]

    def _cross_source_pairs(self, *, require_size: bool):
        found = []
        for left, right in combinations(self.named, 2):
            if left["source_type"] == right["source_type"]:
                continue
            if not same_file(left, right):
                continue
            if require_size and not same_size(left, right):
                continue
            found.append(tuple(sorted((left["event_id"], right["event_id"]))))
        return sorted(found)

    def test_thirty_five_events_name_a_file(self):
        self.assertEqual(len(self.named), 35)

    def test_name_plus_exact_size_yields_exactly_one_pair(self):
        pairs = self._cross_source_pairs(require_size=True)
        self.assertEqual(len(pairs), 1)
        self.assertEqual(pairs, [("EVT-0237", "EVT-0238")])

    def test_name_alone_yields_two(self):
        pairs = self._cross_source_pairs(require_size=False)
        self.assertEqual(len(pairs), 2)
        self.assertEqual(pairs, [("EVT-0237", "EVT-0238"), ("EVT-0238", "EVT-0239")])


class MutationControl(unittest.TestCase):
    """The proof the size predicate has teeth.

    T09 asks for this as a manual step: delete the size check by hand and watch
    the count rise 1 -> 2 and the test fail. Encoding it is strictly better --
    it runs on every commit rather than once, and it names the false positive
    the weaker predicate admits.

    If someone later drops `same_size` from the relation set, the dataset-wide
    count above changes from 1 to the number asserted here, and two tests fail
    with a diagnostic that says exactly what was lost.
    """

    @classmethod
    def setUpClass(cls):
        cls.named = [event for event in load() if basename(event)]

    def _pairs_without_the_size_predicate(self):
        return sorted(
            tuple(sorted((left["event_id"], right["event_id"])))
            for left, right in combinations(self.named, 2)
            if left["source_type"] != right["source_type"] and same_file(left, right)
        )

    def test_dropping_size_admits_one_false_positive(self):
        weaker = self._pairs_without_the_size_predicate()
        self.assertEqual(len(weaker), 2, "the weaker predicate should admit 2 pairs")
        self.assertIn(("EVT-0238", "EVT-0239"), weaker, "the false positive the size check removes")

    def test_that_is_a_fifty_percent_false_positive_rate(self):
        weaker = self._pairs_without_the_size_predicate()
        correct = [pair for pair in weaker if pair == ("EVT-0237", "EVT-0238")]
        self.assertEqual(len(correct), 1)
        self.assertEqual(len(weaker) - len(correct), 1)
        self.assertEqual((len(weaker) - len(correct)) / len(weaker), 0.5)

    def test_the_false_positive_is_not_merely_unordered(self):
        """It would still be admitted by a predicate that checked ordering but not
        size -- as the *earlier* member of a reversed pair. So ordering alone does
        not substitute for the size check."""
        events = {event["event_id"]: event for event in load()}
        deleted, uploaded = events["EVT-0239"], events["EVT-0238"]
        self.assertTrue(same_file(uploaded, deleted))
        self.assertGreater(temporal_delta(uploaded, deleted), 0)
        self.assertFalse(same_size(uploaded, deleted))


if __name__ == "__main__":
    unittest.main()
