"""T08 -- the measured facts, pinned as committed fixtures.

Two jobs. First, the fixtures must be *regenerable*: every number in them is
computed from the raw dataset, so a stale figure cannot survive. Second, and
more important, `ground_truth.json` must stay unreachable from the system. R7.2
admits the `note` annotations for accuracy measurement only, and the way that
rule gets broken is not malice -- it is one convenient import during a late
debugging session.
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from collections import Counter
from pathlib import Path

import _env  # noqa: F401  -- puts src/ on sys.path

SCRIPTS = _env.REPO_ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import regen_fixtures  # noqa: E402

CENSUS = _env.FIXTURES_DIR / "dataset_census.json"
GROUND_TRUTH = _env.FIXTURES_DIR / "ground_truth.json"
RELATIONS = _env.FIXTURES_DIR / "relation_expectations.json"


def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class TheFixturesRegenerate(unittest.TestCase):
    """T08's verification: regenerating all three is a no-op."""

    def test_regeneration_is_a_no_op(self):
        self.assertEqual(regen_fixtures.main(["--check"]), 0)

    def test_all_three_exist(self):
        for path in (CENSUS, GROUND_TRUTH, RELATIONS):
            with self.subTest(path=path.name):
                self.assertTrue(path.exists())


class TheCensusMatchesTheDataset(unittest.TestCase):
    """Spot-checked against the raw file rather than against itself, so a bug in
    the generator cannot make the fixture agree with the generator."""

    @classmethod
    def setUpClass(cls):
        cls.census = read(CENSUS)
        payload = json.loads(_env.RAW_DATASET.read_text(encoding="utf-8"))
        cls.events = payload["events"]

    def test_242_events_and_metadata_agrees(self):
        self.assertEqual(self.census["total_events"], 242)
        self.assertEqual(len(self.events), 242)
        self.assertEqual(self.census["metadata_total_events"], 242)

    def test_source_type_counts(self):
        self.assertEqual(
            self.census["by_source_type"],
            {"auth": 62, "cloud_storage": 31, "endpoint": 65, "network": 84},
        )
        self.assertEqual(
            dict(sorted(Counter(e["source_type"] for e in self.events).items())),
            self.census["by_source_type"],
        )

    def test_fourteen_event_kinds(self):
        """14 logical `source_type` + `event_name` kinds -- not 14 fixed schemas.
        Shapes vary *within* a kind through optional fields."""
        self.assertEqual(self.census["event_kinds"]["count"], 14)
        self.assertEqual(sum(self.census["event_kinds"]["counts"].values()), 242)

    def test_forty_keys_including_the_two_claude_md_omits(self):
        """The whole inventory rebuilt here, not just its headline number.

        It is the census's largest block and the one CLAUDE.md's field table gets
        wrong, so agreeing with the generator proves too little: the map is
        recounted from the raw events and compared entry by entry. `service_path`
        and `target_pid` are the two keys that table omits, and each occurs
        exactly once -- a lone occurrence is precisely what a hand-written table
        loses.
        """
        inventory = self.census["key_inventory"]
        measured = Counter()
        for event in self.events:
            measured.update(event.keys())

        self.assertEqual(inventory["distinct_keys"], 40)
        self.assertEqual(len(measured), 40)
        self.assertEqual(inventory["present"], dict(sorted(measured.items())))
        self.assertEqual(
            inventory["absent"],
            {key: len(self.events) - n for key, n in sorted(measured.items())},
        )
        for key in ("service_path", "target_pid"):
            with self.subTest(key=key):
                self.assertEqual(measured[key], 1)
                self.assertEqual(inventory["present"][key], 1)

    def test_network_connection_has_three_shapes(self):
        """The measured correction to T08's own text, which said 13 and 14 keys.
        It is 12, 14 and 15 -- and the 4 richest records are precisely the ones
        that name their hosts outright and so need no address resolution."""
        network = self.census["network_connection"]
        self.assertEqual(network["events"], 84)
        self.assertEqual(network["key_set_sizes"], {"12": 80, "14": 3, "15": 1})
        self.assertEqual(network["without_src_host"], 80)
        self.assertEqual(network["without_dst_host"], 83)

    def test_command_line_has_three_absence_encodings(self):
        """Absent, empty string and valued are three different facts. Collapsing
        them would turn "the source does not carry this field" into "the process
        had no command line"."""
        encoding = self.census["command_line_encoding"]
        self.assertEqual(encoding["absent"], 184)
        self.assertEqual(encoding["empty_string"], 50)
        self.assertEqual(encoding["null"], 0)
        self.assertEqual(encoding["valued"], 8)
        self.assertEqual(encoding["absent"] + encoding["empty_string"] + encoding["valued"], 242)

    def test_timestamp_precision_is_mixed(self):
        """220 microsecond, 22 whole-second. Load-bearing twice over: a single
        `strptime` format string fails on one group, and the split is one of
        CLAUDE.md's three leaks."""
        precision = self.census["timestamp_precision"]
        self.assertEqual(precision["sub_second"], 220)
        self.assertEqual(precision["whole_second"], 22)


class GroundTruthIsLabelledAndQuarantined(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.truth = read(GROUND_TRUTH)

    def test_exactly_22_ids(self):
        self.assertEqual(self.truth["count"], 22)
        self.assertEqual(len(self.truth["attack_event_ids"]), 22)
        self.assertEqual(len(set(self.truth["attack_event_ids"])), 22)

    def test_it_says_what_it_is_for(self):
        self.assertIn("ACCURACY MEASUREMENT ONLY", self.truth["_warning"])
        self.assertIn("R7.2", self.truth["_warning"])

    def test_it_records_the_three_leaks_it_is_correlated_with(self):
        """Every one of CLAUDE.md's three leaks selects exactly this set, so each
        scores perfect precision and recall while demonstrating nothing. Recording
        that beside the labels is what stops the set being mistaken for a feature."""
        leaks = self.truth["leaks_this_set_is_perfectly_correlated_with"]
        for leak in ("note_annotation", "whole_second_timestamps", "event_id_ordering"):
            self.assertIn(leak, leaks)

    def test_the_leak_correlation_claims_are_true(self):
        """Asserted against the dataset, because a claim about a leak that is
        itself wrong would be worse than no claim."""
        events = json.loads(_env.RAW_DATASET.read_text(encoding="utf-8"))["events"]
        labelled = set(self.truth["attack_event_ids"])

        noted = {e["event_id"] for e in events if "note" in e}
        whole_second = {e["event_id"] for e in events if "." not in e["timestamp"]}
        numbers = sorted(int(e["event_id"].split("-")[1]) for e in events)
        last_22 = {f"EVT-{n:04d}" for n in numbers[-22:]}

        self.assertEqual(noted, labelled, "the `note` leak does not select exactly this set")
        self.assertEqual(whole_second, labelled, "the precision leak does not select exactly this set")
        self.assertEqual(last_22, labelled, "the id-ordering leak does not select exactly this set")

    @staticmethod
    def _quarantine_grep(token: str) -> subprocess.CompletedProcess:
        """One invocation shape for both the quarantine check and its control, so
        the control cannot drift into exercising a different command."""
        return subprocess.run(
            ["git", "grep", "-n", "--untracked", token, "--", "src/", "app/"],
            cwd=_env.REPO_ROOT,
            capture_output=True,
            text=True,
        )

    def test_no_module_under_src_or_app_reads_it(self):
        """T08's standing verification, and it has to keep holding at every later
        task. `--untracked` so a new uncommitted module cannot pass vacuously."""
        result = self._quarantine_grep("ground_truth")
        self.assertNotEqual(result.returncode, 0, f"ground_truth is reachable from the system:\n{result.stdout}")
        self.assertEqual(result.stdout.strip(), "")

    def test_the_quarantine_grep_is_actually_searching_files(self):
        """The check above is worth exactly as much as its pathspec, and no more.

        Measured: `git grep` exits 1 both for "searched real files, found nothing"
        and for "searched nothing at all" -- against a renamed or emptied `src/`
        it reports success while proving nothing, at precisely the later tasks the
        guarantee is meant to cover. A token that is certainly there shows the
        search reached files.
        """
        control = self._quarantine_grep("siem_investigator")
        self.assertEqual(control.returncode, 0, "the src/ app/ pathspec matched no files at all")
        self.assertTrue(control.stdout.strip())


class RelationExpectationsPinTheCentralClaim(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expectations = read(RELATIONS)

    def test_staging_to_upload_matches_on_name_and_exact_size(self):
        pair = self.expectations["staging_to_upload"]
        self.assertEqual(pair["from"], "EVT-0237")
        self.assertEqual(pair["to"], "EVT-0238")
        self.assertEqual(pair["basename"], "backup_archive.zip")
        self.assertTrue(pair["same_basename"])
        self.assertTrue(pair["same_size"])
        self.assertEqual(pair["size_bytes"], 2473829122)
        self.assertTrue(pair["ordered_from_before_to"])
        self.assertEqual(pair["delta_seconds"], 5261.0)
        self.assertEqual(pair["delta_human"], "1h 27m 41s")

    def test_the_deletion_fails_on_two_independent_counts(self):
        """Worth having both: a relation set that only checked ordering would
        reject this pair, and so would one that only checked size, so neither
        check is carrying the case alone."""
        pair = self.expectations["deletion_after_upload"]
        self.assertEqual(pair["from"], "EVT-0239")
        self.assertTrue(pair["same_basename"])
        self.assertFalse(pair["same_size"])
        self.assertFalse(pair["size_present"]["EVT-0239"])
        self.assertFalse(pair["ordered_from_before_to"])
        self.assertEqual(pair["delta_seconds"], -6273.0)

    def test_exact_size_halves_the_candidate_set(self):
        """SS3.6's central claim, as a number: basename alone gives 2 pairs, one of
        them wrong; basename plus exact size gives 1, the right one."""
        pairs = self.expectations["cross_source_file_pairs"]
        self.assertEqual(pairs["on_basename_alone"], 2)
        self.assertEqual(pairs["on_basename_and_exact_size"], 1)
        self.assertEqual(self.expectations["events_naming_a_file"], 35)


if __name__ == "__main__":
    unittest.main()
