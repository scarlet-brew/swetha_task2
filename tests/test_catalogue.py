"""T04 -- the derived ATT&CK catalogue, and the tactic facts design text rests on.

The three slice assertions here are checked **against the bundle**, not from
memory. R4.9 and acceptance scenario AS-03's expected wording depend on exactly
two tactic mappings -- that `T1078` carries privilege-escalation and that
`T1569.002` does not -- and asserting those from recollection is precisely the
confident-sounding error the whole spec process exists to prevent. Each test
therefore states the expected literal *and* re-reads the bundle to confirm the
derived file did not invent it.
"""

from __future__ import annotations

import json
import time
import tracemalloc
import unittest

import _env  # noqa: F401  -- puts src/ on sys.path

from siem_investigator import jsonl, paths
from siem_investigator.enrich import catalogue as catalogue_module
from siem_investigator.enrich.catalogue import Catalogue


def _bundle_techniques(technique_ids: tuple[str, ...]) -> dict[str, dict]:
    """The raw `attack-pattern` objects for `technique_ids`, read from the bundle.

    One pass for all of them: the bundle is 51 MiB, and re-parsing it per
    assertion would cost the suite several seconds to learn nothing new.
    """
    wanted = set(technique_ids)
    found: dict[str, dict] = {}
    with paths.ATTACK_BUNDLE.open(encoding="utf-8") as handle:
        objects = json.load(handle)["objects"]
    for obj in objects:
        if obj["type"] != "attack-pattern":
            continue
        for reference in obj.get("external_references", ()):
            if (
                reference.get("source_name") == "mitre-attack"
                and reference.get("external_id") in wanted
            ):
                found[reference["external_id"]] = obj
    missing = wanted - set(found)
    if missing:
        raise AssertionError(f"not present in the bundle: {sorted(missing)}")
    return found


def _mitre_phases(obj: dict) -> list[str]:
    """`kill_chain_phases` can name other kill chains; only ATT&CK's are tactics."""
    return [
        phase["phase_name"]
        for phase in obj.get("kill_chain_phases", ())
        if phase.get("kill_chain_name") == "mitre-attack"
    ]


class TestCatalogueShape(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalogue = Catalogue.load()

    def test_version_reads_exactly_19_2(self):
        """Copied verbatim from the `x-mitre-collection` object, never re-derived
        from the filename -- R4.2's claim is about what MITRE published."""
        self.assertEqual(self.catalogue.attack_version, "19.2")

    def test_version_matches_the_collection_object(self):
        with paths.ATTACK_BUNDLE.open(encoding="utf-8") as handle:
            objects = json.load(handle)["objects"]
        collections = [obj for obj in objects if obj["type"] == "x-mitre-collection"]
        self.assertEqual(len(collections), 1)
        self.assertEqual(self.catalogue.attack_version, collections[0]["x_mitre_version"])

    def test_d03_slice_counts(self):
        """D-03 names the three slices used: 1 collection, 15 tactics, 858
        techniques. The 21,262 relationship objects are not used."""
        counts = self.catalogue.payload["counts"]
        self.assertEqual(counts["tactics"], 15)
        self.assertEqual(counts["techniques"], 858)
        self.assertEqual(len(self.catalogue.techniques), 858)
        self.assertEqual(len(self.catalogue.tactics), 15)

    def test_every_technique_carries_the_id_ref_pair(self):
        """D-04 borrows one idea back from Attack Flow: id and STIX ref travel as a
        pair, so stage 4 can check them against each other. The documented model
        failure is a right name with a wrong id, which existence-checking passes."""
        for technique_id, technique in self.catalogue.techniques.items():
            with self.subTest(technique_id=technique_id):
                self.assertTrue(technique.technique_ref.startswith("attack-pattern--"))
                self.assertTrue(technique.name)

    def test_records_its_source_bundle(self):
        source = self.catalogue.payload["source"]
        self.assertEqual(source["file"], "data/attack/enterprise-attack-19.2.json")
        self.assertRegex(source["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(source["sha256"], catalogue_module.sha256_of(paths.ATTACK_BUNDLE))


class TestTheThreeSlices(unittest.TestCase):
    """The assertions design SS4's R4.4-R4.9 paragraph and AS-03 depend on."""

    #: Every expected literal below is checked twice -- against the derived
    #: catalogue, and against the bundle object it was projected from. The first
    #: check alone would pass on a projection that invented the value; the second
    #: is what makes "against the bundle, not from memory" literally true.
    SLICES = ("T1059.001", "T1078", "T1569.002", "T1068")

    @classmethod
    def setUpClass(cls):
        cls.catalogue = Catalogue.load()
        cls.bundle = _bundle_techniques(cls.SLICES)

    def assert_matches_bundle(self, technique_id: str) -> None:
        technique = self.catalogue.technique(technique_id)
        obj = self.bundle[technique_id]
        self.assertEqual(technique.name, obj["name"])
        self.assertEqual(list(technique.tactics), _mitre_phases(obj))
        self.assertEqual(technique.technique_ref, obj["id"])

    def test_t1059_001_is_powershell_under_execution(self):
        technique = self.catalogue.technique("T1059.001")
        self.assertIsNotNone(technique)
        self.assertEqual(technique.name, "PowerShell")
        self.assertIn("execution", technique.tactics)
        self.assertEqual(self.catalogue.tactic_name("execution"), "Execution")
        self.assert_matches_bundle("T1059.001")

    def test_t1078_is_valid_accounts_and_includes_privilege_escalation(self):
        """Load-bearing for R4.9: privilege escalation is reported from the
        technique's own tactics rather than inferred from the event."""
        technique = self.catalogue.technique("T1078")
        self.assertIsNotNone(technique)
        self.assertEqual(technique.name, "Valid Accounts")
        self.assertIn("privilege-escalation", technique.tactics)
        self.assert_matches_bundle("T1078")

    def test_t1569_002_is_service_execution_under_execution_only(self):
        """The other half of the pair: service execution is *not* privilege
        escalation in v19.2, so a report that called it one would be wrong."""
        technique = self.catalogue.technique("T1569.002")
        self.assertIsNotNone(technique)
        self.assertEqual(technique.name, "Service Execution")
        self.assertEqual(list(technique.tactics), ["execution"])
        self.assertNotIn("privilege-escalation", technique.tactics)
        self.assert_matches_bundle("T1569.002")

    def test_t1068_is_present_and_selectable(self):
        """Present so it *could* be selected. T23 must nonetheless emit no mapping
        to it: nothing in this dataset evidences exploitation for privilege
        escalation, and T30 checks that no mapping claims it."""
        technique = self.catalogue.technique("T1068")
        self.assertIsNotNone(technique)
        self.assertEqual(technique.name, "Exploitation for Privilege Escalation")
        self.assertEqual(list(technique.tactics), ["privilege-escalation"])
        self.assertIn("T1068", self.catalogue.selectable_ids())
        self.assert_matches_bundle("T1068")

    def test_v19_renamed_defense_evasion_to_stealth(self):
        """Worth pinning, because it is the kind of upstream change that silently
        invalidates a hand-written expectation. In v19.2 TA0005 is *Stealth*, and
        `defense-evasion` is not a tactic shortname at all -- T1078 carries
        `stealth`. A mapping table written from older ATT&CK would miss here."""
        self.assertEqual(self.catalogue.tactic_name("stealth"), "Stealth")
        self.assertIsNone(self.catalogue.tactic_name("defense-evasion"))
        self.assertIn("stealth", self.catalogue.technique("T1078").tactics)


class TestSelectableEnum(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalogue = Catalogue.load()

    def test_revoked_and_deprecated_are_retained_but_not_selectable(self):
        """They stay in the catalogue so an id from older reporting still resolves
        to a name; they leave the enum because mapping a finding to a revoked
        technique is a defect."""
        counts = self.catalogue.payload["counts"]
        self.assertEqual(counts["revoked"], 149)
        self.assertEqual(counts["deprecated"], 12)
        self.assertEqual(counts["selectable"], 697)
        self.assertEqual(len(self.catalogue.selectable_ids()), 697)

        for technique in self.catalogue.techniques.values():
            if technique.revoked or technique.deprecated:
                self.assertNotIn(technique.technique_id, self.catalogue.selectable_ids())

    def test_selectable_ids_are_sorted_and_unique(self):
        ids = self.catalogue.selectable_ids()
        self.assertEqual(list(ids), sorted(set(ids)))

    def test_name_matches_id_catches_a_right_name_on_a_wrong_id(self):
        self.assertTrue(self.catalogue.name_matches_id("T1059.001", "PowerShell"))
        # The documented failure mode: a real name paired with a real-but-other id.
        self.assertFalse(self.catalogue.name_matches_id("T1569.002", "PowerShell"))
        self.assertFalse(self.catalogue.name_matches_id("T9999", "PowerShell"))


class TestDerivationIsReproducible(unittest.TestCase):
    def test_regenerating_yields_byte_identical_output(self):
        """SS8.3's invariant for this projection: delete it, regenerate from the
        authority, get the same bytes. A failure means something non-derivable
        leaked in -- a timestamp, a set iteration order, a machine path."""
        committed = paths.ATTACK_CATALOGUE.read_bytes()
        scratch = paths.ATTACK_CATALOGUE.with_suffix(".test.json")
        try:
            jsonl.write_json(scratch, catalogue_module.derive())
            self.assertEqual(scratch.read_bytes(), committed)
        finally:
            scratch.unlink(missing_ok=True)

    def test_check_mode_agrees(self):
        self.assertEqual(catalogue_module.main(["--check"]), 0)


class TestMeasuredParseCost(unittest.TestCase):
    """T04 records wall time and peak memory for the stdlib parse of 51 MiB.

    Not a performance gate -- a machine-dependent number would be a flaky test.
    The assertion is the one that matters for D-03: the parse completes at all
    with stdlib `json` alone, which is what let `mitreattack-python` and its
    150-300 MB of pandas/numpy/pillow be rejected.

    `tracemalloc` is the portable half of the measurement. SS10.2's 274 MiB peak
    working set came from `GetProcessMemoryInfo` in a fresh process, measured out
    of band and deliberately not asserted here: a Windows-only call would cost
    this suite the portability the rest of it keeps.
    """

    def test_stdlib_parse_completes_and_report_the_cost(self):
        tracemalloc.start()
        started = time.perf_counter()
        with paths.ATTACK_BUNDLE.open(encoding="utf-8") as handle:
            bundle = json.load(handle)
        elapsed = time.perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        self.assertEqual(len(bundle["objects"]), 26086)
        print(
            f"\n  [T04 measured] stdlib json parse of "
            f"{paths.ATTACK_BUNDLE.stat().st_size / 2**20:.1f} MiB: "
            f"{elapsed:.2f} s, tracemalloc peak {peak / 2**20:.0f} MiB, "
            f"{len(bundle['objects']):,} objects"
        )


if __name__ == "__main__":
    unittest.main()
