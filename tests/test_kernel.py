"""T02 -- the shared kernel: identity (SS8.2), the JSONL representation (D-10),
and the D-09 line reporter.

Every assertion here corresponds to a clause of T02's verification. The two
that matter most are the cross-process identity check and the byte-identical
round-trip: retrofitting either after nodes exist would invalidate every
committed artifact, which is why T02 comes before anything that mints a node.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

import _env  # noqa: F401  -- puts src/ on sys.path

import siem_investigator
from siem_investigator import ids, jsonl, loc

ID_SHAPE = re.compile(r"^(rec|obs|edg|fnd|map|hyp)_[0-9a-f]{12}$")


class TestVersionIsSingleSourced(unittest.TestCase):
    """SS8.2 stamps the software version onto every artifact, so the two places it
    is written have to agree or provenance records a version nothing was built
    with."""

    def test_package_version_matches_pyproject(self):
        pyproject = tomllib.loads((_env.REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(siem_investigator.__version__, pyproject["project"]["version"])


class TestCanonicalJson(unittest.TestCase):
    def test_key_order_does_not_matter(self):
        """Three orders of one identity, one canonical form."""
        forms = [
            {"a": 1, "b": 2, "c": 3},
            {"c": 3, "a": 1, "b": 2},
            {"b": 2, "c": 3, "a": 1},
        ]
        rendered = {ids.canonical_json(form) for form in forms}
        self.assertEqual(len(rendered), 1, f"key order leaked into the canonical form: {rendered}")

    def test_nested_key_order_does_not_matter(self):
        """Sorting has to reach all the way down -- `payload` is a nested dict."""
        left = {"outer": {"z": 1, "a": {"q": 2, "b": 3}}}
        right = {"outer": {"a": {"b": 3, "q": 2}, "z": 1}}
        self.assertEqual(ids.canonical_json(left), ids.canonical_json(right))

    def test_no_whitespace(self):
        self.assertEqual(ids.canonical_json({"a": [1, 2]}), '{"a":[1,2]}')

    def test_non_ascii_is_not_escaped(self):
        """`ensure_ascii=False`: a host or filename outside ASCII stays readable."""
        self.assertEqual(ids.canonical_json({"f": "café-Ü-é"}), '{"f":"café-Ü-é"}')
        self.assertNotIn("\\u", ids.canonical_json({"f": "café"}))

    def test_integral_float_narrows_to_int(self):
        """SS8.2: integers for byte counts. A count that took a detour through
        arithmetic must not hash differently from the same count read as an int."""
        self.assertEqual(ids.canonical_json({"bytes": 4096.0}), '{"bytes":4096}')
        self.assertEqual(ids.canonical_json({"bytes": 4096}), ids.canonical_json({"bytes": 4096.0}))

    def test_inexact_float_is_refused(self):
        with self.assertRaises(ids.IdentityError):
            ids.canonical_json({"ratio": 0.1})

    def test_nan_and_infinity_refused(self):
        for bad in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(ids.IdentityError):
                ids.canonical_json({"x": bad})

    def test_set_is_refused_because_it_has_no_order(self):
        """A set's iteration order depends on hash randomisation, so admitting one
        would make identity depend on PYTHONHASHSEED."""
        with self.assertRaises(ids.IdentityError):
            ids.canonical_json({"x": {"a", "b"}})

    def test_non_string_key_refused(self):
        with self.assertRaises(ids.IdentityError):
            ids.canonical_json({1: "a"})

    def test_bool_stays_bool(self):
        """`True` must not narrow to `1`: they are different JSON documents."""
        self.assertEqual(ids.canonical_json({"x": True}), '{"x":true}')
        self.assertNotEqual(ids.canonical_json({"x": True}), ids.canonical_json({"x": 1}))

    def test_error_names_the_offending_path(self):
        with self.assertRaises(ids.IdentityError) as caught:
            ids.canonical_json({"outer": {"inner": [1, 0.5]}})
        self.assertIn("$.outer.inner[1]", str(caught.exception))


class TestCanonicalInstant(unittest.TestCase):
    def test_matches_the_datasets_own_spelling(self):
        """The supplied dataset writes `...ffffffZ`, so a canonicalised datetime and
        the raw string it came from agree character for character."""
        parsed = dt.datetime(2026, 6, 12, 9, 7, 30, 394151, tzinfo=dt.timezone.utc)
        self.assertEqual(ids.canonical_instant(parsed), "2026-06-12T09:07:30.394151Z")

    def test_always_six_fractional_digits(self):
        """R7.1's perturbation alters sub-second precision, so a variable number of
        digits would make two spellings of one instant hash differently."""
        whole = dt.datetime(2026, 6, 12, 9, 7, 30, tzinfo=dt.timezone.utc)
        self.assertEqual(ids.canonical_instant(whole), "2026-06-12T09:07:30.000000Z")

    def test_offset_normalises_to_utc(self):
        offset = dt.datetime(2026, 6, 12, 11, 7, 30, 394151, tzinfo=dt.timezone(dt.timedelta(hours=2)))
        self.assertEqual(ids.canonical_instant(offset), "2026-06-12T09:07:30.394151Z")

    def test_naive_datetime_refused(self):
        with self.assertRaises(ids.IdentityError):
            ids.canonical_instant(dt.datetime(2026, 6, 12, 9, 7, 30))

    def test_datetime_inside_an_identity_is_canonicalised(self):
        aware = dt.datetime(2026, 6, 12, 9, 7, 30, 394151, tzinfo=dt.timezone.utc)
        self.assertEqual(ids.canonical_json({"t": aware}), '{"t":"2026-06-12T09:07:30.394151Z"}')


class TestIdShape(unittest.TestCase):
    def test_every_prefix_yields_prefix_plus_twelve_hex(self):
        for prefix in sorted(ids.PREFIXES):
            with self.subTest(prefix=prefix):
                value = ids.node_id(prefix, {"k": "v"})
                self.assertRegex(value, ID_SHAPE)
                self.assertTrue(value.startswith(f"{prefix}_"))
                self.assertEqual(len(value), len(prefix) + 1 + 12)

    def test_unknown_prefix_refused(self):
        with self.assertRaises(ids.IdentityError):
            ids.node_id("claim", {"k": "v"})

    def test_empty_identity_refused(self):
        """An id derived from nothing would be the same id for every node of its kind."""
        with self.assertRaises(ids.IdentityError):
            ids.node_id("obs", {})


class TestIdentityIsStableAcrossProcesses(unittest.TestCase):
    """The clause that makes committed ids meaningful: two processes with
    different hash seeds must agree, or every artifact is only valid within the
    process that wrote it."""

    SNIPPET = (
        "import sys; sys.path.insert(0, %r);"
        "from siem_investigator import ids;"
        "print(ids.node_id('fnd', {'stage': 'exfiltration', 'cited': ['obs_a', 'obs_b'], 'n': 3}))"
    )

    def _id_with_seed(self, seed: str) -> str:
        result = subprocess.run(
            [sys.executable, "-c", self.SNIPPET % str(_env.SRC_DIR)],
            capture_output=True,
            text=True,
            env={**dict(__import__("os").environ), "PYTHONHASHSEED": seed},
            check=True,
        )
        return result.stdout.strip()

    def test_two_seeds_agree(self):
        first = self._id_with_seed("0")
        second = self._id_with_seed("12345")
        self.assertRegex(first, ID_SHAPE)
        self.assertEqual(first, second, "identity depends on PYTHONHASHSEED")


class TestFindingIdentity(unittest.TestCase):
    """SS8.2's load-bearing exclusion: prose is not identity."""

    OBS = ["obs_aaaaaaaaaaaa", "obs_bbbbbbbbbbbb"]
    EDGES = ["edg_cccccccccccc"]

    def _id(self, observations=None, edges=None, stage="exfiltration"):
        return ids.finding_id(
            cited_observations=observations if observations is not None else self.OBS,
            cited_edges=edges if edges is not None else self.EDGES,
            stage=stage,
        )

    def test_rewording_the_statement_leaves_the_id_unchanged(self):
        """Two findings differing only in prose. `finding_id` has no parameter for
        `statement`, so the exclusion is structural rather than remembered -- this
        test states the consequence a caller relies on."""
        first = {
            "id": self._id(),
            "statement": "The archive staged on FILE-SRV-01 was uploaded to external storage.",
            "rationale": "Same basename and identical byte count, staged before the upload.",
            "stage": "exfiltration",
            "cited_observations": self.OBS,
            "cited_edges": self.EDGES,
        }
        second = dict(
            first,
            statement="An archive of the same name and size left the estate via cloud storage.",
            rationale="Basename and exact size agree; the staging precedes the transfer.",
        )
        second["id"] = self._id()
        self.assertEqual(first["id"], second["id"])
        self.assertNotEqual(first["statement"], second["statement"])

    def test_changing_one_cited_observation_changes_the_id(self):
        changed = self._id(observations=["obs_aaaaaaaaaaaa", "obs_dddddddddddd"])
        self.assertNotEqual(self._id(), changed)

    def test_changing_the_stage_changes_the_id(self):
        self.assertNotEqual(self._id(), self._id(stage="lateral_movement"))

    def test_citation_order_does_not_matter(self):
        self.assertEqual(self._id(), self._id(observations=list(reversed(self.OBS))))

    def test_citing_one_observation_twice_is_the_same_claim(self):
        self.assertEqual(self._id(), self._id(observations=self.OBS + [self.OBS[0]]))

    def test_a_finding_may_rest_on_observations_alone(self):
        self.assertRegex(self._id(edges=[]), ID_SHAPE)

    def test_a_finding_citing_nothing_is_refused(self):
        """Invariant 2 -- termination in raw records -- would have nothing to terminate."""
        with self.assertRaises(ids.IdentityError):
            self._id(observations=[])


class TestEdgeIdentity(unittest.TestCase):
    def test_endpoint_order_is_significant(self):
        """`process_parent` names parent then child; reversing it states something
        different, so unlike a finding's citations the order is not sorted away."""
        forward = ids.edge_id(relation="process_parent", endpoints=["obs_a1", "obs_b2"])
        reverse = ids.edge_id(relation="process_parent", endpoints=["obs_b2", "obs_a1"])
        self.assertNotEqual(forward, reverse)

    def test_relation_name_is_significant(self):
        self.assertNotEqual(
            ids.edge_id(relation="same_file", endpoints=["obs_a1", "obs_b2"]),
            ids.edge_id(relation="same_size", endpoints=["obs_a1", "obs_b2"]),
        )

    def test_two_endpoints_required(self):
        for endpoints in ([], ["obs_a1"], ["obs_a1", "obs_b2", "obs_c3"]):
            with self.subTest(endpoints=endpoints):
                with self.assertRaises(ids.IdentityError):
                    ids.edge_id(relation="same_file", endpoints=endpoints)


class TestMappingIdentity(unittest.TestCase):
    def _id(self, technique="T1059.001", quoted=("powershell.exe",)):
        return ids.mapping_id(
            technique_id=technique,
            finding="fnd_aaaaaaaaaaaa",
            cited_observations=["obs_bbbbbbbbbbbb"],
            quoted_values=list(quoted),
        )

    def test_catalogue_version_cannot_reach_the_digest(self):
        """SS8.2 excludes it: *"this is T1059.001"* is unchanged by a catalogue bump,
        so bumping must not rewrite every mapping id in the tree. There is no
        parameter to pass it through."""
        import inspect

        self.assertNotIn("catalogue", inspect.signature(ids.mapping_id).parameters)

    def test_technique_id_is_significant(self):
        self.assertNotEqual(self._id(), self._id(technique="T1569.002"))

    def test_quoted_value_order_does_not_matter(self):
        self.assertEqual(
            self._id(quoted=("powershell.exe", "-enc")),
            self._id(quoted=("-enc", "powershell.exe")),
        )


class TestHypothesisIdentity(unittest.TestCase):
    PREDICTION = {
        "entity": "FILE-SRV-01",
        "role": "observed_on",
        "event_kind": "process_created",
        "source_type": "endpoint",
        "window": ["2026-06-12T09:00:00.000000Z", "2026-06-12T10:00:00.000000Z"],
    }

    def test_status_is_not_identity(self):
        """Status changes -- proposed to confirmed, unconfirmed or uncoverable -- and
        an identity that changed with it would make the hypothesis ledger unjoinable
        to itself, which is exactly what the coverage-gap report reads."""
        before = {
            "id": ids.hypothesis_id(premises=["fnd_aaaaaaaaaaaa"], prediction=self.PREDICTION),
            "status": "proposed",
            "prediction": self.PREDICTION,
        }
        after = dict(before, status="unconfirmed")
        after["id"] = ids.hypothesis_id(premises=["fnd_aaaaaaaaaaaa"], prediction=self.PREDICTION)
        self.assertEqual(before["id"], after["id"])
        self.assertNotEqual(before["status"], after["status"])

    def test_status_inside_the_prediction_is_refused_outright(self):
        """Not merely ignored. Silently dropping it would let a caller believe the
        field was part of identity when it was not."""
        with self.assertRaises(ids.IdentityError):
            ids.hypothesis_id(
                premises=["fnd_aaaaaaaaaaaa"],
                prediction={**self.PREDICTION, "status": "proposed"},
            )

    def test_prediction_content_is_significant(self):
        other = {**self.PREDICTION, "entity": "WKSTN-08"}
        self.assertNotEqual(
            ids.hypothesis_id(premises=["fnd_aaaaaaaaaaaa"], prediction=self.PREDICTION),
            ids.hypothesis_id(premises=["fnd_aaaaaaaaaaaa"], prediction=other),
        )


class TestRecordAndObservationIdentity(unittest.TestCase):
    def test_record_id_covers_the_whole_payload(self):
        payload = {"event_id": "EVT-0046", "username": "jclark"}
        first = ids.record_id(source_type="auth", event_id="EVT-0046", payload=payload)
        second = ids.record_id(
            source_type="auth", event_id="EVT-0046", payload={**payload, "username": "mchen"}
        )
        self.assertNotEqual(first, second)

    def test_observation_id_ignores_when_it_was_made(self):
        """Excluded: created-at and trajectory step. Two runs observing the same
        field of the same record must agree, or the graph would differ between runs
        for no factual reason. Again structural -- no parameter exists."""
        import inspect

        parameters = set(inspect.signature(ids.observation_id).parameters)
        self.assertEqual(parameters, {"record", "field", "normalised_value", "transform"})

    def test_transform_name_is_part_of_identity(self):
        """The same asserted value reached two ways is two observations: invariant 5
        re-applies the recorded transform, so which transform was used is a fact
        about the observation."""
        self.assertNotEqual(
            ids.observation_id(
                record="rec_a", field="file_path", normalised_value="backup.zip", transform="basename"
            ),
            ids.observation_id(
                record="rec_a", field="file_path", normalised_value="backup.zip", transform="identity"
            ),
        )


class TestJsonlRepresentation(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    @staticmethod
    def _corpus(n=500):
        """500 objects, deliberately supplied out of id order and with keys in
        varying order, so sorting is doing work rather than preserving input."""
        out = []
        for i in range(n):
            node_id = ids.node_id("obs", {"i": i})
            out.append(
                {"value": i, "id": node_id, "field": f"f{i % 7}", "nested": {"z": i, "a": -i}}
                if i % 2
                else {"id": node_id, "nested": {"a": -i, "z": i}, "field": f"f{i % 7}", "value": i}
            )
        return out

    def test_write_read_write_is_byte_identical(self):
        corpus = self._corpus()
        first, second = self.tmp / "a.jsonl", self.tmp / "b.jsonl"

        written = jsonl.write(first, corpus)
        self.assertEqual(written, 500)
        jsonl.write(second, jsonl.read(first))

        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_input_order_does_not_change_the_bytes(self):
        """The file is a function of its contents, not of insertion order."""
        corpus = self._corpus()
        first, second = self.tmp / "a.jsonl", self.tmp / "b.jsonl"
        jsonl.write(first, corpus)
        jsonl.write(second, list(reversed(corpus)))
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_no_crlf_anywhere(self):
        """Written on Windows, where text mode would translate every newline."""
        path = self.tmp / "a.jsonl"
        jsonl.write(path, self._corpus())
        raw = path.read_bytes()
        self.assertNotIn(b"\r", raw)
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(raw.count(b"\n"), 500)

    def test_lines_are_sorted_by_id(self):
        path = self.tmp / "a.jsonl"
        jsonl.write(path, self._corpus())
        found = [json.loads(line)["id"] for line in path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(found, sorted(found))

    def test_keys_are_sorted_within_each_line(self):
        path = self.tmp / "a.jsonl"
        jsonl.write(path, [{"id": "obs_aaaaaaaaaaaa", "z": 1, "a": 2, "m": 3}])
        self.assertEqual(
            path.read_text(encoding="utf-8").strip(),
            '{"a": 2, "id": "obs_aaaaaaaaaaaa", "m": 3, "z": 1}',
        )

    def test_default_separators_keep_it_readable(self):
        """D-10 fixes this form as plain `json.dumps(sort_keys, ensure_ascii=False)`
        -- unlike the canonical form, which drops the spaces because it is only
        hashed. Conflating them would give different ids."""
        path = self.tmp / "a.jsonl"
        jsonl.write(path, [{"id": "obs_aaaaaaaaaaaa", "a": 1, "b": 2}])
        line = path.read_text(encoding="utf-8").strip()
        self.assertIn(', "', line)  # space after each comma
        self.assertIn('": ', line)  # space after each colon
        self.assertNotEqual(line, ids.canonical_json({"id": "obs_aaaaaaaaaaaa", "a": 1, "b": 2}))

    def test_non_ascii_round_trips_unescaped(self):
        path = self.tmp / "a.jsonl"
        jsonl.write(path, [{"id": "obs_aaaaaaaaaaaa", "file": "rapport-café.zip"}])
        text = path.read_text(encoding="utf-8")
        self.assertIn("rapport-café.zip", text)
        self.assertNotIn("\\u", text)
        self.assertEqual(jsonl.read(path)[0]["file"], "rapport-café.zip")

    def test_identical_objects_deduplicate(self):
        """The dedup key and the id are one mechanism (SS8.2)."""
        obj = {"id": "obs_aaaaaaaaaaaa", "value": 1}
        path = self.tmp / "a.jsonl"
        self.assertEqual(jsonl.write(path, [obj, dict(obj), obj]), 1)

    def test_one_id_two_payloads_is_refused(self):
        """Under SS8.2 this means an excluded field leaked into a digest -- a bug that
        must not reach a committed artifact."""
        path = self.tmp / "a.jsonl"
        with self.assertRaises(jsonl.IdConflict):
            jsonl.write(path, [{"id": "obs_a", "value": 1}, {"id": "obs_a", "value": 2}])

    def test_missing_id_is_refused(self):
        with self.assertRaises(ValueError):
            jsonl.write(self.tmp / "a.jsonl", [{"value": 1}])

    def test_index_by_id_supports_citation_lookup(self):
        corpus = self._corpus(10)
        index = jsonl.index_by_id(corpus)
        self.assertEqual(len(index), 10)
        self.assertEqual(index[corpus[3]["id"]]["value"], corpus[3]["value"])

    def test_json_artifacts_are_lf_and_key_sorted(self):
        path = self.tmp / "report.json"
        jsonl.write_json(path, {"z": 1, "a": {"y": 2, "b": 3}})
        raw = path.read_bytes()
        self.assertNotIn(b"\r", raw)
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(jsonl.read_json(path), {"z": 1, "a": {"y": 2, "b": 3}})
        self.assertLess(raw.index(b'"a"'), raw.index(b'"z"'))


class TestLineReporter(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def _file_of(self, lines: int) -> Path:
        path = self.tmp / f"mod_{lines}.py"
        path.write_text("\n".join(f"x = {i}" for i in range(lines)) + "\n", encoding="utf-8")
        return path

    def test_counts_physical_lines(self):
        self.assertEqual(loc.count_lines(self._file_of(37)), 37)

    def test_silent_at_the_ceiling(self):
        self._file_of(loc.CEILING)
        self.assertEqual(loc.over_ceiling([self.tmp]), [])

    def test_flags_one_line_over(self):
        self._file_of(loc.CEILING + 1)
        flagged = loc.over_ceiling([self.tmp])
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0][1], loc.CEILING + 1)

    def test_reporting_never_fails_the_build(self):
        """D-09 chose a soft ceiling on purpose: the cheapest way to satisfy a hard
        one is to split a coherent module into two incoherent halves."""
        self._file_of(loc.CEILING + 200)
        self.assertEqual(loc.main([]), 0)

    def test_ceiling_is_four_hundred(self):
        self.assertEqual(loc.CEILING, 400)


if __name__ == "__main__":
    unittest.main()
