"""T02 -- SS8.2's identity table: which fields of which node kind form an id.

Six node kinds, and for four of them SS8.2 *excludes* specific fields. Those
exclusions are the load-bearing part, so each is asserted twice here: once as
the behaviour a caller depends on (reword a finding's statement, its id holds),
and once structurally (`finding_id` has no `statement` parameter, so the prose
has nowhere to go). The second form is the same constrain-don't-validate move
the ATT&CK enum makes at stage 4, applied to identity -- an excluded field
cannot leak in by being forgotten.

`TestIdentityIsStableAcrossProcesses` is the clause that makes a committed id
mean anything at all. The canonical form itself is covered in
`test_kernel_canonical.py`.
"""

from __future__ import annotations

import inspect
import json
import os
import re
import subprocess
import sys
import unittest

import _env  # noqa: F401  -- must precede the package import; puts src/ on sys.path

from siem_investigator import ids

ID_SHAPE = re.compile(r"^(rec|obs|edg|fnd|map|hyp)_[0-9a-f]{12}$")


BUILDER_CALLS: dict[str, tuple[str, dict[str, object]]] = {
    "rec": (
        "record_id",
        {
            "source_type": "cloud_storage",
            "event_id": "EVT-0238",
            "payload": {"file_name": "archive.zip", "file_size_bytes": 2469606195},
        },
    ),
    "obs": (
        "observation_id",
        {
            "record": "rec_0123456789ab",
            "field": "file_path",
            "normalised_value": "archive.zip",
            "transform": "basename",
        },
    ),
    "edg": (
        "edge_id",
        {"relation": "same_file", "endpoints": ["obs_aaaaaaaaaaaa", "obs_bbbbbbbbbbbb"]},
    ),
    "fnd": (
        "finding_id",
        {
            "cited_observations": ["obs_dddddddddddd", "obs_aaaaaaaaaaaa", "obs_cccccccccccc"],
            "cited_edges": ["edg_ffffffffffff", "edg_eeeeeeeeeeee"],
            "stage": "exfiltration",
        },
    ),
    "map": (
        "mapping_id",
        {
            "technique_id": "T1567.002",
            "finding": "fnd_aaaaaaaaaaaa",
            "cited_observations": ["obs_cccccccccccc", "obs_aaaaaaaaaaaa"],
            "quoted_values": ["archive.zip", "external-bucket", "2469606195"],
        },
    ),
    "hyp": (
        "hypothesis_id",
        {
            "premises": ["fnd_bbbbbbbbbbbb", "fnd_aaaaaaaaaaaa"],
            "prediction": {
                "entity": "FILE-SRV-01",
                "role": "observed_on",
                "event_kind": "process_created",
                "source_type": "endpoint",
            },
        },
    ),
}

_SNIPPET = (
    "import json, sys;"
    "sys.path.insert(0, sys.argv[1]);"
    "from siem_investigator import ids;"
    "calls = json.loads(sys.stdin.read());"
    "print(json.dumps({n: getattr(ids, f)(**kw) for n, (f, kw) in calls.items()}, sort_keys=True))"
)


class TestIdentityIsStableAcrossProcesses(unittest.TestCase):
    """The clause that makes a committed id meaningful.

    Every builder is exercised here rather than one flat dict, and that is the
    point: `PYTHONHASHSEED` randomises `str.__hash__`, so set iteration order
    differs between the two processes below. Four of the six builders deduplicate
    their citations through a `set`, and one that fed set *order* into a digest
    would agree with itself within a process and disagree here.
    """

    def _run(self, calls: dict[str, object], seed: str) -> dict[str, str]:
        result = subprocess.run(
            [sys.executable, "-c", _SNIPPET, str(_env.SRC_DIR)],
            input=json.dumps(calls),
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONHASHSEED": seed},
            check=True,
        )
        return json.loads(result.stdout)

    def test_all_six_builders_agree_across_two_hash_seeds(self):
        first = self._run(BUILDER_CALLS, "0")
        second = self._run(BUILDER_CALLS, "524287")
        self.assertEqual(sorted(first), sorted(BUILDER_CALLS))
        for prefix, value in sorted(first.items()):
            with self.subTest(prefix=prefix):
                self.assertRegex(value, ID_SHAPE)
                self.assertTrue(value.startswith(f"{prefix}_"))
        self.assertEqual(first, second, "identity depends on PYTHONHASHSEED")

    def test_the_subprocess_ids_are_the_ids_this_process_computes(self):
        """Without this, the pair above could agree on a wrong answer."""
        expected = {
            name: getattr(ids, function)(**kwargs)
            for name, (function, kwargs) in BUILDER_CALLS.items()
        }
        self.assertEqual(self._run(BUILDER_CALLS, "0"), expected)

    def test_key_order_does_not_matter_across_processes(self):
        orders = [
            {"record": "rec_a", "field": "f", "normalised_value": "v", "transform": "t"},
            {"transform": "t", "record": "rec_a", "field": "f", "normalised_value": "v"},
            {"field": "f", "normalised_value": "v", "transform": "t", "record": "rec_a"},
        ]
        calls = {
            f"order{index}": ["node_id", {"prefix": "obs", "identity_fields": form}]
            for index, form in enumerate(orders)
        }
        produced = set(self._run(calls, "1").values()) | set(self._run(calls, "99991").values())
        self.assertEqual(len(produced), 1, f"one identity, {len(produced)} ids: {produced}")


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

    def test_prose_and_provenance_have_nowhere_to_go(self):
        """SS8.2 excludes `statement`, `rationale`, `proposed_at`, model id, prompt
        hash and provider version. Constrain rather than validate: the signature
        admits three parameters and no more."""
        self.assertEqual(
            set(inspect.signature(ids.finding_id).parameters),
            {"cited_observations", "cited_edges", "stage"},
        )

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

    def test_computed_params_have_nowhere_to_go(self):
        """SS8.2 excludes them: a reported delta-t is derivable from the endpoints,
        so including it adds nothing and churns the id if the time base shifts."""
        self.assertEqual(
            set(inspect.signature(ids.edge_id).parameters), {"relation", "endpoints"}
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
        self.assertEqual(
            set(inspect.signature(ids.mapping_id).parameters),
            {"technique_id", "finding", "cited_observations", "quoted_values"},
        )

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
        after["id"] = ids.hypothesis_id(
            premises=["fnd_aaaaaaaaaaaa"], prediction=self.PREDICTION
        )
        self.assertEqual(before["id"], after["id"])
        self.assertNotEqual(before["status"], after["status"])

    def test_status_inside_the_prediction_is_refused_outright(self):
        """Not merely ignored. Silently dropping it would let a caller believe the
        field was part of identity when it was not."""
        for excluded in ("status", "rationale", "outcome"):
            with self.subTest(field=excluded):
                with self.assertRaises(ids.IdentityError):
                    ids.hypothesis_id(
                        premises=["fnd_aaaaaaaaaaaa"],
                        prediction={**self.PREDICTION, excluded: "proposed"},
                    )

    def test_prediction_content_is_significant(self):
        other = {**self.PREDICTION, "entity": "WKSTN-08"}
        self.assertNotEqual(
            ids.hypothesis_id(premises=["fnd_aaaaaaaaaaaa"], prediction=self.PREDICTION),
            ids.hypothesis_id(premises=["fnd_aaaaaaaaaaaa"], prediction=other),
        )

    def test_premise_order_does_not_matter(self):
        premises = ["fnd_aaaaaaaaaaaa", "fnd_bbbbbbbbbbbb"]
        self.assertEqual(
            ids.hypothesis_id(premises=premises, prediction=self.PREDICTION),
            ids.hypothesis_id(premises=list(reversed(premises)), prediction=self.PREDICTION),
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
        self.assertEqual(
            set(inspect.signature(ids.observation_id).parameters),
            {"record", "field", "normalised_value", "transform"},
        )

    def test_transform_name_is_part_of_identity(self):
        """The same asserted value reached two ways is two observations: invariant 5
        re-applies the recorded transform, so which transform was used is a fact
        about the observation."""
        self.assertNotEqual(
            ids.observation_id(
                record="rec_a",
                field="file_path",
                normalised_value="backup.zip",
                transform="basename",
            ),
            ids.observation_id(
                record="rec_a",
                field="file_path",
                normalised_value="backup.zip",
                transform="identity",
            ),
        )


if __name__ == "__main__":
    unittest.main()
