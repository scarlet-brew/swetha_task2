"""The deterministic pipeline, end to end, and accuracy against the labels.

Runs the whole build with `--no-model`, so it needs no credential and no
network. The interpretive layer is the scripted stub, which is exactly the
split T21 wanted: if the mechanism works here and fails with the model, the
fault is the prompt.

`TheAccuracyGate` is the only place in the test suite that reads
`ground_truth.json`, which R7.2 admits for accuracy measurement and nothing
else. It measures against whatever artifacts are committed -- so after a
model-backed build it reports that run's numbers.
"""

from __future__ import annotations

import json
import unittest

import _env  # noqa: F401

from siem_investigator import jsonl, paths
from siem_investigator.correlate import anchors, relations, stub, validate
from siem_investigator.evidence import close, graph, observations as obsmod, synthesise
from siem_investigator.ingest import load, parse, transforms


class ThePipelineRunsWithoutACredential(unittest.TestCase):
    """NFR-02: the deterministic stages do not need the model."""

    @classmethod
    def setUpClass(cls):
        cls.records, cls.ingest_report = load.run(write=False)
        cls.parsed = parse.run(cls.records, write=False)
        cls.observations = obsmod.build(
            cls.records, cls.parsed["provenance"], cls.parsed["references"]
        )
        cls.index = relations.RelationIndex(cls.observations, cls.parsed["resolution"])
        cls.edges = cls.index.materialise_sparse()

    def test_ingest_is_lossless_and_strips_the_annotation(self):
        self.assertEqual(self.ingest_report["counts"]["events_in"], 242)
        self.assertEqual(self.ingest_report["counts"]["records_out"], 242)
        self.assertEqual(self.ingest_report["counts"]["annotations_stripped"], 22)
        blob = json.dumps(self.records)
        self.assertNotIn("ATTACK:", blob)
        self.assertNotIn('"note"', blob)

    def test_invariant_4_grounding(self):
        self.assertEqual(obsmod.grounding_failures(self.observations, self.records), [])

    def test_invariant_5_reproducibility(self):
        self.assertEqual(transforms.check_all(self.parsed["provenance"]), [])

    def test_every_transform_used_is_registered(self):
        for entry in self.parsed["provenance"]:
            self.assertIn(entry["transform"], transforms.REGISTRY)

    def test_address_resolution_keeps_candidates(self):
        """Only three hosts have a single stable address, and they are the
        compromised ones -- so collapsing to one answer would rediscover the
        intrusion by construction."""
        ambiguous = [row for row in self.parsed["resolution"] if row["ambiguous"]]
        self.assertTrue(ambiguous, "expected at least one ambiguous address")
        for row in self.parsed["resolution"]:
            self.assertEqual(row["candidate_count"], len(row["candidates"]))

    def test_the_central_relation_claim_holds_in_real_code(self):
        """SS3.6: exact byte count carries the cross-source file relation.
        T09 froze these numbers from the raw data; this reproduces them through
        the actual relation functions."""
        same_size = [edge for edge in self.edges if edge["relation"] == "same_size"]
        cross = {
            tuple(sorted((edge["from_event"], edge["to_event"])))
            for edge in same_size
            if self.index.by_id[edge["from_observation"]]["source_type"]
            != self.index.by_id[edge["to_observation"]]["source_type"]
        }
        self.assertIn(("EVT-0237", "EVT-0238"), cross)

    def test_the_deletion_pair_carries_no_size_relation(self):
        """EVT-0239 names the file but does not size it. Absent is not equal."""
        pairs = {
            tuple(sorted((edge["from_event"], edge["to_event"])))
            for edge in self.edges
            if edge["relation"] == "same_size"
        }
        self.assertNotIn(("EVT-0238", "EVT-0239"), pairs)

    def test_anchors_order_and_never_filter(self):
        order = anchors.ranked(self.observations, self.edges)
        self.assertEqual(len(order), len(self.observations))
        self.assertEqual(len(set(order)), len(self.observations))

    def test_anchors_are_independent_of_all_three_leaks(self):
        report = anchors.leak_independence(self.observations, self.edges)
        for leak in ("note_field", "timestamp_precision", "event_id_ordering"):
            with self.subTest(leak=leak):
                self.assertTrue(report[leak]["independent"], report[leak])

    def test_the_loop_runs_against_the_stub_and_produces_a_valid_graph(self):
        from siem_investigator.correlate import loop

        ledger = loop.run(
            observations=self.observations,
            edges=self.edges,
            index=self.index,
            interpreter=stub.StubInterpreter(self.index),
            entities=self.parsed["entities"],
            max_steps=30,
        )
        self.assertTrue(ledger.findings, "the stub produced no findings at all")

        closed = close.close(ledger.findings, self.observations)
        self.assertTrue(closed["check_6_mutual_compatibility"]["holds"])

        investigation = graph.Graph()
        for record in self.records:
            investigation.add(record, layer="record")
        for observation in self.observations:
            investigation.add(observation, layer="observation", cites=[observation["record"]])
        # The traversed edges as well as the materialised sparse ones: a
        # finding cites whichever edges the loop actually used, and a graph
        # missing those fails invariant 1 for the wrong reason.
        for edge in list(self.edges) + list(ledger.edges_traversed.values()):
            investigation.add(
                edge, layer="edge", cites=[edge["from_observation"], edge["to_observation"]]
            )
        for finding in closed["findings"]:
            investigation.add(
                finding,
                layer="finding",
                cites=finding["cites_observations"] + finding["cites_edges"],
            )

        checks = investigation.check_all()
        self.assertTrue(checks["invariant_1_layer_order"]["holds"], checks["invariant_1_layer_order"])
        self.assertTrue(checks["invariant_2_termination"]["holds"], checks["invariant_2_termination"])
        self.assertIsNone(checks["invariant_3_acyclicity"]["cycle_path"])

    def test_every_record_is_examined_when_no_budget_is_set(self):
        """The instrument that was missing. Three builds passed every invariant
        while 93 of 242 records were never shown to the model, because a record
        whose top-ranked field had no linking neighbour was marked done and
        skipped, and nothing counted what was skipped. With no budget, coverage
        is total, and the loop says so."""
        from siem_investigator.correlate import loop

        ledger = loop.run(
            observations=self.observations,
            edges=self.edges,
            index=self.index,
            interpreter=stub.StubInterpreter(self.index),
            entities=self.parsed["entities"],
            max_steps=None,
        )
        self.assertEqual(ledger.coverage["records_not_examined"], 0, ledger.coverage)
        self.assertEqual(ledger.coverage["records_examined"], ledger.coverage["records_total"])
        examined = {
            self.index.by_id[step["observation"]]["record"]
            for step in ledger.trajectory
            if step.get("action") == "interpret"
        }
        self.assertEqual(len(examined), ledger.coverage["records_total"])

    def test_a_failed_model_call_is_not_a_verdict(self):
        """A credit outage once produced 242 'nothing here' outcomes and an
        all-green empty build. A failure is recorded as a failure."""
        from siem_investigator.correlate import loop

        class Failing:
            def interpret(self, neighbourhood, context):
                return {"error": "BadRequestError: credit balance is too low"}

            def hypothesise(self, findings, context):
                return None

        ledger = loop.run(
            observations=self.observations,
            edges=self.edges,
            index=self.index,
            interpreter=Failing(),
            entities=self.parsed["entities"],
            max_steps=4,
        )
        outcomes = {step["outcome"] for step in ledger.trajectory if step.get("action") == "interpret"}
        self.assertEqual(outcomes, {"call_failed"})
        self.assertEqual(ledger.coverage["records_with_failed_model_calls"], 4)
        self.assertIn("credit", ledger.coverage["first_failure"])

    def test_a_record_neighbourhood_spans_every_field_of_the_record(self):
        """A payload field carries no linking relation; the record still does.
        The union over its fields is what the model must see."""
        payload = next(
            o for o in self.observations
            if o["field"] == "command_line" and o["entity_type"] is not None
        )
        whole = self.index.neighbourhood(payload["id"], k=8)["relations"]
        self.assertTrue(whole, "a command line's record shares an account or host with something")
        for relation, data in whole.items():
            for row in data["observations"]:
                holds, _ = self.index.evaluate(
                    relation, row["from_observation"], row["to_observation"]
                )
                self.assertTrue(holds, (relation, row))


class TheValidatorRejectsWhatItShould(unittest.TestCase):
    """The adversarial corpus. Each of these must be refused, by name."""

    @classmethod
    def setUpClass(cls):
        records, _ = load.run(write=False)
        parsed = parse.run(records, write=False)
        observations = obsmod.build(records, parsed["provenance"], parsed["references"])
        cls.index = relations.RelationIndex(observations, parsed["resolution"])
        cls.real = observations[0]["id"]
        cls.other = observations[1]["id"]

    def _base(self, **overrides):
        return {
            "statement": "Something happened.",
            "stage": "execution",
            "cites_observations": [self.real],
            "cites_edges": [],
            "rationale": "because",
            **overrides,
        }

    def test_a_nonexistent_observation_is_refused(self):
        verdict = validate.validate(self._base(cites_observations=["obs_deadbeefcafe"]), index=self.index)
        self.assertFalse(verdict.accepted)
        self.assertFalse(verdict.checks["1_observations_exist"])

    def test_an_edge_that_does_not_hold_is_refused(self):
        verdict = validate.validate(
            self._base(
                cites_observations=[self.real, self.other],
                cites_edges=[
                    {
                        "relation": "same_size",
                        "from_observation": self.real,
                        "to_observation": self.other,
                    }
                ],
            ),
            index=self.index,
        )
        self.assertFalse(verdict.accepted)
        self.assertFalse(verdict.checks["2_edges_reevaluate"])

    def test_an_invented_identifier_is_refused_and_named(self):
        verdict = validate.validate(
            self._base(statement="PSEXESVC.EXE ran on WKSTN-99 and contacted 203.0.113.7."),
            index=self.index,
        )
        self.assertFalse(verdict.accepted)
        self.assertFalse(verdict.checks["3_no_invented_identifier"])
        self.assertTrue(
            any("WKSTN-99" in d or "203.0.113.7" in d for d in verdict.diagnostics),
            verdict.diagnostics,
        )

    def test_an_edge_whose_endpoint_is_not_cited_is_refused(self):
        verdict = validate.validate(
            self._base(
                cites_observations=[self.real],
                cites_edges=[
                    {
                        "relation": "temporal_within",
                        "from_observation": self.real,
                        "to_observation": self.other,
                    }
                ],
            ),
            index=self.index,
        )
        self.assertFalse(verdict.accepted)
        self.assertFalse(verdict.checks["3b_basis_roles_fulfilled"])

    def test_a_stage_outside_the_vocabulary_is_refused(self):
        verdict = validate.validate(self._base(stage="pivoting"), index=self.index)
        self.assertFalse(verdict.accepted)
        self.assertFalse(verdict.checks["4_stage_in_vocabulary"])

    def test_belief_language_is_refused(self):
        """R3.4 -- support is computed from evidence structure, never asserted."""
        for phrasing in (
            "The account was probably compromised.",
            "This is 87% likely to be exfiltration.",
            "We are confident the attacker moved laterally.",
        ):
            with self.subTest(phrasing=phrasing):
                verdict = validate.validate(self._base(statement=phrasing), index=self.index)
                self.assertFalse(verdict.accepted)
                self.assertFalse(verdict.checks["r3_4_no_belief_language"])

    def test_a_grounded_proposal_is_accepted(self):
        """The corpus has to contain a positive, or it only proves the validator
        says no."""
        observation = self.index.by_id[self.real]
        verdict = validate.validate(
            self._base(statement=f"Event {observation['event_id']} was recorded."),
            index=self.index,
        )
        self.assertTrue(verdict.accepted, verdict.diagnostics)

    def test_a_known_name_inside_a_cited_value_is_grounded(self):
        """`powershell.exe` inside a cited command line is on the record. The
        entity lookup refused it by equality and took the initial-access
        finding with it, twice, on a diagnostic that was simply false."""
        command = next(
            o
            for o in self.index.observations
            if o["field"] == "command_line"
            and "powershell.exe" in str(o["normalised_value"]).lower()
        )
        verdict = validate.validate(
            self._base(
                cites_observations=[command["id"]],
                statement=f"Event {command['event_id']} ran a command naming powershell.exe.",
            ),
            index=self.index,
        )
        self.assertTrue(verdict.checks["3_no_invented_identifier"], verdict.diagnostics)

    def test_every_rejection_carries_a_specific_diagnostic(self):
        # `file-srv-02` rather than `WKSTN-99`: entity names are now checked by
        # lookup against the graph, not by shape, so a host that exists nowhere
        # in 242 records is prose and is correctly left alone. A host that does
        # exist, named by a finding that never cited it, is the misattribution
        # worth catching.
        verdict = validate.validate(
            self._base(statement="file-srv-02 did something.", stage="pivoting"),
            index=self.index,
        )
        self.assertFalse(verdict.accepted)
        self.assertGreaterEqual(len(verdict.diagnostics), 2)
        for diagnostic in verdict.diagnostics:
            self.assertGreater(len(diagnostic), 20, "a diagnostic must say what went wrong")


class TheCommittedArtifactsAreSound(unittest.TestCase):
    """Whatever build last ran, its artifacts must satisfy the invariants."""

    @classmethod
    def setUpClass(cls):
        if not paths.MANIFEST.exists():
            raise unittest.SkipTest("no build has run; `python -m siem_investigator.build`")
        cls.manifest = jsonl.read_json(paths.MANIFEST)
        cls.findings = jsonl.read(paths.FINDINGS)
        cls.observations = jsonl.index_by_id(jsonl.read(paths.OBSERVATIONS))
        cls.mappings = jsonl.read(paths.MAPPINGS)

    def test_the_manifest_records_both_replay_inputs(self):
        self.assertIn("contract_set_hash", self.manifest)
        self.assertIn("validator_version", self.manifest)

    def test_every_stage_reported_its_verification(self):
        for stage in ("01_ingest", "02_parse", "03_correlate", "04_enrich", "05_synthesise"):
            self.assertIn(stage, self.manifest["stage_verification"])

    def test_every_finding_cites_resolvable_observations(self):
        for finding in self.findings:
            self.assertTrue(finding["cites_observations"])
            for obs in finding["cites_observations"]:
                self.assertIn(obs, self.observations)

    def test_no_finding_carries_a_number_for_support(self):
        for finding in self.findings:
            self.assertIn(finding["support"]["label"], close.LABELS)

    def test_no_artifact_mentions_a_probability(self):
        """R3.4, over the emitted artifacts rather than the schemas."""
        for path in (paths.FINDINGS, paths.TIMELINE, paths.SCOPE, paths.MAPPINGS):
            if not path.exists():
                continue
            text = path.read_text(encoding="utf-8").lower()
            with self.subTest(path=path.name):
                for token in ("probability", "confidence", "% likely"):
                    self.assertNotIn(token, text)

    def test_t1068_is_mapped_by_nothing(self):
        """No record evidences exploitation for privilege escalation."""
        self.assertNotIn("T1068", {mapping["technique_id"] for mapping in self.mappings})

    def test_no_artifact_contains_the_annotation(self):
        for path in paths.DERIVED.glob("*.jsonl"):
            with self.subTest(path=path.name):
                self.assertNotIn("ATTACK:", path.read_text(encoding="utf-8"))


class TheAccuracyGate(unittest.TestCase):
    """Recall and precision against the labelled set (R7.2, T30).

    Evaluation reads labels only after reconstruction. Coverage of labelled
    records includes context; action-event precision counts only events
    explicitly presented as incident behaviours. Neither proves claim semantics.
    """

    def _measure(self):
        if not paths.FINDINGS.exists():
            self.skipTest("no build has run")
        truth = set(
            json.loads((_env.FIXTURES_DIR / "ground_truth.json").read_text(encoding="utf-8"))[
                "attack_event_ids"
            ]
        )
        findings = jsonl.read(paths.FINDINGS)
        cited = {event for finding in findings for event in finding["event_ids"]}
        if paths.TIMELINE.exists():
            timeline = jsonl.read_json(paths.TIMELINE)
            cited.update(e["event_id"] for e in timeline.get("events", []) if e["disposition"] in ("finding", "context"))
        subjects = {event for finding in findings for event in finding.get("subject_event_ids", finding["event_ids"])}
        self.assertTrue(cited, "the labelled incident was not reconstructed")
        self.assertTrue(subjects, "no incident actions were reconstructed")
        recall = len(truth & cited) / len(truth)
        precision = len(truth & subjects) / len(subjects)
        subject_recall = len(truth & subjects) / len(truth)
        print(f"\n  [accuracy] labelled-event evidence coverage {recall:.0%}; action-event precision {precision:.0%}; action-event recall {subject_recall:.0%}")
        return recall, precision

    def test_recall_floor(self):
        # Coverage includes clearly identified context, such as the final logoff.
        recall, _ = self._measure()
        self.assertGreaterEqual(recall, 0.80, f"labelled-event evidence coverage fell to {recall:.0%}")

    def test_precision_floor(self):
        # Context must not be promoted to attack actions just to satisfy a count.
        _, precision = self._measure()
        self.assertGreaterEqual(precision, 0.70, f"action-event precision is {precision:.0%}")


if __name__ == "__main__":
    unittest.main()
