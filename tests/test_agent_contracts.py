"""T06 -- the four model-site contracts, and the contract-set hash.

What each site may *send* is `tests/test_egress_inventory.py`; this file is
about the contracts themselves: the closed vocabularies, the schema that reaches
the wire, and the two values SS11.1's replay claim needs.

The posture under test is D-08's, and the order in it is the point. A value
outside a vocabulary must be **unrepresentable** rather than rejected after the
fact -- so these tests check the emitted schema and the constructor, not the
error message of a validator.

**What is not tested here, and cannot be.** No live round-trip. There is no
credential in this environment, so "each model returns a populated instance" is
verified for the *return* half only -- `TheContractsParseWhatTheyPromise` parses
a representative payload for every contract through the same
`TypeAdapter.validate_json` the SDK uses. The live call is T06's one blocked
verification and is named as such rather than stubbed: a mocked success proves
the mock, and a fabricated response body is the one thing this must never
manufacture.

Every test in this file runs offline.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import typing
import unittest

import _env  # noqa: F401  -- puts src/ on sys.path

import pydantic

from siem_investigator import ids
from siem_investigator.agent import client, contracts, schemas
from siem_investigator.enrich.catalogue import Catalogue

SCRIPTS = _env.REPO_ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import regen_egress_fixture  # noqa: E402


class TheClosedVocabularies(unittest.TestCase):
    def test_the_stage_enum_is_the_catalogues_tactic_set(self):
        """Not a parallel vocabulary. Stage/tactic consistency at stage 4 becomes
        identity rather than a mapping table that can drift, and the vocabulary is
        versioned by the committed catalogue instead of by this file's opinion."""
        catalogue = Catalogue.load()
        self.assertEqual(
            tuple(sorted(typing.get_args(schemas.IntrusionStage))),
            tuple(sorted(catalogue.tactics)),
        )

    def test_the_stage_enum_uses_v19_2_names(self):
        """v19.2 renamed TA0005 from Defense Evasion to Stealth and added Defense
        Impairment. A vocabulary written from older ATT&CK would pass every other
        test in this file."""
        stages = set(typing.get_args(schemas.IntrusionStage))
        self.assertIn("stealth", stages)
        self.assertIn("defense-impairment", stages)
        self.assertNotIn("defense-evasion", stages)

    def test_eleven_relations_and_no_composite(self):
        """Eleven relation *types*, zero detection rules.

        Design D-07 locked ten. `process_pid` is the eleventh, added after an
        audit found that nothing in the system compared process ids -- so
        EVT-0226 (PowerShell pid 5104 reading LSASS) had **no path at all** to
        EVT-0222 (the creation of pid 5104), and the credential theft could not
        be connected to the shell that performed it.

        It earns the place on the same terms as the other ten: atomic, an exact
        equality between a named field of two records, and it decides nothing.
        What is still forbidden is a composite like `staged_then_uploaded`,
        which would both compute a link and call it exfiltration -- the
        interpretation leak that killed design draft 3.
        """
        relations = set(typing.get_args(schemas.RelationName))
        self.assertEqual(len(relations), 11)
        self.assertEqual(
            relations,
            {
                "same_account",
                "same_host",
                "same_address",
                "same_file",
                "same_size",
                "process_parent",
                "process_pid",
                "temporal_within",
                "flow_endpoint",
                "session_bracket",
                "address_resolves_to_host",
            },
        )
        for name in relations:
            with self.subTest(relation=name):
                self.assertNotIn("_then_", name, "a composite relation interprets")

    def test_the_event_kind_vocabulary_is_the_datasets_own(self):
        """The fix for the worst failure in the build.

        With an open string here, 18 of 24 hypotheses predicted kinds that
        cannot exist -- `authentication/logon`, `endpoint/network_connection` --
        so the search never matched and all 13 misses were reported as verified
        gaps in log coverage. A false claim of blindness tells a reader to stop
        looking, which is worse than a missed detection.
        """
        census = json.loads(
            (_env.FIXTURES_DIR / "dataset_census.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            sorted(typing.get_args(schemas.EventKind)),
            sorted(census["event_kinds"]["counts"]),
        )
        self.assertEqual(
            sorted(typing.get_args(schemas.SourceType)),
            sorted(census["by_source_type"]),
        )

    def test_a_kind_that_cannot_exist_is_unrepresentable(self):
        import pydantic

        with self.assertRaises(pydantic.ValidationError):
            schemas.Hypothesis(
                premises=["fnd_a"],
                predicted_entity="jdavis",
                predicted_role="actor",
                predicted_event_kind="authentication/logon",   # not a real kind
                predicted_source_type="auth",
                window_start="2026-06-10T08:00:00.000000Z",
                window_end="2026-06-13T08:00:00.000000Z",
                rationale="x",
            )

    def test_seek_distinguishes_absent_from_uncovered(self):
        """Without `not_covered`, "not found" conflates absence from the
        environment with blindness of the source."""
        self.assertEqual(
            set(typing.get_args(schemas.SeekOutcome)), {"found", "not_found", "not_covered"}
        )


class TheEmittedSchemas(unittest.TestCase):
    def test_every_site_schema_is_defect_free(self):
        """`additionalProperties: false` at *every* nesting level, a `required`
        list on every object, and no field suggesting a belief value."""
        for site in contracts.SITES:
            with self.subTest(site=site.name):
                self.assertEqual(client.schema_defects(site.wire_schema()), [])

    def test_additional_properties_false_at_every_object_level(self):
        """Checked directly as well as through the defect scan, since this is the
        property a nested object silently loses."""
        for site in contracts.SITES:
            schema = site.wire_schema()
            objects = 0

            def walk(node, path="$"):
                nonlocal objects
                if not isinstance(node, dict):
                    return
                if "properties" in node:
                    objects += 1
                    self.assertIs(
                        node.get("additionalProperties"),
                        False,
                        f"{site.name}{path}: object left open",
                    )
                for name, sub in (node.get("properties") or {}).items():
                    walk(sub, f"{path}.{name}")
                for name, sub in (node.get("$defs") or {}).items():
                    walk(sub, f"{path}.$defs.{name}")
                if "items" in node:
                    walk(node["items"], f"{path}[]")

            walk(schema)
            with self.subTest(site=site.name):
                self.assertGreater(objects, 0, "no object level found to check")

    def test_the_candidate_finding_schema_closes_the_stage(self):
        schema = client.wire_schema(schemas.CandidateFinding)
        stage = schema["properties"]["stage"]
        self.assertIn("enum", stage, "the stage reached the wire without its enum")
        self.assertEqual(set(stage["enum"]), set(typing.get_args(schemas.IntrusionStage)))

    def test_a_stage_outside_the_enum_is_unrepresentable(self):
        with self.assertRaises(pydantic.ValidationError):
            schemas.CandidateFinding(
                statement="x",
                stage="exfiltrationn",  # typo, deliberately
                cites_observations=["obs_a"],
                rationale="y",
            )

    def test_an_unmodelled_field_is_refused(self):
        with self.assertRaises(pydantic.ValidationError):
            schemas.CandidateFinding(
                statement="x",
                stage="exfiltration",
                cites_observations=["obs_a"],
                rationale="y",
                confidence=0.9,  # the field R3.4 forbids, and there is nowhere to put it
            )

    def test_a_finding_citing_nothing_is_refused(self):
        with self.assertRaises(pydantic.ValidationError):
            schemas.CandidateFinding(
                statement="x", stage="exfiltration", cites_observations=[], rationale="y"
            )

    def test_cited_edges_are_objects_with_named_ordered_endpoints(self):
        """Not a tuple. A 2-tuple would emit `prefixItems`, making the ordering
        positional and easy to reverse silently -- and several relations are
        directional."""
        schema = client.wire_schema(schemas.CandidateFinding)
        edge = schema["$defs"]["CitedEdge"]
        self.assertEqual(edge["type"], "object")
        self.assertEqual(
            set(edge["properties"]), {"relation", "from_observation", "to_observation"}
        )
        self.assertNotIn("prefixItems", json.dumps(schema))

    def test_no_schema_carries_a_belief_value(self):
        """R3.4, scanned across all four contracts rather than remembered."""
        for site in contracts.SITES:
            rendered = json.dumps(site.wire_schema()).lower()
            for token in ("probability", "confidence", "percent", "likelihood"):
                with self.subTest(site=site.name, token=token):
                    self.assertNotIn(token, rendered)

    def test_class_docstrings_do_not_reach_the_wire(self):
        """Pydantic uses `__doc__` as the object's schema `description`, so leaving
        it would send this codebase's design commentary to the provider on every
        call -- egress no category in docs/egress.md could honestly cover."""
        for site in contracts.SITES:
            schema = site.wire_schema()
            with self.subTest(site=site.name):
                self.assertNotIn("description", schema)
                # The leak this test was strengthened to catch: `CitedEdge`'s
                # docstring was reaching the API through `$defs`, because
                # stripping only the root looked correct and was not.
                for name, entry in (schema.get("$defs") or {}).items():
                    with self.subTest(definition=name):
                        self.assertNotIn("description", entry)

    def test_field_descriptions_survive_because_they_are_prompt_content(self):
        """The strip must be surgical: a field description is what tells the model
        what the field means, and removing it would quietly degrade every call."""
        schema = client.wire_schema(schemas.CandidateFinding)
        self.assertIn("description", schema["properties"]["statement"])
        self.assertIn("description", schema["$defs"]["CitedEdge"]["properties"]["relation"])


class TheDynamicTechniqueEnum(unittest.TestCase):
    """D-08's constrain-don't-validate move, where it actually matters."""

    CANDIDATES = ("T1059.001", "T1078", "T1569.002")

    def test_the_enum_is_exactly_the_retrieved_candidates(self):
        model = schemas.technique_selection_model(self.CANDIDATES)
        schema = client.wire_schema(model)
        self.assertEqual(schema["properties"]["technique_id"]["enum"], list(self.CANDIDATES))

    def test_a_technique_outside_the_candidates_is_unrepresentable(self):
        model = schemas.technique_selection_model(self.CANDIDATES)
        with self.assertRaises(pydantic.ValidationError):
            model(
                technique_id="T1068",
                technique_name="Exploitation for Privilege Escalation",
                quoted_values=["x"],
                cited_observations=["obs_a"],
            )

    def test_t1068_is_absent_from_a_candidate_set_that_does_not_retrieve_it(self):
        """T1068 exists in the catalogue and must appear in no mapping, because
        nothing in this dataset evidences exploitation for privilege escalation."""
        schema = client.wire_schema(schemas.technique_selection_model(self.CANDIDATES))
        self.assertNotIn("T1068", schema["properties"]["technique_id"]["enum"])

    def test_an_empty_candidate_set_is_refused_rather_than_left_open(self):
        """"We retrieved nothing" is a `non_mappable` outcome for the caller to
        record, not a licence to send an unconstrained field."""
        with self.assertRaises(ValueError):
            schemas.technique_selection_model(())

    def test_duplicate_candidates_collapse(self):
        model = schemas.technique_selection_model(("T1078", "T1078", "T1059.001"))
        self.assertEqual(
            client.wire_schema(model)["properties"]["technique_id"]["enum"],
            ["T1078", "T1059.001"],
        )


class ThePromptHashAndContractSet(unittest.TestCase):
    def test_the_prompt_hash_is_stable_across_two_runs(self):
        first = client.prompt_hash("system text", "user text")
        second = client.prompt_hash("system text", "user text")
        self.assertEqual(first, second)
        self.assertRegex(first, r"^[0-9a-f]{64}$")

    def test_the_prompt_hash_is_stable_across_processes(self):
        """It hashes bytes, not object identity -- so a recorded trajectory stays
        replayable in a later process with a different hash seed."""
        snippet = (
            "import sys; sys.path.insert(0, %r);"
            "from siem_investigator.agent import client;"
            "print(client.prompt_hash('system text', 'user text'))" % str(_env.SRC_DIR)
        )
        out = subprocess.run(
            [__import__("sys").executable, "-c", snippet],
            capture_output=True,
            text=True,
            check=True,
            env={**os.environ, "PYTHONHASHSEED": "7"},
        ).stdout.strip()
        self.assertEqual(out, client.prompt_hash("system text", "user text"))

    def test_a_reworded_prompt_changes_the_hash(self):
        self.assertNotEqual(
            client.prompt_hash("system text", "user text"),
            client.prompt_hash("system text.", "user text"),
        )

    def test_the_contract_set_hash_covers_prompts_and_schemas(self):
        """Hashing only the prompts would miss a widened contract; hashing only
        the schemas would miss a reworded instruction. Either changes what the
        untrusted step does."""
        base = contracts.contract_set()
        self.assertEqual(ids.content_digest(base), contracts.CONTRACT_SET_HASH)

        reworded = json.loads(json.dumps(base))
        reworded["sites"]["interpret"]["system"] += " "
        self.assertNotEqual(ids.content_digest(reworded), contracts.CONTRACT_SET_HASH)

        widened = json.loads(json.dumps(base))
        widened["sites"]["interpret"]["schema"]["properties"]["extra"] = {"type": "string"}
        self.assertNotEqual(ids.content_digest(widened), contracts.CONTRACT_SET_HASH)

    def test_the_stamp_carries_both_replay_inputs(self):
        """SS11.1: a verdict is reproducible given the trajectory, the contract-set
        hash and the validator version. Both of the latter have to be values."""
        stamp = contracts.stamp()
        self.assertEqual(stamp["contract_set_hash"], contracts.CONTRACT_SET_HASH)
        self.assertEqual(stamp["validator_version"], contracts.VALIDATOR_VERSION)
        self.assertIn("software_version", stamp)


class TheContractsParseWhatTheyPromise(unittest.TestCase):
    """The return half of the round-trip, without a model.

    T06 asks that each contract "round-trips and returns a populated instance".
    With no credential in this environment the send half cannot run, so this
    covers the half that can: a representative response payload for each of the
    five contracts, parsed through the same `TypeAdapter.validate_json` the SDK
    calls on the way back, yielding a populated instance.

    Deliberately not a mocked call. A stub that hands back a canned response and
    asserts the canned response arrived proves the stub, and the live call is
    reported as blocked instead.
    """

    #: One payload per contract, as the API would return it.
    PAYLOADS: dict[str, tuple[type[pydantic.BaseModel], dict]] = {
        "CitedEdge": (
            schemas.CitedEdge,
            {
                "relation": "process_parent",
                "from_observation": "obs_000000000001",
                "to_observation": "obs_000000000002",
            },
        ),
        "CandidateFinding": (
            schemas.CandidateFinding,
            {
                "statement": "notepad.exe was created by explorer.exe on WKSTN-08.",
                "stage": "execution",
                "cites_observations": ["obs_000000000001", "obs_000000000002"],
                "cites_edges": [
                    {
                        "relation": "process_parent",
                        "from_observation": "obs_000000000002",
                        "to_observation": "obs_000000000001",
                    }
                ],
                "rationale": "The parent field of one names the process of the other.",
            },
        ),
        "Hypothesis": (
            schemas.Hypothesis,
            {
                "premises": ["fnd_000000000001"],
                "predicted_entity": "WKSTN-08",
                "predicted_role": "observed_on",
                "predicted_event_kind": "auth/user_logon",
                "predicted_source_type": "auth",
                "window_start": "2026-06-13T02:00:00.000000Z",
                "window_end": "2026-06-13T04:00:00.000000Z",
                "rationale": "A process ran under an account, so a session should precede it.",
            },
        ),
        "TechniqueSelection": (
            schemas.TechniqueSelection,
            {
                "technique_id": "T1059.001",
                "technique_name": "PowerShell",
                "quoted_values": ["powershell.exe"],
                "cited_observations": ["obs_000000000001"],
            },
        ),
        "Answer": (
            schemas.Answer,
            {
                "body": "One account appears on that host in the period examined.",
                "claims": [
                    {
                        "text": "The account jclark appears on WKSTN-08.",
                        "kind": "observation",
                        "cites_observations": ["obs_000000000001"],
                    },
                    {
                        "text": "No mail-gateway source is present.",
                        "kind": "absence",
                        "applies_because": "no source in this dataset records mail delivery",
                    },
                ],
                "gaps": ["no DNS source, so an address cannot be resolved to a name"],
            },
        ),
    }

    def test_every_contract_parses_a_representative_payload(self):
        for name, (model, payload) in self.PAYLOADS.items():
            with self.subTest(contract=name):
                adapter = pydantic.TypeAdapter(model)
                instance = adapter.validate_json(json.dumps(payload))
                self.assertIsInstance(instance, model)
                self.assertTrue(instance.model_dump(), "the instance came back empty")

    def test_the_five_named_contracts_are_all_covered(self):
        """T06 names five models. A contract added later without a payload here
        would be a contract nobody parsed."""
        self.assertEqual(
            set(self.PAYLOADS),
            {model.__name__ for model in schemas.CONTRACT_MODELS} | {"CitedEdge"},
        )

    def test_the_nested_edge_parses_as_an_object_within_a_finding(self):
        """The nesting is the part D-08 flagged: if a list of edge objects could
        not be expressed strictly, the native-parse choice would change."""
        _, payload = self.PAYLOADS["CandidateFinding"]
        finding = schemas.CandidateFinding.model_validate(payload)
        self.assertIsInstance(finding.cites_edges[0], schemas.CitedEdge)
        self.assertEqual(finding.cites_edges[0].relation, "process_parent")

    def test_an_answer_claim_keeps_its_citation_lists_distinct(self):
        _, payload = self.PAYLOADS["Answer"]
        answer = schemas.Answer.model_validate(payload)
        self.assertEqual(answer.claims[0].cites_observations, ["obs_000000000001"])
        self.assertEqual(answer.claims[0].cites_findings, [])
        self.assertIsNone(answer.claims[0].applies_because)


class TheClosedFieldsReachTheWire(unittest.TestCase):
    """Every closed field, not the two that were spot-checked.

    The SDK's transform drops `enum`, so "structurally unrepresentable" holds
    only where the repair put it back. Checking `stage` and `technique_id` by
    hand leaves `relation`, `predicted_role` and `kind` unverified -- and each
    is a place a value outside the vocabulary could arrive and be accepted.
    """

    @staticmethod
    def _enum_paths(schema: dict, path: str = "$") -> dict[str, list]:
        found: dict[str, list] = {}
        if not isinstance(schema, dict):
            return found
        if "enum" in schema:
            found[path] = schema["enum"]
        for name, sub in (schema.get("properties") or {}).items():
            found.update(TheClosedFieldsReachTheWire._enum_paths(sub, f"{path}.{name}"))
        for name, sub in (schema.get("$defs") or {}).items():
            found.update(TheClosedFieldsReachTheWire._enum_paths(sub, f"{path}.$defs.{name}"))
        if "items" in schema:
            found.update(TheClosedFieldsReachTheWire._enum_paths(schema["items"], f"{path}[]"))
        return found

    def test_every_literal_in_every_contract_keeps_its_enum_on_the_wire(self):
        for site in contracts.SITES:
            model = regen_egress_fixture.model_type_for(site)
            pydantic_enums = self._enum_paths(model.model_json_schema())
            wire_enums = self._enum_paths(client.wire_schema(model))
            with self.subTest(site=site.name):
                self.assertTrue(pydantic_enums, "this contract closes no field at all")
                self.assertEqual(wire_enums, pydantic_enums)

    def test_the_closed_fields_are_the_ones_the_design_names(self):
        """Named rather than counted, so a vocabulary quietly opened to a bare
        string shows up here."""
        closed = set()
        for site in contracts.SITES:
            schema = client.wire_schema(regen_egress_fixture.model_type_for(site))
            closed.update(path.rsplit(".", 1)[-1] for path in self._enum_paths(schema))
        self.assertEqual(
            closed,
            {
                "stage",
                "relation",
                "predicted_role",
                "technique_id",
                "kind",
                # Closed at P0. With these two open, 18 of 24 hypotheses
                # predicted event kinds that cannot exist, so the search never
                # matched and all 13 misses were published as verified gaps in
                # log coverage.
                "predicted_event_kind",
                "predicted_source_type",
            },
        )

    def test_no_contract_carries_a_belief_value_at_any_depth(self):
        """R3.4, over every model including the nested ones -- a `confidence`
        added to `CitedEdge` reaches the wire just as surely as one added to
        `CandidateFinding`, and is the easier one to miss on review."""
        for model in schemas.ALL_CONTRACT_MODELS:
            with self.subTest(contract=model.__name__):
                self.assertEqual(client.schema_defects(client.wire_schema(model)), [])
                rendered = json.dumps(client.wire_schema(model)).lower()
                for token in ("probability", "confidence", "percent", "likelihood"):
                    self.assertNotIn(token, rendered)

    def test_the_prompts_may_say_the_words_the_schemas_may_not(self):
        """Stated so nobody "strengthens" the scan into scanning the whole body.
        The system prompt forbids belief language in so many words, so it
        contains those words; a schema *field* carrying one is the violation."""
        self.assertIn("confidence level", contracts.COMMON_SYSTEM)
        self.assertEqual(client.schema_defects(contracts.ANSWER.wire_schema()), [])


class TheAnswerContractMatchesTheRenderedPayload(unittest.TestCase):
    """T07 committed the payload contract; T06 defines what the model may return.

    They are different shapes on purpose -- support labels and record ids are
    computed, never returned -- but where they share a key they have to agree,
    and where they must not share one the names have to differ.
    """

    PAYLOAD_CONTRACT = _env.REPO_ROOT / "docs" / "specs" / "answer_payload.md"

    def test_the_claim_kinds_the_model_may_return_are_the_rendered_ones(self):
        kinds = set(typing.get_args(schemas.AnswerClaim.model_fields["kind"].annotation))
        self.assertEqual(kinds, {"observation", "attribution", "absence", "recommendation"})

    def test_the_model_cannot_return_the_payloads_basis_object(self):
        """`app/components/citation.py` reads `basis` with `.get`. A string under
        that key would crash the renderer, and before that it would be a
        model-invented basis name -- so the field the model fills is
        `applies_because`, and there is no `basis` to copy through."""
        self.assertNotIn("basis", schemas.AnswerClaim.model_fields)
        self.assertIn("applies_because", schemas.AnswerClaim.model_fields)

    def test_the_model_cannot_return_a_support_label(self):
        """R3.4: the label is counted from the structure of the support. A
        model-asserted one would be an opinion wearing the clothes of a
        measurement."""
        for forbidden in ("support", "label", "flags", "claim_id", "answer_id"):
            with self.subTest(field=forbidden):
                self.assertNotIn(forbidden, schemas.AnswerClaim.model_fields)
                self.assertNotIn(forbidden, schemas.Answer.model_fields)

    def test_the_payload_contract_is_still_the_one_this_was_written_against(self):
        """A cheap tripwire. If the renderer stops reading `basis` as an object
        the reasoning above changes, and this is where to notice."""
        text = self.PAYLOAD_CONTRACT.read_text(encoding="utf-8")
        self.assertIn('"basis": {', text)
        self.assertIn("applies_because", text)

class TheLiveRoundTripScript(unittest.TestCase):
    """The one verification that needs a credential, and its offline behaviour.

    `scripts/live_round_trip.py` is where T06's "each model round-trips and
    returns a populated instance" is checked, because that claim cannot be
    checked without a key and must not be stubbed. What *can* be tested here is
    everything up to the call, and that the no-credential path is a clean exit
    rather than a traceback -- NFR-02 makes running without a key an ordinary
    state.
    """

    SCRIPT = _env.REPO_ROOT / "scripts" / "live_round_trip.py"

    def _run(self, *args, credential: str | None = None):
        environment = {key: value for key, value in os.environ.items()}
        environment.pop("ANTHROPIC_API_KEY", None)
        environment.pop("ANTHROPIC_AUTH_TOKEN", None)
        if credential is not None:
            environment["ANTHROPIC_API_KEY"] = credential
        return subprocess.run(
            [sys.executable, str(self.SCRIPT), *args],
            cwd=_env.REPO_ROOT,
            capture_output=True,
            text=True,
            env=environment,
        )

    def test_the_dry_run_builds_every_request_with_no_credential(self):
        result = self._run("--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        for site in contracts.SITES:
            with self.subTest(site=site.name):
                self.assertIn(site.name, result.stdout)
        self.assertIn(contracts.CONTRACT_SET_HASH[:12], result.stdout)

    def test_a_missing_credential_is_one_line_and_no_traceback(self):
        result = self._run()
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(len(result.stderr.strip().splitlines()), 1)
        self.assertIn("ANTHROPIC_API_KEY", result.stderr)

    def test_it_sends_the_payload_the_fixture_documents(self):
        """Otherwise the live check would prove a request the inventory does not
        describe, which is the failure `docs/egress.md` exists to prevent."""
        source = self.SCRIPT.read_text(encoding="utf-8")
        self.assertIn("regen_egress_fixture", source)
        self.assertIn("client.call(", source)


if __name__ == "__main__":
    unittest.main()
