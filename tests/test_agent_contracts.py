"""T06 -- the three model-site contracts, the contract-set hash, the egress inventory.

The load-bearing test here is `TheCapturedRequestBody`. NFR-04 has two halves:
the model sites are documented, and the documentation is *true*. A document
cannot establish the second about itself, so the real serialised request body
for each site is captured through a mock transport and checked against
`docs/egress.md`. Nothing leaves the process and no credential is needed.

Every test in this file runs offline.
"""

from __future__ import annotations

import json
import subprocess
import typing
import unittest

import _env  # noqa: F401  -- puts src/ on sys.path

from siem_investigator import ids
from siem_investigator.agent import client, contracts, schemas
from siem_investigator.enrich.catalogue import Catalogue

EGRESS_DOC = _env.REPO_ROOT / "docs" / "egress.md"


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

    def test_ten_relations_and_no_composite(self):
        """Ten relation *types*, zero detection rules. A composite like
        `staged_then_uploaded` would both compute a link and call it exfiltration
        -- the interpretation leak that killed design draft 3."""
        relations = set(typing.get_args(schemas.RelationName))
        self.assertEqual(len(relations), 10)
        self.assertEqual(
            relations,
            {
                "same_account",
                "same_host",
                "same_address",
                "same_file",
                "same_size",
                "process_parent",
                "temporal_within",
                "flow_endpoint",
                "session_bracket",
                "address_resolves_to_host",
            },
        )
        for name in relations:
            with self.subTest(relation=name):
                self.assertNotIn("_then_", name, "a composite relation interprets")

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
        import pydantic

        with self.assertRaises(pydantic.ValidationError):
            schemas.CandidateFinding(
                statement="x",
                stage="exfiltrationn",  # typo, deliberately
                cites_observations=["obs_a"],
                rationale="y",
            )

    def test_an_unmodelled_field_is_refused(self):
        import pydantic

        with self.assertRaises(pydantic.ValidationError):
            schemas.CandidateFinding(
                statement="x",
                stage="exfiltration",
                cites_observations=["obs_a"],
                rationale="y",
                confidence=0.9,  # the field R3.4 forbids, and there is nowhere to put it
            )

    def test_a_finding_citing_nothing_is_refused(self):
        import pydantic

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
        import pydantic

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
        import os

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


class TheCapturedRequestBody(unittest.TestCase):
    """NFR-04's second half, tested rather than described.

    The capture goes through the same `_request_kwargs` the live call uses.
    Building the request twice is exactly what would let this inventory describe
    a request the system does not send.
    """

    #: Keys the Messages API body legitimately carries. Anything else appearing
    #: is an unreviewed field reaching the provider.
    ALLOWED_TOP_LEVEL = {
        "model",
        "max_tokens",
        "system",
        "messages",
        "thinking",
        "output_config",
        "stream",
        "metadata",
    }

    def _body(self, site: contracts.Site) -> dict:
        model_type = site.model_type
        if site is contracts.SELECT_TECHNIQUE:
            model_type = schemas.technique_selection_model(("T1059.001", "T1078"))
        return client.captured_request_body(
            model_type=model_type,
            system=site.system,
            user="OBSERVATIONS\nobs_a  endpoint  process_name  powershell.exe\n",
        )

    def test_every_site_builds_a_request_with_no_credential_and_no_network(self):
        for site in contracts.SITES:
            with self.subTest(site=site.name):
                body = self._body(site)
                self.assertEqual(body["model"], client.MODEL_ID)
                self.assertEqual(body["thinking"], {"type": "adaptive"})

    def test_no_field_outside_the_documented_api_surface_is_sent(self):
        for site in contracts.SITES:
            body = self._body(site)
            with self.subTest(site=site.name):
                self.assertEqual(
                    set(body) - self.ALLOWED_TOP_LEVEL,
                    set(),
                    "an unreviewed top-level field is reaching the provider",
                )

    def test_the_repaired_schema_is_what_actually_goes_out(self):
        """The measured SDK behaviour this guards: `transform_schema` discards
        `enum`, so without the repair a closed Literal arrives as a description
        hint and a hallucinated value is accepted by the API. `wire_schema` says
        what we intend to send; this says what the SDK does."""
        body = self._body(contracts.SELECT_TECHNIQUE)
        self.assertEqual(client.request_defects(body), [])
        sent = body["output_config"]["format"]["schema"]
        self.assertEqual(sent["properties"]["technique_id"]["enum"], ["T1059.001", "T1078"])

    def test_the_stage_enum_survives_to_the_wire_for_interpret(self):
        body = self._body(contracts.INTERPRET)
        sent = body["output_config"]["format"]["schema"]
        self.assertIn("enum", sent["properties"]["stage"])

    def test_the_body_carries_no_raw_note_field(self):
        """The dataset's answer key is stripped at the parse boundary, so no
        prompt can contain it."""
        for site in contracts.SITES:
            rendered = json.dumps(self._body(site))
            with self.subTest(site=site.name):
                self.assertNotIn("ATTACK:", rendered)

    def test_the_body_carries_no_credential(self):
        for site in contracts.SITES:
            rendered = json.dumps(self._body(site)).lower()
            with self.subTest(site=site.name):
                self.assertNotIn("sk-ant", rendered)
                self.assertNotIn("api_key", rendered)


class TheEgressInventoryIsComplete(unittest.TestCase):
    def test_exactly_three_model_stages(self):
        """Design SS7's claim, as a test. A fourth stage appearing without a
        documented egress category is what the inventory exists to catch."""
        self.assertEqual(len(contracts.MODEL_STAGES), 3)

    def test_every_site_appears_in_the_egress_doc(self):
        text = EGRESS_DOC.read_text(encoding="utf-8")
        for site in contracts.SITES:
            with self.subTest(site=site.name):
                self.assertIn(f"`{site.name}`", text)

    def test_every_declared_category_appears_in_the_egress_doc(self):
        """A category named in code but not in the document would be undocumented
        egress, which is the NFR-04 failure."""
        text = EGRESS_DOC.read_text(encoding="utf-8").lower()
        for site in contracts.SITES:
            for category in site.egress_categories:
                with self.subTest(site=site.name, category=category):
                    # Match on the distinctive head of the phrase; the document
                    # renders these as table prose rather than verbatim strings.
                    head = " ".join(category.lower().split()[:3])
                    self.assertIn(head, text, f"{category!r} is not documented")

    def test_every_site_declares_at_least_one_category(self):
        for site in contracts.SITES:
            with self.subTest(site=site.name):
                self.assertTrue(site.egress_categories)

    def test_the_doc_names_what_is_never_sent(self):
        text = EGRESS_DOC.read_text(encoding="utf-8")
        for absent in ("ground_truth.json", "`note`", "credential"):
            with self.subTest(item=absent):
                self.assertIn(absent, text)


class TheQueryPlaneCannotReachTheService(unittest.TestCase):
    def test_no_app_module_names_anthropic(self):
        result = subprocess.run(
            ["git", "grep", "-n", "--untracked", "anthropic", "--", "app/"],
            cwd=_env.REPO_ROOT,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_the_credential_is_read_from_the_environment_only(self):
        self.assertEqual(client.CREDENTIAL_VARIABLE, "ANTHROPIC_API_KEY")
        source = (_env.SRC_DIR / "siem_investigator/agent/client.py").read_text(encoding="utf-8")
        self.assertIn("os.environ", source)
        self.assertNotIn(".env", source.replace("environ", ""))

    def test_a_missing_credential_raises_one_line_not_a_traceback(self):
        import os

        saved = os.environ.pop(client.CREDENTIAL_VARIABLE, None)
        try:
            self.assertFalse(client.credential_present())
            with self.assertRaises(client.CredentialMissing) as caught:
                client.call(
                    site="interpret",
                    model_type=schemas.CandidateFinding,
                    system="s",
                    user="u",
                )
            self.assertIn("ANTHROPIC_API_KEY", str(caught.exception))
        finally:
            if saved is not None:
                os.environ[client.CREDENTIAL_VARIABLE] = saved


if __name__ == "__main__":
    unittest.main()
