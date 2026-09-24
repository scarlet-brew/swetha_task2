"""Stage-5 projections, checked against the standards they claim to meet.

This file exists because of a specific failure. Design D-04 says the Attack Flow
export "validates against the vendored schema", three separate plan
verifications repeat it, and **all 26 objects failed** -- unnoticed, because
nothing ever ran the validator. A claim about conformance that no test makes is
a claim about intent.

Everything here runs offline: the schema's remote `$ref` closure is vendored and
preloaded into a registry, which is the whole reason T03 fetched 13 extra
documents.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

import _env  # noqa: F401

from siem_investigator import jsonl, paths


def offline_validator():
    """A Draft 2020-12 validator with the vendored closure preloaded.

    Without the registry, `jsonschema` resolves the OASIS references *over the
    network* -- it succeeds, with a deprecation warning, which is an NFR-02
    failure that looks like a pass.
    """
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012

    index = json.loads((paths.DATA_SCHEMA / "ref_index.json").read_text(encoding="utf-8"))
    registry = Registry().with_resources(
        [
            (
                entry["uri"],
                Resource.from_contents(
                    json.loads((paths.ROOT / entry["path"]).read_text(encoding="utf-8")),
                    default_specification=DRAFT202012,
                ),
            )
            for entry in index["refs"]
        ]
    )
    schema = json.loads((paths.ROOT / index["root"]["path"]).read_text(encoding="utf-8"))
    return Draft202012Validator(schema, registry=registry)


class TheAttackFlowExportConforms(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not paths.ATTACK_FLOW.is_file():
            raise unittest.SkipTest("no build has run")
        cls.bundle = jsonl.read_json(paths.ATTACK_FLOW)
        cls.validator = offline_validator()

    def test_every_object_validates_against_the_vendored_schema(self):
        """The vendored schema describes Attack Flow's own object types. The
        bundle also carries plain STIX objects -- the creator `identity` --
        which the official validator checks as STIX, not as Attack Flow; run
        against this schema they fail for lacking the flow extension, which
        they must not carry. So flow objects meet the schema and the rest
        meet the STIX 2.1 shape."""
        failures = []
        for obj in self.bundle["objects"]:
            if obj.get("type", "").startswith("attack-"):
                errors = list(self.validator.iter_errors(obj))
                if errors:
                    failures.append(f"{obj.get('type')} {obj.get('id')}: {errors[0].message[:160]}")
                continue
            for key in ("type", "id", "spec_version", "created", "modified"):
                if key not in obj:
                    failures.append(f"{obj.get('type')} {obj.get('id')}: missing STIX property {key}")
            if obj.get("spec_version") != "2.1":
                failures.append(f"{obj.get('type')} {obj.get('id')}: spec_version is not 2.1")
        self.assertEqual(failures, [], "\n".join(failures))

    def test_ids_are_stix_shaped_and_content_derived(self):
        """Both at once. D-04 noted the tension -- STIX wants `<type>--<uuid>`,
        D-10 wants content-derived ids for diffability -- and a uuid5 over the
        content satisfies both, so regenerating is byte-identical."""
        import re

        pattern = re.compile(r"^[a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}$")
        for obj in self.bundle["objects"]:
            with self.subTest(obj=obj.get("type")):
                self.assertRegex(obj["id"], pattern)

    def test_the_evidence_extension_is_declared_not_bolted_on(self):
        """A bare top-level property fails `unevaluatedProperties` on every
        object, which is precisely how the first export failed."""
        actions = [o for o in self.bundle["objects"] if o["type"] == "attack-action"]
        self.assertTrue(actions)
        for action in actions:
            with self.subTest(action=action["id"]):
                self.assertNotIn("evidence_refs", action)
                extensions = action["extensions"]
                evidence = next(
                    value for key, value in extensions.items() if "evidence_refs" in value
                )
                self.assertIn("finding", evidence["evidence_refs"])

    def test_it_regenerates_byte_for_byte(self):
        """SS8.3: delete an export, regenerate from the graph, get the same bytes.
        Fixed timestamps rather than `now` are what make this hold."""
        from siem_investigator.enrich.catalogue import Catalogue
        from siem_investigator.evidence import exports

        regenerated = exports.attack_flow(
            jsonl.read(paths.FINDINGS),
            jsonl.read(paths.MAPPINGS),
            Catalogue.load().attack_version,
        )
        self.assertEqual(
            json.dumps(regenerated, sort_keys=True),
            json.dumps(self.bundle, sort_keys=True),
        )


class TheTimelineBoundsAreRight(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not paths.TIMELINE.is_file():
            raise unittest.SkipTest("no build has run")
        cls.timeline = jsonl.read_json(paths.TIMELINE)

    def test_the_window_end_is_the_maximum_not_the_last_row(self):
        """Rows are ordered by their *start*, so a long earlier step can finish
        after a short later one. It did: the reported end was 06:54:52 while a
        cited record ran to 07:41:34."""
        steps = self.timeline.get("steps") or []
        if not steps:
            self.skipTest("no timeline rows")
        self.assertEqual(
            self.timeline["window"]["last"],
            max(step["last_recorded_time"] for step in steps),
        )

    def test_the_window_start_is_the_minimum(self):
        steps = self.timeline.get("steps") or []
        if not steps:
            self.skipTest("no timeline rows")
        self.assertEqual(
            self.timeline["window"]["first"],
            min(step["first_recorded_time"] for step in steps),
        )


class TheScopeSeparatesNamedFromColocated(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not paths.SCOPE.is_file():
            raise unittest.SkipTest("no build has run")
        cls.scope = jsonl.read_json(paths.SCOPE)

    def test_every_row_says_how_it_got_there(self):
        """"A finding named it" and "it shares a log line with something a
        finding named" are different claims. Marking both confirmed put
        background hosts and an ownership marker called `external` into the
        blast radius as compromised."""
        for row in self.scope["involved"]:
            with self.subTest(entity=row["value"]):
                self.assertIn(row["basis"], ("named_by_finding", "on_a_cited_record"))
                self.assertEqual(row["confirmed"], row["basis"] == "named_by_finding")

    def test_the_headline_count_counts_only_named_entities(self):
        named = sum(1 for row in self.scope["involved"] if row["confirmed"])
        self.assertEqual(sum(self.scope["counts"].values()), named)
        self.assertGreaterEqual(
            sum(self.scope["counts_including_record_neighbours"].values()), named
        )

    def test_an_ownership_marker_is_not_an_account(self):
        """`bucket_owner: EXTERNAL` classifies ownership; it is not a principal."""
        accounts = {
            row["value"] for row in self.scope["involved"] if row["entity_type"] == "account"
        }
        self.assertNotIn("external", accounts)


class ThePrivilegeReportDoesNotOverclaim(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not paths.PRIVILEGE.is_file():
            raise unittest.SkipTest("no build has run")
        cls.privilege = jsonl.read_json(paths.PRIVILEGE)

    def test_no_exploit_based_escalation_is_claimed(self):
        self.assertFalse(self.privilege["exploit_based_escalation"]["evidenced"])
        self.assertIn("T1068", self.privilege["exploit_based_escalation"]["techniques_deliberately_not_mapped"])

    def test_the_mechanism_claim_matches_the_mappings(self):
        """The prose used to assert stolen credentials and service execution were
        both evidenced while `mechanisms_evidenced` was empty -- a claim the
        artifact itself contradicted."""
        evidenced = self.privilege["mechanisms_evidenced"]
        claim = self.privilege["mechanism_claim"]
        if evidenced:
            for technique in evidenced:
                self.assertIn(technique, claim)
        else:
            self.assertIn("not established", claim)

    def test_the_cross_host_progression_is_reported(self):
        """The brief asks for privilege escalation. Every per-host `rises` list is
        empty because no single host rises -- the progression is *across* hosts,
        and reporting only per-host maxima hid it completely."""
        progression = self.privilege["cross_host_progression"]
        self.assertIn("ladder", progression)
        ranks = [row["rank"] for row in progression["ladder"]]
        self.assertEqual(ranks, sorted(ranks), "the ladder is not ordered by privilege")


if __name__ == "__main__":
    unittest.main()
