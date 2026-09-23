"""The two external artifacts, asserted rather than trusted (task T03).

These files are the only content in the repository that was fetched from the
internet, and both underpin a claim the system makes to a reader:
`enterprise-attack-19.2.json` is what `R4.2`'s catalogue-version statement
points at, and `attack-flow-2.0.0.json` is what three later verifications mean
by "validates against the vendored schema".

A provenance claim nobody re-checks is decoration, so this module re-hashes
every byte against the digests written in the two PROVENANCE.md files, parsed
out of the markdown rather than restated here. Restating them would let the two
drift apart and still pass.

It also asserts the thing that is easy to get wrong and invisible when it is:
that validating against the Attack Flow schema resolves its remote `$ref`s
**locally**. `jsonschema` fetches an unregistered remote reference over the
network, so the offline claim in `NFR-02` is a property of the registry, not of
the schema file.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import unittest
from pathlib import Path
from urllib.parse import urljoin

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from _env import DATA_DIR, REPO_ROOT, SRC_DIR

ATTACK_DIR = DATA_DIR / "attack"
SCHEMA_DIR = DATA_DIR / "schema"

BUNDLE = ATTACK_DIR / "enterprise-attack-19.2.json"
ATTACK_INDEX = ATTACK_DIR / "index.json"
FLOW_SCHEMA = SCHEMA_DIR / "attack-flow-2.0.0.json"
REF_INDEX = SCHEMA_DIR / "ref_index.json"

ATTACK_VERSION = "19.2"
COLLECTION_NAME = "Enterprise ATT&CK"
# The published bundle URL, which index.json must agree with -- the whole point
# of committing the index next to the bundle.
BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
    "/enterprise-attack/enterprise-attack-19.2.json"
)

PROVENANCE_HEADER = "| File | Bytes | sha256 | Source URL |"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# T03's shell check, as a pattern rather than a shell invocation: `git grep`
# skips untracked files by default, and at the time this was written every
# file in src/ was still untracked, so the shell form passes vacuously.
NETWORK_TOKENS_RE = re.compile(r"requests|urllib|httpx|taxii")


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def provenance_rows(provenance: Path) -> dict[str, tuple[int, str, str]]:
    """Parse the retrieval table out of a PROVENANCE.md.

    Returns file-name-relative-to-that-directory -> (bytes, sha256, url). Only
    the table under `PROVENANCE_HEADER` is read; both files carry other tables.
    """
    rows: dict[str, tuple[int, str, str]] = {}
    inside = False
    for line in provenance.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped == PROVENANCE_HEADER:
            inside = True
            continue
        if not inside:
            continue
        if not stripped.startswith("|"):
            break
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if len(cells) != 4 or set(cells[0]) <= {"-", ":"}:
            continue
        name, size, digest, url = cells
        rows[name.strip("`")] = (int(size), digest.strip("`"), url)
    if not rows:
        raise AssertionError(f"no retrieval table found in {provenance}")
    return rows


def vendored_registry() -> tuple[dict[str, object], Registry]:
    """The Attack Flow schema plus a registry holding its whole `$ref` closure.

    Keyed by retrieval URI *and* by each document's own `$id`: the schema cites
    two spellings of `timestamp.json` (an `http` stix2.1 one and an `https`
    master one) whose contents both declare the stix2.1 `$id`, so neither key
    alone resolves everything.
    """
    index = json.loads(REF_INDEX.read_bytes())
    registry = Registry()
    for entry in index["refs"]:
        document = json.loads((REPO_ROOT / entry["path"]).read_bytes())
        resource = Resource.from_contents(document, default_specification=DRAFT202012)
        registry = registry.with_resource(entry["uri"], resource)
        own_id = document.get("$id")
        if own_id and own_id != entry["uri"]:
            registry = registry.with_resource(own_id, resource)
    schema = json.loads(FLOW_SCHEMA.read_bytes())
    registry = registry.with_resource(
        schema["$id"], Resource.from_contents(schema, default_specification=DRAFT202012)
    )
    return schema, registry


def every_ref(node: object):
    """Every `$ref` string anywhere in a schema document."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                yield value
            else:
                yield from every_ref(value)
    elif isinstance(node, list):
        for value in node:
            yield from every_ref(value)


class ArtifactsArePresentAndParse(unittest.TestCase):
    """T03 verification 1: `json.load` succeeds on all three."""

    def test_all_three_exist(self) -> None:
        for path in (BUNDLE, ATTACK_INDEX, FLOW_SCHEMA):
            with self.subTest(path=path.name):
                self.assertTrue(path.is_file(), f"{path} is missing")

    def test_all_three_parse(self) -> None:
        for path in (BUNDLE, ATTACK_INDEX, FLOW_SCHEMA):
            with self.subTest(path=path.name):
                with path.open("rb") as handle:
                    self.assertIsInstance(json.load(handle), dict)

    def test_no_crlf_reached_the_committed_bytes(self) -> None:
        """The failure `.gitattributes` exists to prevent, checked on content.

        `git check-attr` asserts the rule; this asserts the outcome, which is
        what the digests are actually a claim about.
        """
        for path in (BUNDLE, ATTACK_INDEX, FLOW_SCHEMA):
            with self.subTest(path=path.name):
                self.assertNotIn(b"\r\n", path.read_bytes()[:4096])


class DigestsReproduce(unittest.TestCase):
    """T03 verification 2: re-hashing reproduces the digests in PROVENANCE.md."""

    def test_attack_provenance_reproduces(self) -> None:
        rows = provenance_rows(ATTACK_DIR / "PROVENANCE.md")
        self.assertEqual(set(rows), {BUNDLE.name, ATTACK_INDEX.name})
        for name, (size, digest, url) in rows.items():
            with self.subTest(file=name):
                path = ATTACK_DIR / name
                self.assertTrue(SHA256_RE.match(digest), f"{digest!r} is not a sha256")
                self.assertTrue(url.startswith("https://"))
                self.assertEqual(path.stat().st_size, size)
                self.assertEqual(sha256_of(path), digest)

    def test_schema_provenance_reproduces(self) -> None:
        rows = provenance_rows(SCHEMA_DIR / "PROVENANCE.md")
        for name, (size, digest, url) in rows.items():
            with self.subTest(file=name):
                path = SCHEMA_DIR / name
                self.assertTrue(SHA256_RE.match(digest), f"{digest!r} is not a sha256")
                self.assertTrue(url.startswith("http"))
                self.assertEqual(path.stat().st_size, size)
                self.assertEqual(sha256_of(path), digest)

    def test_every_vendored_ref_has_a_provenance_row(self) -> None:
        """A fetched file with no row is the drift this whole file guards."""
        rows = provenance_rows(SCHEMA_DIR / "PROVENANCE.md")
        on_disk = {
            path.relative_to(SCHEMA_DIR).as_posix()
            for path in (SCHEMA_DIR / "refs").rglob("*.json")
        }
        self.assertTrue(on_disk, "data/schema/refs/ is empty")
        self.assertEqual(on_disk | {FLOW_SCHEMA.name}, set(rows))

    def test_ref_index_agrees_with_provenance(self) -> None:
        """Two records of the same digest can drift; this is the check that
        makes `ref_index.json` safe to generate separately."""
        rows = provenance_rows(SCHEMA_DIR / "PROVENANCE.md")
        index = json.loads(REF_INDEX.read_bytes())
        self.assertEqual(
            index["root"]["path"], FLOW_SCHEMA.relative_to(REPO_ROOT).as_posix()
        )
        self.assertEqual(index["root"]["sha256"], rows[FLOW_SCHEMA.name][1])
        for entry in index["refs"]:
            path = REPO_ROOT / entry["path"]
            relative = path.relative_to(SCHEMA_DIR).as_posix()
            with self.subTest(ref=relative):
                self.assertTrue(path.is_file())
                self.assertIn(relative, rows)
                self.assertEqual(entry["sha256"], rows[relative][1])
                self.assertEqual(entry["uri"], rows[relative][2])


class TheBundleIsWhatItClaims(unittest.TestCase):
    """`R4.2` rests on the bundle being the published v19.2, not on its name."""

    @classmethod
    def setUpClass(cls) -> None:
        with BUNDLE.open("rb") as handle:
            cls.bundle = json.load(handle)
        with ATTACK_INDEX.open("rb") as handle:
            cls.index = json.load(handle)

    def test_it_is_a_stix_21_bundle(self) -> None:
        """STIX 2.1 moved `spec_version` from the bundle onto each object, so
        its absence at bundle level is part of the evidence, not a gap."""
        self.assertEqual(self.bundle["type"], "bundle")
        self.assertNotIn("spec_version", self.bundle)
        versions = {obj.get("spec_version") for obj in self.bundle["objects"]}
        self.assertEqual(versions, {"2.1"})

    def test_one_collection_object_carrying_version_19_2(self) -> None:
        collections = [
            obj for obj in self.bundle["objects"] if obj["type"] == "x-mitre-collection"
        ]
        self.assertEqual(len(collections), 1)
        collection = collections[0]
        self.assertEqual(collection["name"], COLLECTION_NAME)
        # T04 copies this field verbatim into `attack_version`.
        self.assertEqual(collection["x_mitre_version"], ATTACK_VERSION)

    def test_the_index_names_this_bundle_at_this_version(self) -> None:
        enterprise = [
            coll
            for coll in self.index["collections"]
            if coll["name"] == COLLECTION_NAME
        ]
        self.assertEqual(len(enterprise), 1)
        newest = enterprise[0]["versions"][0]
        self.assertEqual(newest["version"], ATTACK_VERSION)
        self.assertEqual(newest["url"], BUNDLE_URL)

    def test_the_techniques_a_later_task_depends_on_are_present(self) -> None:
        """Cheap precondition for T04/T24. Names are not asserted here -- T04
        reads those out of the bundle rather than out of anyone's memory."""
        ids = set()
        for obj in self.bundle["objects"]:
            if obj["type"] != "attack-pattern":
                continue
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    ids.add(ref.get("external_id"))
        for technique in ("T1059.001", "T1078", "T1569.002", "T1068"):
            with self.subTest(technique=technique):
                self.assertIn(technique, ids)


class TheSchemaResolvesOffline(unittest.TestCase):
    """The reason `refs/` is vendored: `NFR-02` for stage 5's validation."""

    def test_it_is_the_2_0_0_draft_2020_12_schema(self) -> None:
        schema = json.loads(FLOW_SCHEMA.read_bytes())
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertIn("attack-flow-schema-2.0.0.json", schema["$id"])
        Draft202012Validator.check_schema(schema)

    def test_every_ref_resolves_against_the_vendored_closure(self) -> None:
        schema, registry = vendored_registry()
        resolver = registry.resolver_with_root(
            Resource.from_contents(schema, default_specification=DRAFT202012)
        )
        references = sorted(set(every_ref(schema)))
        self.assertTrue(references, "the schema declares no $ref at all")
        for reference in references:
            with self.subTest(ref=reference):
                resolver.lookup(reference)

    def test_a_representative_sdo_validates_with_no_network(self) -> None:
        """End to end: the shape stage 5 emits, through the real validator.

        No `retrieve` callable is given to the registry, so an unvendored
        reference raises `Unresolvable` here instead of quietly succeeding by
        fetching it -- which is exactly what happens without the registry.
        """
        schema, registry = vendored_registry()
        validator = Draft202012Validator(schema, registry=registry)
        action = {
            "type": "attack-action",
            "spec_version": "2.1",
            "id": "attack-action--0e2e4f0a-9b9a-4d09-8f8b-2b1a1c1d1e1f",
            "created": "2026-06-10T08:00:00.000Z",
            "modified": "2026-06-10T08:00:00.000Z",
            "extensions": {
                "extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4": {
                    "extension_type": "new-sdo"
                }
            },
            "name": "WINWORD.EXE spawns cmd.exe on WKSTN-07",
            "technique_id": "T1059.003",
        }
        self.assertEqual(list(validator.iter_errors(action)), [])

    def test_the_closure_is_complete_and_self_contained(self) -> None:
        """Every remote `$ref` in every vendored document is itself vendored.

        The OASIS documents cite each other **relatively** (`../common/hex.json`),
        so a reference is only meaningful against the base URI of the document
        it appears in -- its `$id` where it declares one. Comparing the raw
        string against the vendored URIs would fail on every one of them while
        the closure is in fact complete.
        """
        index = json.loads(REF_INDEX.read_bytes())
        known = {entry["uri"] for entry in index["refs"]} | {index["root"]["uri"]}
        documents = [(index["root"]["uri"], json.loads(FLOW_SCHEMA.read_bytes()))]
        documents += [
            (entry["uri"], json.loads((REPO_ROOT / entry["path"]).read_bytes()))
            for entry in index["refs"]
        ]
        checked = 0
        for uri, document in documents:
            base = document.get("$id") or uri
            for reference in every_ref(document):
                if reference.startswith("#"):
                    continue
                absolute = urljoin(base, reference).split("#", 1)[0]
                checked += 1
                with self.subTest(base=base, ref=reference):
                    self.assertIn(absolute, known, "an unvendored remote $ref remains")
        self.assertGreater(checked, 0, "no remote $ref was examined at all")


class NothingFetchesAtRuntime(unittest.TestCase):
    """T03 verifications 3 and 4, as tests rather than as shell history."""

    def test_git_leaves_the_json_bytes_alone(self) -> None:
        for path in (BUNDLE, ATTACK_INDEX, FLOW_SCHEMA):
            relative = path.relative_to(REPO_ROOT).as_posix()
            with self.subTest(path=relative):
                result = subprocess.run(
                    ["git", "check-attr", "text", "--", relative],
                    cwd=REPO_ROOT,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                self.assertEqual(result.stdout.strip(), f"{relative}: text: unset")

    #: The one module under `src/` allowed to name a network client: the model
    #: plane's transport. Its egress is inventoried in `docs/egress.md` and
    #: captured field-by-field by `tests/test_agent_contracts.py`.
    EGRESS_BOUNDARY = "src/siem_investigator/agent/client.py"

    def test_only_the_model_transport_names_a_network_client(self) -> None:
        """D-03's rule, stated precisely now that the model plane exists.

        The rule was originally "nothing under `src/` names a network client",
        which was true only because `agent/` was empty. It would now fail on the
        model transport, which is *supposed* to reach the service -- so asserting
        it would either be wrong or would push the transport somewhere less
        visible.

        The real invariant is narrower and stronger: egress happens at exactly
        one place, so there is exactly one function to capture in order to check
        the inventory. A second module reaching the network is what this catches,
        and that is the failure that would make `docs/egress.md` untrue.
        """
        sources = sorted(SRC_DIR.rglob("*.py"))
        self.assertTrue(sources, "src/ has no Python files; the scan is vacuous")

        offenders = [
            source.relative_to(REPO_ROOT).as_posix()
            for source in sources
            if NETWORK_TOKENS_RE.search(source.read_text(encoding="utf-8"))
        ]
        self.assertEqual(
            offenders,
            [self.EGRESS_BOUNDARY],
            "egress must happen at exactly one place under src/",
        )

    def test_nothing_under_src_fetches_an_external_artifact(self) -> None:
        """The half of D-03 that is still an absolute ban.

        The model transport may talk to the model service. Nothing may fetch the
        ATT&CK catalogue, the Attack Flow schema or any other external artifact
        at runtime -- that is what retaining them locally is *for*, and it is why
        `scripts/fetch_external.py` lives outside the package.
        """
        forbidden = re.compile(
            r"githubusercontent|attack-stix-data|cti-stix2-json-schemas|taxii|urlretrieve"
        )
        for source in sorted(SRC_DIR.rglob("*.py")):
            with self.subTest(path=source.relative_to(REPO_ROOT).as_posix()):
                self.assertIsNone(
                    forbidden.search(source.read_text(encoding="utf-8")),
                    "src/ fetches an external artifact; D-03 retains them locally",
                )


if __name__ == "__main__":
    unittest.main()
