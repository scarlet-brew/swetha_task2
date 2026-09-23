"""T03 -- the two external artifacts, and the provenance that makes them checkable.

The substance of this file is the offline discipline. D-03 retains the ATT&CK
catalogue locally so the build and the app never reach outside; NFR-02 requires
the system to work with no off-machine service available. Both are trivially
true today and easy to break later by adding one convenient `requests` import,
so the grep is a test rather than a note.
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

import _env  # noqa: F401  -- puts src/ on sys.path

from siem_investigator import paths

SCRIPTS = _env.REPO_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import verify_external  # noqa: E402


class TestArtifactsArePresentAndParse(unittest.TestCase):
    def test_all_three_parse(self):
        for path in (paths.ATTACK_BUNDLE, paths.ATTACK_INDEX, paths.ATTACK_FLOW_SCHEMA):
            with self.subTest(path=path.name):
                self.assertTrue(path.exists(), f"{path.name} missing -- run scripts/fetch_external.py")
                with path.open(encoding="utf-8") as handle:
                    self.assertIsInstance(json.load(handle), dict)

    def test_bundle_is_the_whole_stix_bundle(self):
        """Committed whole rather than as the derived subset: a subset would make the
        derivation unreproducible and R4.2's version claim unverifiable."""
        with paths.ATTACK_BUNDLE.open(encoding="utf-8") as handle:
            bundle = json.load(handle)
        self.assertEqual(bundle["type"], "bundle")
        self.assertGreater(len(bundle["objects"]), 20_000)

    def test_attack_flow_schema_is_a_json_schema(self):
        with paths.ATTACK_FLOW_SCHEMA.open(encoding="utf-8") as handle:
            schema = json.load(handle)
        self.assertIn("$schema", schema)
        self.assertIn("$defs", schema)


class TestRecordedProvenanceStillHolds(unittest.TestCase):
    """The claim R4.2 rests on, re-computed rather than believed."""

    def test_verifier_passes(self):
        self.assertEqual(verify_external.main([]), 0)

    def test_every_artifact_has_a_recorded_digest(self):
        recorded = set()
        for provenance in verify_external.PROVENANCE_FILES:
            self.assertTrue(provenance.exists(), f"{provenance} missing")
            for name, digest, size in verify_external.claims(provenance):
                recorded.add((provenance.parent / name).resolve())
                self.assertRegex(digest, r"^[0-9a-f]{64}$")
                self.assertGreater(size, 0)

        for path in (paths.ATTACK_BUNDLE, paths.ATTACK_INDEX, paths.ATTACK_FLOW_SCHEMA):
            self.assertIn(path.resolve(), recorded, f"{path.name} has no provenance section")

    def test_provenance_records_the_source_url(self):
        """A digest without a URL says the bytes have not changed, not where they
        came from. R4.2 needs both."""
        for provenance in verify_external.PROVENANCE_FILES:
            text = provenance.read_text(encoding="utf-8")
            self.assertIn("**source** <https://", text)
            self.assertIn("**retrieved** 20", text)


class TestEolNormalisationCannotAlterTheBytes(unittest.TestCase):
    """The failure this task exists to close.

    `* text=auto eol=lf` with no `.json` exception resolved the bundle to
    `eol: lf`, so git would rewrite line endings on checkout while the file went
    on parsing perfectly -- and every sha256 above would fail against a file
    nobody had knowingly touched. Since the whole reason D-03 commits the bundle
    is to make the catalogue a reproducible authority, that would have quietly
    voided the point of the decision.
    """

    def _check_attr(self, path: Path) -> str:
        result = subprocess.run(
            ["git", "check-attr", "text", "--", paths.relative(path)],
            cwd=_env.REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip().rsplit(":", 1)[-1].strip()

    def test_json_artifacts_are_text_unset(self):
        for path in (paths.ATTACK_BUNDLE, paths.ATTACK_INDEX, paths.ATTACK_FLOW_SCHEMA, paths.RAW_LOGS):
            with self.subTest(path=path.name):
                self.assertEqual(self._check_attr(path), "unset")

    def test_the_assignment_pdf_is_binary(self):
        """Same class of bug, caught earlier: git classified the 9,430-byte PDF as
        text, which would have corrupted it on checkout."""
        pdfs = sorted((_env.REPO_ROOT / "docs").rglob("*.pdf"))
        self.assertTrue(pdfs, "no PDF found under docs/")
        for pdf in pdfs:
            with self.subTest(path=pdf.name):
                self.assertEqual(self._check_attr(pdf), "unset")


class TestNothingFetchesAtRuntime(unittest.TestCase):
    """D-03 and NFR-02: the build and the app have no path to an outside service.

    Grepped rather than asserted in prose, because the way this breaks is one
    convenient import added months later by someone who never read D-03.
    """

    def _git_grep(self, pattern: str, *pathspecs: str) -> list[str]:
        # `--untracked` matters more than it looks. Plain `git grep` searches only
        # tracked files, so a not-yet-committed `src/fetcher.py` would make this
        # check pass while the offline guarantee was already broken -- the test
        # would be green for the wrong reason, which is worse than absent.
        result = subprocess.run(
            ["git", "grep", "-nE", "--untracked", pattern, "--", *pathspecs],
            cwd=_env.REPO_ROOT,
            capture_output=True,
            text=True,
        )
        # git grep exits 1 with no output when there are no matches.
        if result.returncode not in (0, 1):
            self.fail(f"git grep failed: {result.stderr}")
        return [line for line in result.stdout.splitlines() if line.strip()]

    def test_src_has_no_network_client(self):
        self.assertEqual(self._git_grep(r"requests|urllib|httpx|taxii", "src/"), [])

    def test_app_has_no_network_client(self):
        self.assertEqual(self._git_grep(r"requests|urllib|httpx|taxii", "app/"), [])

    def test_the_fetcher_lives_outside_the_package(self):
        """It has to exist somewhere -- the artifacts came from the internet. It
        lives in `scripts/`, which is provisioning, not runtime."""
        hits = self._git_grep(r"urllib", "scripts/")
        self.assertTrue(hits, "expected scripts/fetch_external.py to use urllib")
        self.assertTrue(all(hit.startswith("scripts/fetch_external.py:") for hit in hits), hits)


if __name__ == "__main__":
    unittest.main()
