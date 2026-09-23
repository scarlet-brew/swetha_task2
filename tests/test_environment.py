"""The frozen environment, asserted rather than assumed (task T01).

Three things this pins, each of which is cheap here and expensive later:

1. `requirements.txt` is the transitive closure of the four dependencies design
   10.1 declares -- recomputed here from installed metadata. A `pip freeze`
   would have smuggled pandera back in, and a demo venv that cannot be derived
   from the design cannot be reviewed against it.
2. pandera is gone from the working venv, not merely absent from a clean one.
   Its import chain reaches `pandas._libs.join`, which this machine's
   Application Control policy blocks, so it fails at runtime on specific
   operations rather than cleanly at import -- the worst failure shape.
3. No credential material sits in the tree (NFR-10). Run at T01 this is a
   habit; run at T40 it is an incident.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import unittest
from importlib.metadata import PackageNotFoundError, distribution, distributions, version
from pathlib import Path

from packaging.requirements import Requirement

from _env import REPO_ROOT

# The locked decision, copied from design 10.1. Written out rather than read
# from requirements.txt so that this test can disagree with that file.
DECLARED: dict[str, str] = {
    "anthropic": "0.84.0",
    "streamlit": "1.64.0",
    "pydantic": "2.13.5",
    "jsonschema": "4.26.0",
}

REQUIREMENTS_TXT = REPO_ROOT / "requirements.txt"
PIN_RE = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)==(?P<version>[A-Za-z0-9._+!-]+)$")


def canonical(name: str) -> str:
    """PEP 503 name normalisation, so `docstring_parser` and `docstring-parser`
    are one package rather than two."""
    return re.sub(r"[-_.]+", "-", name).lower()


def installed_distributions() -> dict[str, tuple[str, str]]:
    """Canonical name -> (metadata name, version) for everything in the venv."""
    found: dict[str, tuple[str, str]] = {}
    for dist in distributions():
        name = dist.metadata["Name"]
        if name:
            found[canonical(name)] = (name, dist.version)
    return found


def declared_closure() -> dict[str, str]:
    """Walk Requires-Dist outward from the four declared roots.

    Markers are evaluated for the running interpreter with no extras, which is
    exactly the set `pip install -r requirements.txt` would materialise here.
    """
    installed = installed_distributions()
    closure: dict[str, str] = {}
    pending = list(DECLARED)
    while pending:
        key = canonical(pending.pop(0))
        if key in closure:
            continue
        if key not in installed:
            raise AssertionError(f"declared dependency {key!r} is not installed")
        metadata_name, dist_version = installed[key]
        closure[key] = dist_version
        for spec in distribution(metadata_name).requires or []:
            requirement = Requirement(spec)
            if requirement.marker is None or requirement.marker.evaluate({"extra": ""}):
                pending.append(requirement.name)
    return closure


def parse_requirements() -> dict[str, str]:
    pins: dict[str, str] = {}
    for lineno, raw in enumerate(
        REQUIREMENTS_TXT.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = PIN_RE.match(line)
        if match is None:
            raise AssertionError(
                f"requirements.txt line {lineno} is not an exact pin: {raw!r}"
            )
        pins[canonical(match["name"])] = match["version"]
    return pins


class DeclaredDependencies(unittest.TestCase):
    def test_all_four_import(self) -> None:
        """The NFR-02 offline claim starts here: these four and stdlib only."""
        import anthropic  # noqa: F401
        import jsonschema  # noqa: F401
        import pydantic  # noqa: F401
        import streamlit  # noqa: F401

    def test_installed_at_the_versions_the_design_locked(self) -> None:
        for name, expected in DECLARED.items():
            with self.subTest(package=name):
                self.assertEqual(version(name), expected)

    def test_anthropic_sdk_surface_d08_depends_on(self) -> None:
        """D-08 rests on `messages.parse`; if 0.84.0 ever moves, fail here and
        not inside the first model call."""
        import anthropic

        client_attrs = dir(anthropic.Anthropic)
        self.assertIn("messages", client_attrs)
        self.assertTrue(
            hasattr(anthropic.resources.messages.Messages, "parse"),
            "anthropic.messages.parse is absent; design D-08 no longer holds",
        )


class FrozenSet(unittest.TestCase):
    def test_requirements_is_the_closure_of_the_declared_four(self) -> None:
        """The anti-`pip freeze` check, in both directions.

        A package in the venv that no declared dependency requires must not be
        in requirements.txt; a package requirements.txt pins must be reachable
        from the declared four.
        """
        self.assertEqual(parse_requirements(), declared_closure())

    def test_the_four_are_pinned_in_requirements(self) -> None:
        pins = parse_requirements()
        for name, expected in DECLARED.items():
            with self.subTest(package=name):
                self.assertEqual(pins.get(canonical(name)), expected)

    def test_nothing_is_left_installed_outside_the_closure(self) -> None:
        """`.venv` matching 10.1 exactly, which is stronger than the clean-venv
        check: the venv that ships the demo is this one."""
        extra = sorted(set(installed_distributions()) - set(declared_closure()) - {"pip"})
        self.assertEqual(extra, [], f"installed but not derivable from 10.1: {extra}")

    def test_pandera_is_absent(self) -> None:
        """10.1 drops pandera on measured grounds; it was installed at 0.33.1."""
        self.assertIsNone(importlib.util.find_spec("pandera"))
        with self.assertRaises(PackageNotFoundError):
            version("pandera")

    def test_pytest_is_absent_so_unittest_stays_the_runner(self) -> None:
        """Guards the T01 decision: every verification in the plan has to run
        under stdlib unittest, and a pytest-only test would be invisible to the
        frozen venv that constitutes Phase 5's evidence."""
        self.assertIsNone(importlib.util.find_spec("pytest"))
        self.assertNotIn("pytest", parse_requirements())


SKIP_SUFFIXES = {".pdf", ".png", ".jpg", ".jpeg", ".ico", ".zip", ".whl", ".pyc"}
# Local secret holders, gitignored and therefore out of scope for a check about
# what is stored *in the repository*. A developer's own `.env` is theirs; the
# thing that would be a breach is one entering the index, and the git
# enumeration below catches exactly that, because `--cached` includes staged
# files. `test_env_file_itself_is_gitignored` covers the other half.
LOCAL_SECRET_NAMES = {".env", "secrets.toml", "secrets.json"}
# The vendored ATT&CK bundle (T03) is ~51 MiB of external content carrying its
# own sha256 provenance; scanning it on every test run costs seconds and proves
# nothing about this repository's hygiene.
MAX_SCAN_BYTES = 1_048_576

# The prefix alone is not a finding -- this plan's own documents name it, and a
# test that fails on its own verification text is noise. A key is the prefix
# followed by key-shaped material.
SK_ANT_RE = re.compile(r"sk-ant-[A-Za-z0-9_-]{16,}", re.IGNORECASE)
ASSIGNMENT_RE = re.compile(r"""api[_-]?key["']?\s*[:=]\s*(?P<rhs>.*)""", re.IGNORECASE)
QUOTED_RE = re.compile(r"""^(?P<q>["'])(?P<value>.*?)(?P=q)""")
ENV_VAR_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
# `"<your key>"` in a documented shell line. A real credential is never in
# angle brackets, and the instructions have to be copy-pasteable (NFR-08).
PLACEHOLDER_RE = re.compile(r"^<[^>]*>$")


def repository_files() -> list[Path]:
    """Files that are in the repository or would be by the next commit.

    Enumerated with git rather than by walking the filesystem, for the same
    reason T01's shell check is a `git grep`: the question is what is stored
    alongside the system, and `.venv`, `__pycache__` and a developer's ignored
    local files are not. `--cached` covers tracked and staged, `--others
    --exclude-standard` covers new files not yet added -- so a key committed,
    staged, or merely dropped into `src/` all fail here.
    """
    listing = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    files: list[Path] = []
    for name in listing.stdout.split("\0"):
        if not name:
            continue
        path = REPO_ROOT / name
        if not path.is_file() or path.name in LOCAL_SECRET_NAMES:
            continue
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        if path.stat().st_size > MAX_SCAN_BYTES:
            continue
        files.append(path)
    return files


class NoCredentialInTheTree(unittest.TestCase):
    """NFR-10: credentials required to operate the system are not stored
    alongside it. The shell form of this check is
    `git grep -iE "sk-ant|api[_-]?key\\s*="`, which matches documentation as
    well as secrets; this test is the part that can tell them apart.
    """

    def test_the_scan_actually_reads_files(self) -> None:
        """A scan over an empty file list passes vacuously, so count first."""
        self.assertGreater(len(repository_files()), 5)

    def test_no_anthropic_key_literal_anywhere(self) -> None:
        for path in repository_files():
            text = path.read_text(encoding="utf-8", errors="replace")
            with self.subTest(path=str(path.relative_to(REPO_ROOT))):
                self.assertIsNone(
                    SK_ANT_RE.search(text),
                    "an Anthropic key literal appears in a repository file",
                )

    def test_every_api_key_assignment_is_empty_or_an_indirection(self) -> None:
        """A key-shaped name assigned a non-empty string literal is the failure
        mode; `os.environ["ANTHROPIC_API_KEY"]` and an empty template line are
        not."""
        for path in repository_files():
            relative = path.relative_to(REPO_ROOT)
            for lineno, line in enumerate(
                path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
            ):
                match = ASSIGNMENT_RE.search(line)
                if match is None:
                    continue
                rhs = match["rhs"].strip()
                quoted = QUOTED_RE.match(rhs)
                if quoted is None:
                    # Empty (a template line) or an expression: no secret here.
                    continue
                value = quoted["value"].strip()
                with self.subTest(path=str(relative), line=lineno):
                    self.assertTrue(
                        value == ""
                        or ENV_VAR_NAME_RE.match(value)
                        or PLACEHOLDER_RE.match(value),
                        f"{relative}:{lineno} assigns a literal to a key-shaped "
                        f"name: {line.strip()!r}",
                    )


class KeyHandlingIsDocumented(unittest.TestCase):
    def test_env_example_names_the_variable_and_carries_no_value(self) -> None:
        example = REPO_ROOT / ".env.example"
        self.assertTrue(example.is_file(), ".env.example is missing")
        lines = [
            line.strip()
            for line in example.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        self.assertIn("ANTHROPIC_API_KEY=", lines)
        for line in lines:
            with self.subTest(line=line):
                self.assertTrue(
                    line.endswith("="),
                    "a value is set in .env.example; it is a template, not a store",
                )

    def test_readme_documents_build_app_and_the_environment_variable(self) -> None:
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("## Running it", readme)
        self.assertIn("siem_investigator.build", readme)
        self.assertIn("streamlit run app/main.py", readme)
        self.assertIn("ANTHROPIC_API_KEY", readme)

    def test_env_file_itself_is_gitignored(self) -> None:
        """`.env.example` is committed; `.env` must never be."""
        gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        self.assertIn(".env", gitignore)
        self.assertIn("!.env.example", gitignore)


if __name__ == "__main__":
    unittest.main()
