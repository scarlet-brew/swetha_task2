"""T02 -- the committed audit representation (D-10) and the line reporter (D-09).

D-10's claim is that `git diff` between two builds shows exactly which nodes
changed and nothing else. That rests on three properties, each asserted below:
the file is a function of its contents rather than of insertion order, the bytes
survive a Windows checkout, and one id cannot carry two payloads.

Identity itself lives in `test_kernel_identity.py`.
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import tomllib
import unittest
from pathlib import Path

import _env  # noqa: F401  -- must precede the package import; puts src/ on sys.path

import siem_investigator
from siem_investigator import ids, jsonl, loc


class TestVersionIsSingleSourced(unittest.TestCase):
    """NFR-07 stamps the software version onto every output, so the two places it
    is written have to agree or provenance records a version nothing was built
    with."""

    def test_package_version_matches_pyproject(self):
        pyproject = tomllib.loads(
            (_env.REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(siem_investigator.__version__, pyproject["project"]["version"])


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
        found = [
            json.loads(line)["id"] for line in path.read_text(encoding="utf-8").splitlines()
        ]
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

    def test_blank_lines_are_tolerated_on_read(self):
        path = self.tmp / "a.jsonl"
        path.write_text('{"id": "obs_a"}\n\n{"id": "obs_b"}\n', encoding="utf-8")
        self.assertEqual(len(jsonl.read(path)), 2)

    def test_a_malformed_line_names_its_line_number(self):
        path = self.tmp / "a.jsonl"
        path.write_text('{"id": "obs_a"}\nnot json\n', encoding="utf-8")
        with self.assertRaises(ValueError) as caught:
            jsonl.read(path)
        self.assertIn("a.jsonl:2", str(caught.exception))

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

    def test_a_missing_parent_directory_is_created(self):
        path = self.tmp / "nested" / "deeper" / "a.jsonl"
        jsonl.write(path, [{"id": "obs_a"}])
        self.assertTrue(path.is_file())


class TestLineReporter(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def _file_of(self, lines: int) -> Path:
        path = self.tmp / f"mod_{lines}.py"
        path.write_text("\n".join(f"x = {i}" for i in range(lines)) + "\n", encoding="utf-8")
        return path

    @staticmethod
    def _printed(*roots: Path) -> tuple[int, str]:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            status = loc.main([str(root) for root in roots])
        return status, buffer.getvalue()

    def test_ceiling_is_four_hundred(self):
        self.assertEqual(loc.CEILING, 400)

    def test_counts_physical_lines(self):
        self.assertEqual(loc.count_lines(self._file_of(37)), 37)

    def test_silent_at_the_ceiling(self):
        self._file_of(loc.CEILING)
        self.assertEqual(loc.over_ceiling([self.tmp]), [])
        status, printed = self._printed(self.tmp)
        self.assertEqual(status, 0)
        self.assertNotIn("OVER", printed)
        self.assertIn(f"No governed file over {loc.CEILING} lines.", printed)

    def test_flags_one_line_over(self):
        self._file_of(loc.CEILING + 1)
        flagged = loc.over_ceiling([self.tmp])
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0][1], loc.CEILING + 1)
        status, printed = self._printed(self.tmp)
        self.assertEqual(status, 0)
        self.assertIn("OVER", printed)
        self.assertIn("mod_401.py", printed)
        self.assertIn("1 governed file(s) over the soft ceiling", printed)

    def test_reporting_never_fails_the_build(self):
        """D-09 chose a soft ceiling on purpose: the cheapest way to satisfy a hard
        one is to split a coherent module into two incoherent halves. So a file far
        over the line is printed and the exit status stays 0."""
        self._file_of(loc.CEILING + 200)
        status, printed = self._printed(self.tmp)
        self.assertEqual(status, 0)
        self.assertIn(str(loc.CEILING + 200), printed)

    def test_longest_first(self):
        for lines in (10, 500, 100):
            self._file_of(lines)
        counts = [count for _, count in loc.report([self.tmp])]
        self.assertEqual(counts, [500, 100, 10])

    def test_measures_the_repository_without_flagging_anything(self):
        """The real measurement, over the real tree: every governed file is within
        D-09's ceiling as the plan stands."""
        self.assertEqual(loc.over_ceiling(), [])
        self.assertGreater(len(loc.report()), 5)

    def test_caches_and_virtualenvs_are_skipped(self):
        (self.tmp / "__pycache__").mkdir()
        (self.tmp / "__pycache__" / "stale.py").write_text("x = 1\n", encoding="utf-8")
        self._file_of(3)
        self.assertEqual([name for name, _ in loc.report([self.tmp])], ["mod_3.py"])

    def test_a_missing_root_is_not_an_error(self):
        self.assertEqual(loc.report([self.tmp / "absent"]), [])


if __name__ == "__main__":
    unittest.main()
