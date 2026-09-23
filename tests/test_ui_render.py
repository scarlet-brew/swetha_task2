"""T07 -- the day-one render constraints, in both themes.

Four of these settle things design decisions ride on, and each would be
expensive to discover at T37 rather than here:

* **The palette is measured, not asserted.** The contrast ratios are recomputed
  from the exact hex strings in `.streamlit/config.toml`, so the one place a
  colour is written is the place the floor is checked.
* **Citations must render as top-level siblings.** SS9.4 says retrofitting this is
  a rewrite of the render loop. Note the reason is *not* an engine constraint:
  measured at T07, streamlit 1.64.0 raises no nested-expander exception -- the
  backend ancestor check is gone. The flat layout is kept because SS9.4 requires
  it, because a nested expander's frontend behaviour is unverified here, and
  because one open citation at a time would defeat the surface. The AST walk
  below localises a regression to a line number; the runtime check in
  `test_ui_sibling_render.py` is the load-bearing one, since a static walk
  cannot see an expander opened from a helper two calls away.
* **The table path must not reach pandas at all.** SS10.1 originally justified
  dropping `pandera` and `streamlit-aggrid` by claiming this machine's
  Application Control policy blocks `pandas._libs.join`. Re-measured here it
  does not -- the module imports and `DataFrame.merge` works -- so SS10.1 has
  been corrected and the test asserts the property that is both true and worth
  having: the pyarrow route pulls in no pandas module of its own.
* **Startup must be fast with the network dead.** The harsher case is not "no
  network" but a *proxy that hangs*, because then every outbound attempt waits
  for a timeout instead of failing fast.
"""

from __future__ import annotations

import ast
import os
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path

import _env  # noqa: F401  -- puts src/ on sys.path

# app/ imports as a package from the repository root, the way app/main.py
# arranges for itself at runtime.
if str(_env.REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_env.REPO_ROOT))

from app import artifacts, theme  # noqa: E402
from app.components import citation, evidence_table, support_badge  # noqa: E402

CONFIG_TOML = _env.REPO_ROOT / ".streamlit" / "config.toml"

#: Measured against the panel surface #F7F7F7. Deloitte house style, taken from
#: the assignment brief itself: white ground, black text, one green accent.
#: (Replaces the earlier parchment palette -- see design SS9.1.)
LIGHT_EXPECTED = {"ink": 19.60, "ink_secondary": 6.89, "ink_muted": 5.39}
#: The dark column -- selected steps against #1C1C1C, not an automatic flip.
DARK_EXPECTED = {"ink": 17.04, "ink_secondary": 10.25, "ink_muted": 6.17}


class ThePaletteClearsItsFloors(unittest.TestCase):
    """Recomputed from config.toml, so the palette has one copy and one check."""

    def test_light_ratios_match_design_9_1(self):
        ratios = {row["role"]: row["ratio_vs_panel"] for row in theme.audit("light")}
        for role, expected in LIGHT_EXPECTED.items():
            with self.subTest(role=role):
                self.assertAlmostEqual(ratios[role], expected, places=2)

    def test_dark_ratios_match_design_9_1(self):
        ratios = {row["role"]: row["ratio_vs_panel"] for row in theme.audit("dark")}
        for role, expected in DARK_EXPECTED.items():
            with self.subTest(role=role):
                self.assertAlmostEqual(ratios[role], expected, places=2)

    def test_every_ink_role_clears_the_body_text_floor(self):
        """4.5:1, not the 3:1 large-text floor. Muted ink was darkened from its
        first candidate specifically to clear this."""
        for mode in ("light", "dark"):
            for row in theme.audit(mode):
                if row["role"].startswith("ink"):
                    with self.subTest(mode=mode, role=row["role"]):
                        self.assertGreaterEqual(row["ratio_vs_panel"], theme.BODY_TEXT_FLOOR)

    def test_dark_mode_is_selected_not_flipped(self):
        """Its own steps against its own surface.

        Checked on the *ink* roles rather than on the whole palette. A
        black-and-white house style legitimately reuses white as the light page
        and the dark ink, so "no hex appears in both modes" is the wrong test --
        it held for the parchment palette by accident of hue, not by design. The
        property that matters is that no ink role was reused unchanged, which is
        what an automatic flip would do.
        """
        for role in ("ink", "ink_secondary", "ink_muted"):
            with self.subTest(role=role):
                self.assertNotEqual(
                    theme.palette("light")[role],
                    theme.palette("dark")[role],
                    "an ink role is identical in both modes",
                )

    def test_status_palette_is_not_themed(self):
        """The four support states are a status job, not a categorical one, so they
        do not get a dark variant -- an unset section inherits from [theme], which
        is what "unthemed" means mechanically."""
        palette = theme.status_palette()
        self.assertEqual(
            set(palette), {"corroborated", "single_sourced", "absence_based", "conflicted"}
        )
        dark_section = theme.read_config().get("theme", {}).get("dark", {})
        for key in ("greenColor", "yellowColor", "orangeColor", "redColor"):
            with self.subTest(key=key):
                self.assertNotIn(key, dark_section)

    def test_every_status_colour_clears_the_body_text_floor(self):
        """The Deloitte palette buys something the parchment one could not.

        Under parchment, three of the four status colours measured below 3:1 and
        icon + word was the *mitigation*. On white, all four clear 4.5:1 -- so
        icon + word is now belt-and-braces rather than load-bearing. It stays
        mandatory anyway, because R3.2-R3.5 want the support state to be a word.
        """
        surface = theme.palette("light")[theme.SURFACE_ROLE]
        for name, hex_value in theme.status_palette().items():
            with self.subTest(status=name):
                self.assertGreaterEqual(
                    theme.contrast_ratio(hex_value, surface), theme.BODY_TEXT_FLOOR
                )

    def test_the_green_accent_is_never_used_as_text(self):
        """#86BC25 is the Deloitte brand green and measures 2.27:1 on white, so it
        cannot carry text. It is the rule, the metric edge and the widget accent --
        exactly how the brief uses it."""
        surface = theme.palette("light")[theme.SURFACE_ROLE]
        accent = theme.read_config()["theme"]["primaryColor"]
        self.assertEqual(accent.upper(), "#86BC25")
        self.assertLess(theme.contrast_ratio(accent, surface), theme.LARGE_TEXT_FLOOR)
        # And it is therefore absent from every ink role.
        self.assertNotIn(accent.upper(), {v.upper() for v in theme.palette("light").values()})


class NoWebFontAndNoTelemetry(unittest.TestCase):
    """Both NFR-02 failures are visible by *absence*, so they get a test."""

    def test_no_font_faces_table(self):
        """A [[theme.fontFaces]] entry pointing at a CDN would fetch on first
        paint. Only system stacks appear.

        Checked against the *parsed* config, not the raw text: config.toml
        explains in a comment why the table is absent, so a substring search
        finds the word and reports the opposite of the truth.
        """
        self.assertNotIn("fontFaces", theme.read_config().get("theme", {}))
        self.assertNotIn("[[theme.fontFaces]]", CONFIG_TOML.read_text(encoding="utf-8").replace("* no [[theme.fontFaces]]", ""))

    def test_base_is_a_keyword_not_a_url(self):
        """`theme.base` accepts a remote TOML theme -- the same egress by another
        route."""
        self.assertEqual(theme.read_config()["theme"]["base"], "light")

    def test_usage_stats_are_off(self):
        self.assertIs(theme.read_config()["browser"]["gatherUsageStats"], False)

    def test_the_font_is_a_system_sans(self):
        """No serif anywhere. The parchment design used Georgia for dossier chrome;
        the brief's own house style is sans throughout, and the brief grades
        communication rather than polish."""
        for key in ("font", "headingFont"):
            with self.subTest(key=key):
                stack = theme.read_config()["theme"][key].lower()
                self.assertIn("sans-serif", stack)
                for serif in ("georgia", "palatino", "iowan", "times"):
                    self.assertNotIn(serif, stack)

    def test_font_stacks_name_no_remote_family(self):
        fonts = {
            key: value
            for key, value in theme.read_config()["theme"].items()
            if isinstance(value, str) and "ont" in key
        }
        self.assertTrue(fonts)
        for key, value in fonts.items():
            with self.subTest(key=key):
                self.assertNotIn("http", value)
                self.assertNotIn("url(", value)


class SupportStatesNeverRideOnColourAlone(unittest.TestCase):
    def test_a_badge_with_colour_stripped_still_carries_icon_and_word(self):
        for name in support_badge.SUPPORT_STATES:
            with self.subTest(state=name):
                spec = support_badge.spec(name)
                markup = support_badge.badge_markup(name, colour=False)
                self.assertIn(spec.word, markup)
                self.assertIn(spec.icon, markup)
                # No colour directive survives.
                self.assertNotIn(":green", markup)
                self.assertNotIn(":red", markup)
                self.assertNotIn(":orange", markup)
                self.assertNotIn(":yellow", markup)

    def test_all_four_support_states_are_words(self):
        """R3.2-R3.5 want the support state stated, not shaded."""
        self.assertEqual(
            set(support_badge.SUPPORT_STATES),
            {"corroborated", "single_sourced", "absence_based", "conflicted"},
        )
        for name, spec in support_badge.SUPPORT_STATES.items():
            with self.subTest(state=name):
                self.assertTrue(spec.word.strip())
                self.assertTrue(spec.meaning.strip())

    def test_an_unknown_state_is_refused_rather_than_shown_blank(self):
        with self.assertRaises(support_badge.UnknownSupportState):
            support_badge.spec("probably_fine")


class CitationsAreTopLevelSiblings(unittest.TestCase):
    """SS9.4's constraint, checked statically.

    A runtime check would need a live Streamlit session; the guarantee actually
    lives in the *shape* of the render code, so that is what gets asserted. An
    `st.expander` opened inside another `st.expander` raises
    `StreamlitAPIException`, and the whole reason citations render as siblings
    of the answer body rather than nested inside it is to keep three of them
    openable at once.
    """

    def _with_expander_blocks(self, tree: ast.AST) -> list[ast.With]:
        found = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.With):
                continue
            for item in node.items:
                call = item.context_expr
                if (
                    isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Attribute)
                    and call.func.attr == "expander"
                ):
                    found.append(node)
        return found

    def _expander_calls(self, node: ast.AST) -> list[ast.Call]:
        return [
            inner
            for inner in ast.walk(node)
            if isinstance(inner, ast.Call)
            and isinstance(inner.func, ast.Attribute)
            and inner.func.attr == "expander"
        ]

    def test_no_expander_is_opened_inside_another_expander(self):
        for source in sorted((_env.REPO_ROOT / "app").rglob("*.py")):
            tree = ast.parse(source.read_text(encoding="utf-8"))
            for block in self._with_expander_blocks(tree):
                # The block's own context expression is one expander call; any
                # further one inside the body would nest.
                inside = sum(len(self._expander_calls(stmt)) for stmt in block.body)
                with self.subTest(path=source.name, line=block.lineno):
                    self.assertEqual(
                        inside, 0, "an expander is opened inside another expander"
                    )

    def test_expansion_state_is_keyed_in_session_state(self):
        """So which citations are open survives a rerun -- otherwise every
        interaction would collapse them."""
        self.assertIn("session_state", (_env.REPO_ROOT / "app/components/citation.py").read_text(encoding="utf-8"))

    def test_record_lookup_is_cached(self):
        self.assertIn("cache_data", (_env.REPO_ROOT / "app/components/citation.py").read_text(encoding="utf-8"))

    def test_the_payload_contract_is_enforced_not_assumed(self):
        """T31 produces this shape; the renderer refuses a payload missing a
        required key rather than rendering a blank panel."""
        self.assertEqual(
            citation.REQUIRED_PAYLOAD_KEYS, ("answer_id", "question", "body", "claims")
        )
        with self.assertRaises(citation.PayloadError):
            citation.validate_payload({"question": "what happened?"})

    def test_an_uncited_claim_is_refused(self):
        """R2.2 and R2.3: an uncited claim is a bug, not an empty state."""
        with self.assertRaises(citation.PayloadError):
            citation.validate_payload(
                {
                    "answer_id": "ans_1",
                    "question": "q",
                    "body": "b",
                    "claims": [
                        {
                            "claim_id": "c1",
                            "text": "x",
                            "kind": "observation",
                            "support": {"label": "corroborated"},
                            "citations": [],
                        }
                    ],
                }
            )

    def test_a_claim_list_that_arrived_as_a_string_is_refused(self):
        """A string is a Sequence, so without the explicit check it would iterate
        into characters and render one empty claim per letter."""
        with self.assertRaises(citation.PayloadError):
            citation.validate_payload(
                {"answer_id": "a", "question": "q", "body": "b", "claims": "c1"}
            )


class TablesAvoidTheBlockedPandasPath(unittest.TestCase):
    """The unmeasured SS10.1 assumption, settled.

    This machine's Application Control policy blocks `pandas._libs.join`. Plain
    `import pandas` succeeds, so the failure would not appear at import time --
    it would appear the first time a table did a join-shaped operation, in the
    UI, during the demo.
    """

    ROWS = [
        {"event_id": "EVT-0237", "source_type": "endpoint", "bytes": 2473829122, "note": None},
        {"event_id": "EVT-0238", "source_type": "cloud_storage", "bytes": 2473829122, "note": "x"},
        {"event_id": "EVT-0239", "source_type": "endpoint", "bytes": None, "note": None},
    ]

    def test_a_real_table_builds_through_pyarrow(self):
        table = evidence_table.arrow_table(self.ROWS)
        self.assertEqual(table.num_rows, 3)
        self.assertEqual(table.column_names, ["event_id", "source_type", "bytes", "note"])

    def test_column_order_is_the_caller_s(self):
        table = evidence_table.arrow_table(self.ROWS, columns=["source_type", "event_id"])
        self.assertEqual(table.column_names, ["source_type", "event_id"])

    def test_mixed_and_missing_values_do_not_need_an_object_dtype(self):
        """Arrow has no `object` dtype, so a column mixing types has to be
        coerced deliberately rather than left to inference."""
        table = evidence_table.arrow_table([{"v": 1}, {"v": "two"}, {"v": None}])
        self.assertEqual(table.num_rows, 3)

    def test_an_empty_table_is_refused_rather_than_rendered_blank(self):
        with self.assertRaises(evidence_table.EmptyTable):
            evidence_table.arrow_table([])

    def test_building_a_table_does_not_reach_pandas_at_all(self):
        """The property that actually holds, and the one worth having.

        SS10.1 originally justified dropping `pandera` and `streamlit-aggrid` by
        claiming this machine's Application Control policy blocks
        `pandas._libs.join`. Re-measured here, it does not: the module imports
        and `DataFrame.merge` works. Asserting the block would be asserting
        something false, and asserting `"pandas._libs.join" not in sys.modules`
        is worse than useless -- Streamlit pulls pandas in on its own schedule,
        so the test would pass or fail on import order rather than on anything
        this codebase does.

        What is true, checkable, and the real requirement: the table path runs
        entirely through pyarrow, so *our* code never depends on pandas being
        present or functional.
        """
        before = set(sys.modules)
        evidence_table.arrow_table(self.ROWS)
        newly_imported = set(sys.modules) - before
        self.assertEqual(
            [name for name in newly_imported if name.split(".")[0] == "pandas"],
            [],
            "building a table pulled pandas in",
        )

    def test_no_app_module_imports_pandas(self):
        for source in sorted((_env.REPO_ROOT / "app").rglob("*.py")):
            text = source.read_text(encoding="utf-8")
            with self.subTest(path=source.name):
                self.assertNotIn("import pandas", text)


class AllFourSurfacesExist(unittest.TestCase):
    def test_main_registers_exactly_the_four_designed_surfaces(self):
        text = (_env.REPO_ROOT / "app/main.py").read_text(encoding="utf-8")
        for view in ("chat", "timeline", "impact", "pipeline"):
            with self.subTest(view=view):
                self.assertIn(f"views/{view}.py", text)
                self.assertTrue((_env.REPO_ROOT / "app" / "views" / f"{view}.py").is_file())

    def test_the_pipeline_surface_names_all_six_stages(self):
        self.assertEqual(len(artifacts.STAGES), 6)
        self.assertEqual([stage.number for stage in artifacts.STAGES], [1, 2, 3, 4, 5, 6])

    def test_a_missing_artifact_is_reported_rather_than_crashing(self):
        """Every surface has to render before the build has ever run."""
        notice = artifacts.absent_notice(_env.REPO_ROOT / "data/derived/does_not_exist.jsonl")
        self.assertIsInstance(notice, str)
        self.assertIn("does_not_exist", notice)


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class StartsWithTheNetworkDead(unittest.TestCase):
    """The SS10.2 offline case, and deliberately the harsher one.

    `HTTPS_PROXY` points at a black-holed RFC1918 address rather than a closed
    port, so an outbound attempt *hangs* instead of being refused. A refused
    connection fails fast and would pass a test that a hanging one fails --
    which is the situation issue #8364 described as a 2-5 minute startup stall.
    `ANTHROPIC_API_KEY` is unset, because the query plane must never need it.
    """

    BUDGET_SECONDS = 5.0

    def test_accepts_connections_within_the_budget(self):
        port = _free_port()
        environment = {
            **os.environ,
            "HTTP_PROXY": "http://10.255.255.1:8080",
            "HTTPS_PROXY": "http://10.255.255.1:8080",
            "ALL_PROXY": "http://10.255.255.1:8080",
            "STREAMLIT_BROWSER_GATHER_USAGE_STATS": "false",
        }
        environment.pop("ANTHROPIC_API_KEY", None)
        # localhost must not be proxied, or our own probe would hang too.
        environment["NO_PROXY"] = "127.0.0.1,localhost"

        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "streamlit",
                "run",
                "app/main.py",
                "--server.port",
                str(port),
                "--server.headless",
                "true",
                "--server.fileWatcherType",
                "none",
                "--browser.gatherUsageStats",
                "false",
            ],
            cwd=_env.REPO_ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            started = time.perf_counter()
            deadline = started + 60  # generous ceiling; the assertion is on the measurement
            elapsed = None
            while time.perf_counter() < deadline:
                if process.poll() is not None:
                    self.fail(f"streamlit exited with {process.returncode}:\n{process.stdout.read()}")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                        elapsed = time.perf_counter() - started
                        break
                except OSError:
                    time.sleep(0.1)

            self.assertIsNotNone(elapsed, "the app never accepted a connection")
            print(f"\n  [T07 measured] offline startup with a hanging proxy: {elapsed:.2f} s")
            self.assertLess(
                elapsed,
                self.BUDGET_SECONDS,
                f"startup took {elapsed:.2f}s, over the {self.BUDGET_SECONDS}s budget -- "
                "issue #8364's offline stall may be reproducing",
            )
        finally:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()


if __name__ == "__main__":
    unittest.main()
