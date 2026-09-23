"""T07 -- the render constraints proved by running the app, not by reading it.

`tests/test_ui_render.py` checks what can be checked without a script run: the
palette arithmetic, the badge strings, the Arrow tables, the payload contract,
and startup with the network dead. This module covers what cannot, and T07's
verification turns on the difference.

Streamlit's element tree is built during a script run. So is the answer to every
question below: whether three citations can be open simultaneously, whether the
expanders really are siblings of the answer body rather than nested, whether
session state carries expansion across a rerun, whether all four surfaces
navigate, and whether a table reaches the browser with pandas unavailable.
`streamlit.testing.v1.AppTest` runs the real script through the real
ScriptRunner, in process, with no server and no browser -- so these are
measurements, not simulations.

**One measured fact that changes what the check means.** Design SS9.4 frames the
sibling layout around `StreamlitAPIException: Expanders may not be nested inside
other expanders`. On streamlit 1.64.0 that guard no longer exists: a nested
expander raises nothing at all (verified by rendering one -- the backend has no
ancestor check left, and `grep` over the package finds the message only for
dialogs and forms). "No exception was raised" is therefore now satisfied by the
illegal layout too. So the check here is structural -- no expander has an
expander ancestor in the rendered tree -- which stays meaningful whichever way
a future Streamlit version goes.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
import unittest

import _env  # noqa: F401  -- puts src/ on sys.path

if str(_env.REPO_ROOT) not in sys.path:
    # app/ is a package at the repository root rather than under src/.
    # app/main.py arranges this for itself at runtime; a test importing app.*
    # has to do it here. tests/_env.py is shared, so it is left untouched.
    sys.path.insert(0, str(_env.REPO_ROOT))

import pyarrow as pa  # noqa: E402
from streamlit.testing.v1 import AppTest  # noqa: E402

from app import theme  # noqa: E402
from app.components import citation  # noqa: E402

MAIN = _env.REPO_ROOT / "app" / "main.py"

#: Generous. A cold first import is slow, and slowness is not what this file is
#: looking for; a hang still fails, and SS10.2's 5 s startup budget is measured
#: separately in tests/test_ui_render.py against a real server.
RENDER_TIMEOUT = 60

#: The layout specimen's citation count, and the number of expanders the chat
#: surface therefore renders. Written out so a specimen that quietly lost a
#: citation fails here rather than weakening every assertion below.
SPECIMEN_CITATIONS = 7
#: One of the seven points at a record id that is deliberately absent (R2.9).
SPECIMEN_RESOLVABLE = 6
#: Three carry `open_by_default`, which is T07's "three citations at once".
SPECIMEN_OPEN_BY_DEFAULT = 3


def walk(node, ancestors: tuple[str, ...] = ()):
    """Yield `(node, type, ancestor types)` over a rendered element tree.

    AppTest's accessors are flat -- `at.expander` returns every expander
    anywhere in the tree -- so the nesting question cannot be asked through
    them at all. This walk is what makes "are they siblings" assertable.
    """
    kind = getattr(node, "type", None)
    yield node, kind, ancestors
    children = getattr(node, "children", None)
    if children:
        for _, child in sorted(children.items()):
            yield from walk(child, ancestors + ((kind,) if kind else ()))


def arrow_tables(run) -> list[pa.Table]:
    """Every rendered dataframe, read back from the Arrow IPC bytes it sent.

    Deliberately not `AppTest.dataframe[i].value`, which calls
    `convert_arrow_bytes_to_pandas_df` and would drag pandas onto the path this
    task exists to keep clear. These bytes are what the browser receives, so
    reading them is also the closest a test gets to asserting what a reader
    sees.
    """
    tables = []
    for element in run.dataframe:
        data = element.proto.arrow_data.data
        if data:
            tables.append(pa.ipc.open_stream(data).read_all())
    return tables


class TheCitationLayoutRenders(unittest.TestCase):
    """One run, shared: every assertion below is about the same rendered tree.

    The tree is the **pipeline** surface, because that is where the citation
    specimen lives. It started on the chat surface and moved: a synthetic answer
    sitting beside real ones was the most confusing thing in the UI, and as
    render evidence it belongs with the rest of the working.

    Named `app` rather than `run` because `TestCase.run` is how unittest invokes
    a test -- shadowing it makes every test in the class unrunnable with a
    confusing `TypeError`.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.app = AppTest.from_file(str(MAIN), default_timeout=RENDER_TIMEOUT).run()
        cls.app.switch_page("views/pipeline.py").run()

    def test_it_renders_without_exception(self):
        self.assertEqual([(e.type, e.value) for e in self.app.exception], [])

    def test_three_citations_are_expanded_at_once(self):
        """T07's headline check, run rather than reasoned about.

        Three citations open simultaneously, each rendering its raw record
        through `st.json(body, expanded=2)`, and nothing raised.
        """
        expanded = [box for box in self.app.expander if box.proto.expanded]
        self.assertEqual(len(expanded), SPECIMEN_OPEN_BY_DEFAULT)
        self.assertEqual(len(self.app.json), SPECIMEN_OPEN_BY_DEFAULT)
        self.assertEqual([e.type for e in self.app.exception], [])

    def test_no_rendered_expander_has_an_expander_ancestor(self):
        """The invariant SS9.4 calls a day-one constraint, structurally.

        Strictly stronger than the absence of a `StreamlitAPIException`, which
        streamlit 1.64.0 no longer raises for nesting -- see the module
        docstring.
        """
        nested = [
            getattr(node, "label", "?")
            for node, kind, ancestors in walk(self.app.main)
            if kind == "expander" and "expander" in ancestors
        ]
        self.assertEqual(nested, [], f"expanders nested inside expanders: {nested}")

    def test_every_citation_expander_is_a_sibling_inside_the_message(self):
        """SS9.4 says *inside* `st.chat_message`, as siblings of the answer body.

        Both halves matter. Outside the chat message the citations would stop
        being part of the answer; nested inside one another they would stop
        being openable together.
        """
        placements = [
            ancestors
            for _, kind, ancestors in walk(self.app.main)
            if kind == "expander" and "chat_message" in ancestors
        ]
        self.assertEqual(len(placements), SPECIMEN_CITATIONS)
        for ancestors in placements:
            self.assertEqual(ancestors, ("main", "chat_message"))

        # And nothing on the surface nests one expander inside another, which is
        # the property the flat layout exists for.
        nested = [
            ancestors
            for _, kind, ancestors in walk(self.app.main)
            if kind == "expander" and "expander" in ancestors
        ]
        self.assertEqual(nested, [])

    def test_the_answer_body_precedes_its_citations(self):
        """Reading order is part of the layout: prose first, evidence under it."""
        order = [
            kind
            for _, kind, ancestors in walk(self.app.main)
            if ancestors and ancestors[-1] == "chat_message"
        ]
        self.assertIn("markdown", order)
        self.assertIn("expander", order)
        self.assertLess(order.index("markdown"), order.index("expander"))

    def test_an_unresolved_citation_names_the_identifier(self):
        """R2.9: a cited identifier that does not exist is reported, not hidden.

        The specimen points one citation at a record id that is absent from its
        bundled records, so this path is rendered rather than described.
        """
        errors = [error.value for error in self.app.error]
        self.assertTrue(
            any("rec_deliberately_absent" in text for text in errors),
            f"the unresolved citation was not reported: {errors}",
        )

    def test_the_citation_table_reaches_the_browser_as_a_real_table(self):
        """SS10.1's route, asserted on the bytes that were sent.

        A citation table is the heterogeneous case -- `asserted_value` holds a
        process name on one row and a byte count on the next -- so this is also
        where the Arrow coercion either works or does not.
        """
        tables = arrow_tables(self.app)
        citation_tables = [
            table for table in tables if "node_id" in table.column_names
        ]
        self.assertEqual(len(citation_tables), 4, "one per specimen claim")
        first = citation_tables[0]
        self.assertEqual(list(first.column_names), list(citation.CITATION_COLUMNS))
        self.assertEqual(first.num_rows, 3)
        self.assertIn("obs_000000000001", first.column("node_id").to_pylist())
        # The mixed column survived as text rather than raising ArrowTypeError.
        self.assertIn("1024", first.column("asserted_value").to_pylist())

    def test_expansion_state_is_keyed_in_session_state(self):
        """Opening a citation through session state opens it on the next run.

        This is what `key=` plus `on_change="rerun"` buys, and measuring it was
        worth the trouble: with the default `on_change="ignore"` an expander
        tracks no state at all -- `.open` is None, the key never reaches session
        state -- so every citation the reader had opened would collapse on the
        next rerun. That is the failure this test exists to catch, and it is
        invisible in a static read of the code.
        """
        run = AppTest.from_file(str(MAIN), default_timeout=RENDER_TIMEOUT).run()
        # The specimen lives on the pipeline surface: it is render evidence, and
        # a synthetic answer sitting beside real ones on the chat surface was
        # the single most confusing thing in the UI.
        run.switch_page("views/pipeline.py").run()
        keys = [
            box.key
            for box in run.expander
            if box.key and box.key.startswith("pipeline::specimen::")
        ]
        self.assertEqual(len(keys), SPECIMEN_CITATIONS)
        self.assertEqual(len(set(keys)), SPECIMEN_CITATIONS, "two citations share a key")
        for key in keys:
            with self.subTest(key=key):
                # The key carries answer, claim and node, so the same
                # observation cited by two claims stays two independent
                # expanders rather than colliding.
                self.assertIn("pipeline::specimen::", key)
                self.assertIn(key, run.session_state)

        closed = [
            box.key
            for box in run.expander
            if box.key
            and box.key.startswith("pipeline::specimen::")
            and not box.proto.expanded
        ]
        self.assertEqual(len(closed), SPECIMEN_CITATIONS - SPECIMEN_OPEN_BY_DEFAULT)
        for key in closed:
            run.session_state[key] = True
        run.run()

        reopened = {box.key: box.proto.expanded for box in run.expander}
        for key in closed:
            with self.subTest(key=key):
                self.assertTrue(reopened[key], "session state did not reopen it")
        self.assertEqual([e.type for e in run.exception], [])
        # Every citation open at once -- the layout's worst case, and still no
        # nesting exception and no lost record.
        self.assertEqual(len(run.json), SPECIMEN_RESOLVABLE)
        nested = [
            1
            for _, kind, ancestors in walk(run.main)
            if kind == "expander" and "expander" in ancestors
        ]
        self.assertEqual(nested, [])

    def test_the_specimen_is_banned_as_a_specimen_on_screen(self):
        """It must be impossible to mistake for incident data, in the room."""
        warnings = " ".join(warning.value for warning in self.app.warning)
        self.assertIn("layout specimen", warnings.lower())
        self.assertIn("synthetic", warnings.lower())


class AllFourSurfacesNavigate(unittest.TestCase):
    """SS9.4's four surfaces, navigated rather than listed."""

    SURFACES = {
        "views/chat.py": "Incident assistant",
        "views/timeline.py": "Timeline",
        "views/impact.py": "Impact",
        "views/pipeline.py": "Pipeline",
    }

    def test_each_surface_navigates_and_renders(self):
        run = AppTest.from_file(str(MAIN), default_timeout=RENDER_TIMEOUT).run()
        for page, title in self.SURFACES.items():
            with self.subTest(page=page):
                run.switch_page(page).run()
                self.assertEqual(
                    [(e.type, e.value) for e in run.exception], [], f"{page} raised"
                )
                self.assertEqual([element.value for element in run.title], [title])

    def test_a_surface_either_names_its_missing_artifact_or_renders_it(self):
        """The honesty rule, in both directions.

        With no artifact behind it, a surface must name the file it is waiting
        for rather than render an invented row. With the artifact present it
        must actually render it -- an earlier version of this test only checked
        the empty case, so it went on passing after the surfaces were wired and
        would have kept passing if they had rendered nothing at all.
        """
        from siem_investigator import paths

        run = AppTest.from_file(str(MAIN), default_timeout=RENDER_TIMEOUT).run()
        for page, artifact, path in (
            ("views/timeline.py", "05_timeline.json", paths.TIMELINE),
            ("views/impact.py", "05_scope.json", paths.SCOPE),
        ):
            with self.subTest(page=page):
                run.switch_page(page).run()
                self.assertEqual([(e.type, e.value) for e in run.exception], [])
                if path.is_file():
                    # Rendered: at least one real table, and no "waiting" notice.
                    self.assertTrue(
                        len(run.dataframe) >= 1,
                        f"{page} has its artifact but rendered no table",
                    )
                else:
                    notices = " ".join(
                        element.value for element in list(run.info) + list(run.error)
                    )
                    self.assertIn(artifact, notices)

    def test_the_pipeline_surface_reports_every_stage_state(self):
        run = AppTest.from_file(str(MAIN), default_timeout=RENDER_TIMEOUT).run()
        run.switch_page("views/pipeline.py").run()
        self.assertEqual([(e.type, e.value) for e in run.exception], [])
        labels = [status.label for status in run.status]
        self.assertEqual(len(labels), 6, f"six stages, got {labels}")
        for number in range(1, 7):
            with self.subTest(stage=number):
                self.assertTrue(
                    any(label.startswith(f"Stage {number} ") for label in labels),
                    f"stage {number} is missing from {labels}",
                )

    def test_the_rendered_palette_audit_shows_the_measured_ratios(self):
        """SS9.1's figures, computed from config.toml and read back out of the
        bytes the app sent.

        This is the contrast check in its strongest form: not that the ratios
        can be computed, but that the numbers the product displays are the ones
        SS9.1 measured. The hexes live only in `.streamlit/config.toml`, so the
        expected ratios here cannot be reconciled with a colour by editing one
        file.
        """
        run = AppTest.from_file(str(MAIN), default_timeout=RENDER_TIMEOUT).run()
        run.switch_page("views/pipeline.py").run()
        self.assertEqual([(e.type, e.value) for e in run.exception], [])

        audits = [
            table
            for table in arrow_tables(run)
            if {"role", "hex", "ratio_vs_panel"} <= set(table.column_names)
        ]
        self.assertEqual(len(audits), 2, "one audit table per mode")

        light, dark = ({}, {})
        for table in audits:
            rows = dict(
                zip(table.column("role").to_pylist(), table.column("hex").to_pylist())
            )
            ratios = dict(
                zip(
                    table.column("role").to_pylist(),
                    table.column("ratio_vs_panel").to_pylist(),
                )
            )
            target = light if rows["ink"] == theme.palette("light")["ink"] else dark
            target.update(ratios)

        self.assertEqual(
            (light["ink"], light["ink_secondary"], light["ink_muted"]),
            (19.6, 6.89, 5.39),
        )
        self.assertEqual(
            (dark["ink"], dark["ink_secondary"], dark["ink_muted"]),
            (17.04, 10.25, 6.17),
        )
        self.assertEqual((light["rule"], light["baseline"]), (1.44, 1.78))
        self.assertEqual((dark["rule"], dark["baseline"]), (1.35, 1.57))

    def test_the_status_audit_shows_colour_is_never_sufficient_alone(self):
        run = AppTest.from_file(str(MAIN), default_timeout=RENDER_TIMEOUT).run()
        run.switch_page("views/pipeline.py").run()
        status = [
            table
            for table in arrow_tables(run)
            if "support_state" in table.column_names
        ]
        self.assertEqual(len(status), 1)
        sufficient = status[0].column("colour_alone_sufficient").to_pylist()
        # Under the parchment palette three of the four measured below 3:1, and
        # icon + word was the mitigation. On the Deloitte white ground all four
        # clear it, so the audit now reports that. Icon + word stays mandatory
        # regardless, because R3.2-R3.5 want the support state to be a *word*.
        self.assertEqual(sufficient.count(False), 0, "all four now clear 3:1 on white")


class TablesRenderWithPandasBlocked(unittest.TestCase):
    """SS10.1's last unmeasured assumption, settled as hard as it can be.

    Run in a subprocess for two reasons: a `sys.meta_path` hook is
    process-global and would leak into the rest of the suite, and `pandas` may
    already be imported by the time this test runs, which would make an
    in-process block unenforceable.

    The block covers all of `pandas`, not just `pandas._libs.join`. That is
    deliberate and stronger than SS10.1 needs: if no part of pandas is reached,
    the blocked submodule cannot be reached by any route -- including the lazy
    `import pandas as pd` calls inside `streamlit.dataframe_util`, which are the
    ones a source-level check would never see.
    """

    PROBE = textwrap.dedent(
        """
        import json, sys

        class Blocker:
            '''Refuse every pandas import, the way the Application Control
            policy refuses one of them.'''

            def find_spec(self, fullname, path=None, target=None):
                if fullname == "pandas" or fullname.startswith("pandas."):
                    raise ImportError("blocked by the T07 probe: " + fullname)
                return None

        sys.meta_path.insert(0, Blocker())
        sys.path.insert(0, ROOT)
        sys.path.insert(0, ROOT + "/src")

        from streamlit.testing.v1 import AppTest

        at = AppTest.from_file(ROOT + "/app/main.py", default_timeout=120).run()
        result = {
            "chat_exceptions": [str(e.value) for e in at.exception],
            "chat_dataframes": len(at.dataframe),
            "chat_json": len(at.json),
            "chat_expanders": len(at.expander),
        }

        at.switch_page("views/pipeline.py").run()
        result["pipeline_exceptions"] = [str(e.value) for e in at.exception]
        result["pipeline_dataframes"] = len(at.dataframe)
        result["pipeline_json"] = len(at.json)
        result["pipeline_citation_expanders"] = len(
            [b for b in at.expander if b.key and b.key.startswith("pipeline::specimen::")]
        )
        result["pandas_modules"] = sorted(
            name for name in sys.modules
            if name == "pandas" or name.startswith("pandas.")
        )
        print("T07-RESULT " + json.dumps(result))
        """
    )

    def test_every_table_renders_with_every_pandas_import_blocked(self):
        script = f"ROOT = {str(_env.REPO_ROOT)!r}\n" + self.PROBE
        completed = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=str(_env.REPO_ROOT),
        )
        self.assertEqual(
            completed.returncode, 0, f"probe failed:\n{completed.stderr[-4000:]}"
        )
        line = next(
            (t for t in completed.stdout.splitlines() if t.startswith("T07-RESULT ")),
            None,
        )
        self.assertIsNotNone(line, f"probe printed no result:\n{completed.stdout}")
        result = json.loads(str(line).removeprefix("T07-RESULT "))

        self.assertEqual(result["chat_exceptions"], [])
        self.assertEqual(result["pipeline_exceptions"], [])
        # Only the pipeline surface is probed: it is the one that enumerates
        # without charting, and it carries the citation specimen. The timeline
        # and impact surfaces both hold a chart now, and -- measured, not assumed
        # -- `st.vega_lite_chart` reaches pandas through Streamlit's Vega
        # integration even when handed a plain dict. The *table* path avoids
        # pandas, which is the property this test exists for; the chart path does
        # not, and asserting otherwise would be asserting something false.
        self.assertEqual(result["pipeline_citation_expanders"], SPECIMEN_CITATIONS)
        self.assertEqual(result["pipeline_json"], SPECIMEN_OPEN_BY_DEFAULT)
        self.assertGreaterEqual(result["pipeline_dataframes"], 3)
        self.assertEqual(
            result["pandas_modules"], [], "the render path reached pandas after all"
        )


if __name__ == "__main__":
    unittest.main()
