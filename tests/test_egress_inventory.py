"""T06 -- the egress inventory: what each model site sends, checked not described.

NFR-04 has two halves. The first is that every category of incident information
leaving the machine is documented -- `docs/egress.md`. The second is that the
documentation is *true*, which a document cannot establish about itself.

So three things have to agree, and none of them is the sole authority:

* the **declaration** -- `egress_categories` on each `Site`;
* the **document** -- the tables in `docs/egress.md`, parsed here rather than
  restated, so a reworded row fails;
* the **evidence** -- the exact serialised request body, captured through
  `httpx.MockTransport` and committed as `tests/fixtures/egress_request_bodies.json`.

`TheCapturedRequestBody` asserts against a **live** capture, with two tests
comparing the committed fixture to it. That ordering was earned: reading the
fixture was the first shape of this file, and a mutation pass found that adding
a seventh top-level field to the request left every test green, because they
were all asserting about the request as captured yesterday.

The contracts themselves -- vocabularies, emitted schemas, the hashes -- are
`tests/test_agent_contracts.py`.

Nothing here opens a socket and nothing needs a credential.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import unittest

import _env  # noqa: F401  -- puts src/ on sys.path

import anthropic

from siem_investigator import ids
from siem_investigator.agent import client, contracts, schemas

SCRIPTS = _env.REPO_ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import regen_egress_fixture  # noqa: E402

EGRESS_DOC = _env.REPO_ROOT / "docs" / "egress.md"
EGRESS_FIXTURE = _env.FIXTURES_DIR / "egress_request_bodies.json"

#: A site heading in `docs/egress.md`: `### 3 · `select_technique` — stage 4, enrich`.
_SITE_HEADING = re.compile(r"^###\s+\d+\s+·\s+`([a-z_]+)`")

#: Node ids and event ids, the identifiers that make a payload traceable to the
#: incident. Used to check that the five protocol fields carry none of them.
_INCIDENT_TOKEN = re.compile(r"\b(?:obs|rec|fnd|map|edg|hyp)_[0-9a-f]{12}\b|\bEVT-\d{4}\b")


def _table_rows(lines: list[str], start: int) -> list[list[str]]:
    """The markdown table beginning at or after `start`, header and rule dropped.

    A markdown parser would be a dependency for one table shape, and design
    10.1 freezes the dependency set. This is the whole grammar we need: rows
    begin and end with a pipe, and the run ends at the first line that does not.
    """
    rows: list[list[str]] = []
    seen_table = False
    for line in lines[start:]:
        stripped = line.strip()
        if not stripped.startswith("|"):
            if seen_table:
                break
            continue
        seen_table = True
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if all(set(cell) <= {"-", ":"} and cell for cell in cells):
            continue
        rows.append(cells)
    return rows[1:] if rows else []


def documented_categories() -> dict[str, list[str]]:
    """Site name -> the categories `docs/egress.md` tables for it, in order."""
    lines = EGRESS_DOC.read_text(encoding="utf-8").splitlines()
    tabled: dict[str, list[str]] = {}
    for index, line in enumerate(lines):
        match = _SITE_HEADING.match(line)
        if match:
            tabled[match.group(1)] = [row[0] for row in _table_rows(lines, index)]
    return tabled


def documented_envelope() -> dict[str, bool]:
    """Body field -> whether the envelope table says it carries incident information.

    The verdict cell is read as its first word, so a cell may explain itself
    afterwards -- `system` does -- without the parse turning on the prose.
    """
    lines = EGRESS_DOC.read_text(encoding="utf-8").splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("## The request envelope"))
    envelope: dict[str, bool] = {}
    for row in _table_rows(lines, start):
        field = row[0].strip("`*")
        verdict = row[-1].strip("*").split()[0].lower()
        if verdict not in {"yes", "no"}:
            raise AssertionError(f"{field}: verdict {verdict!r} is neither yes nor no")
        envelope[field] = verdict == "yes"
    return envelope


def incident_tokens(payload: str) -> list[str]:
    """The node and event ids a payload names, deduplicated."""
    return sorted(set(_INCIDENT_TOKEN.findall(payload)))


class TheCapturedRequestBody(unittest.TestCase):
    """NFR-04's second half, tested rather than described.

    The capture goes through the same `_request_kwargs` the live call uses.
    Building the request twice is exactly what would let this inventory describe
    a request the system does not send.

    Every assertion below runs against a **live** capture, not against the
    committed fixture. Reading the fixture was the first shape of this class and
    a mutation pass killed it: adding a seventh top-level field to
    `_request_kwargs` left every test green, because they were all asserting
    about the request as it was captured yesterday. The fixture is still
    committed -- a reviewer should be able to read what is sent without running
    anything -- and two tests compare it against the live capture, so it cannot
    go stale either.
    """

    @classmethod
    def setUpClass(cls):
        cls.live = regen_egress_fixture.build()
        cls.fixture = json.loads(EGRESS_FIXTURE.read_text(encoding="utf-8"))

    def _body(self, site: contracts.Site) -> dict:
        return self.live["sites"][site.name]["request_body"]

    def _blocks(self, site: contracts.Site) -> list[contracts.PayloadBlock]:
        return [
            contracts.PayloadBlock(block["category"], block["text"])
            for block in self.live["sites"][site.name]["payload_blocks"]
        ]

    def test_the_fixture_regenerates_byte_for_byte(self):
        """Committed evidence has to be evidence of the current code. `--check`
        rebuilds every body through `captured_request_body` and diffs."""
        self.assertEqual(regen_egress_fixture.main(["--check"]), 0)

    def test_the_committed_fixture_is_the_live_capture(self):
        """The same property as `--check`, asserted per site so a diff names the
        site and the field rather than the whole file."""
        for site in contracts.SITES:
            with self.subTest(site=site.name):
                self.assertEqual(
                    self.live["sites"][site.name], self.fixture["sites"][site.name]
                )

    def test_the_three_named_calls_are_captured(self):
        """T06 names INTERPRET, the technique selection and ANSWER. HYPOTHESISE
        is captured too, because a contract left out of the fixture is a contract
        whose egress nobody checks."""
        for name in ("interpret", "select_technique", "answer", "hypothesise"):
            with self.subTest(site=name):
                self.assertIn(name, self.fixture["sites"])
                self.assertIn(name, self.live["sites"])

    def test_every_site_builds_a_request_with_no_credential_and_no_network(self):
        for site in contracts.SITES:
            with self.subTest(site=site.name):
                body = self._body(site)
                self.assertEqual(body["model"], client.MODEL_ID)
                self.assertEqual(body["thinking"], {"type": "adaptive"})

    def test_the_top_level_fields_are_exactly_the_documented_envelope(self):
        """Not a hand-kept allow-list in this file: the set is parsed out of the
        envelope table in `docs/egress.md`, so an unreviewed field reaching the
        provider fails until someone documents it."""
        documented = set(documented_envelope())
        self.assertEqual(len(documented), 6, "the envelope table did not parse as expected")
        for site in contracts.SITES:
            with self.subTest(site=site.name):
                self.assertEqual(set(self._body(site)), documented)

    def test_the_system_prompt_is_the_committed_one_verbatim(self):
        """A system prompt is authored text rather than incident data, but it
        still goes out, so it is pinned instead: it lives in
        `agent/contracts.py` and is hashed into the contract-set hash.

        This asserts the body carries the committed prompt, not that the prompt
        is unchanged -- an edited prompt is caught by the fixture diff and by
        the contract-set hash, which is where a prompt change belongs.
        """
        for site in contracts.SITES:
            with self.subTest(site=site.name):
                self.assertEqual(self._body(site)["system"], site.system)

    def test_the_user_message_is_exactly_the_labelled_blocks(self):
        """"Nothing beyond it is sent", as an equality rather than a search. The
        payload is the labelled blocks and nothing else -- no preamble, no
        trailing instruction that escaped review.

        The expectation is joined here rather than taken from
        `render_payload`. Calling the function under test to compute its own
        expected value is how a mutation pass found this test passing while
        `render_payload` prepended "PLEASE BE THOROUGH." to every prompt.
        """
        for site in contracts.SITES:
            with self.subTest(site=site.name):
                messages = self._body(site)["messages"]
                self.assertEqual(len(messages), 1)
                self.assertEqual(messages[0]["role"], "user")
                self.assertEqual(
                    messages[0]["content"],
                    contracts.BLOCK_SEPARATOR.join(
                        block.text for block in self._blocks(site)
                    ),
                )

    def test_every_payload_block_maps_to_a_declared_category(self):
        """The mapping the requirement actually asks for: every piece of a
        prompt says which documented category it instantiates, so the check is a
        lookup rather than someone reading a prompt and judging."""
        for site in contracts.SITES:
            for block in self._blocks(site):
                with self.subTest(site=site.name, category=block.category):
                    self.assertIn(block.category, site.egress_categories)

    def test_every_declared_category_is_exercised_by_the_fixture(self):
        """Otherwise the fixture checks the convenient half of the declaration
        and the rest stays untested prose."""
        for site in contracts.SITES:
            with self.subTest(site=site.name):
                self.assertEqual(
                    {block.category for block in self._blocks(site)},
                    set(site.egress_categories),
                )

    def test_only_the_message_field_carries_incident_information(self):
        """The envelope table says five of the six fields carry none. Checked by
        looking for the payload's own node ids and event ids in them, so a
        `metadata` block, or an observation id reaching a schema description,
        fails."""
        for site in contracts.SITES:
            body = self._body(site)
            tokens = incident_tokens(body["messages"][0]["content"])
            with self.subTest(site=site.name):
                self.assertTrue(tokens, "the payload has no identifiers to look for")
                rest = json.dumps({k: v for k, v in body.items() if k != "messages"})
                for token in tokens:
                    self.assertNotIn(token, rest, f"{token} reached a protocol field")

    def test_the_schema_sent_is_exactly_the_contracts(self):
        """`output_config` is documented as protocol, which is only true if it
        carries the response contract and nothing else."""
        for site in contracts.SITES:
            with self.subTest(site=site.name):
                sent = self._body(site)["output_config"]["format"]["schema"]
                expected = client.wire_schema(regen_egress_fixture.model_type_for(site))
                self.assertEqual(sent, expected)

    def test_the_repaired_schema_is_what_actually_goes_out(self):
        """The measured SDK behaviour this guards: `transform_schema` discards
        `enum`, so without the repair a closed Literal arrives as a description
        hint and a hallucinated value is accepted by the API. `wire_schema` says
        what we intend to send; this says what the SDK did."""
        body = self._body(contracts.SELECT_TECHNIQUE)
        self.assertEqual(client.request_defects(body), [])
        sent = body["output_config"]["format"]["schema"]
        self.assertEqual(
            sent["properties"]["technique_id"]["enum"],
            list(regen_egress_fixture.CANDIDATE_TECHNIQUE_IDS),
        )

    def test_the_stage_enum_survives_to_the_wire_for_interpret(self):
        sent = self._body(contracts.INTERPRET)["output_config"]["format"]["schema"]
        self.assertIn("enum", sent["properties"]["stage"])

    def test_the_body_carries_no_raw_note_field(self):
        """The dataset's answer key is stripped at the parse boundary, so no
        prompt can contain it."""
        for site in contracts.SITES:
            rendered = json.dumps(self._body(site))
            with self.subTest(site=site.name):
                self.assertNotIn("ATTACK:", rendered)

    def test_the_fixture_quotes_only_benign_events(self):
        """It is committed, readable and prompt-shaped, so populating it from the
        intrusion would turn a test fixture into a hint sheet. R7.2 confines the
        answer key to accuracy measurement."""
        attack_ids = [f"EVT-{index:04d}" for index in range(221, 243)]
        for site in contracts.SITES:
            rendered = json.dumps(self._body(site))
            for event_id in attack_ids:
                with self.subTest(site=site.name, event=event_id):
                    self.assertNotIn(event_id, rendered)

    def test_the_body_carries_no_credential(self):
        for site in contracts.SITES:
            rendered = json.dumps(self._body(site)).lower()
            with self.subTest(site=site.name):
                self.assertNotIn("sk-ant", rendered)
                self.assertNotIn("api_key", rendered)

    def test_the_fixture_records_both_replay_inputs_and_the_sdk_version(self):
        """A captured body only means something alongside the contract set that
        produced it and the SDK that serialised it -- the schema transform is
        the SDK's, so its version is part of the evidence."""
        for recorded in (self.fixture, self.live):
            self.assertEqual(recorded["contract_set_hash"], contracts.CONTRACT_SET_HASH)
            self.assertEqual(recorded["validator_version"], contracts.VALIDATOR_VERSION)
            self.assertEqual(recorded["provider_sdk_version"], anthropic.__version__)

    def test_the_prompt_hash_in_the_fixture_is_the_one_the_prompt_pair_yields(self):
        """SS11.1 records which prompt produced a proposal by its hash. A recorded
        hash that does not recompute is not a record of anything."""
        for site in contracts.SITES:
            entry = self.live["sites"][site.name]
            user = entry["request_body"]["messages"][0]["content"]
            with self.subTest(site=site.name):
                # SS8.2's canonical form directly, not `prompt_hash` -- which is
                # the function under test, and would agree with itself however
                # it was mutated.
                self.assertEqual(
                    entry["prompt_hash"],
                    ids.content_digest({"system": site.system, "user": user}),
                )


class TheEgressDocumentAndTheCodeAgree(unittest.TestCase):
    """Both directions.

    A category in code and not in the document is undocumented egress -- the
    NFR-04 failure. A category in the document and not in code is stale
    documentation, which fails the same requirement from the other side: the
    document is then no longer a true statement of what is sent.
    """

    def test_each_site_declares_exactly_what_the_document_tables(self):
        tabled = documented_categories()
        self.assertEqual(set(tabled), {site.name for site in contracts.SITES})
        for site in contracts.SITES:
            with self.subTest(site=site.name):
                self.assertEqual(tabled[site.name], list(site.egress_categories))

    def test_the_document_names_the_stage_each_site_runs_at(self):
        text = EGRESS_DOC.read_text(encoding="utf-8")
        for site in contracts.SITES:
            with self.subTest(site=site.name):
                self.assertIn(f"`{site.name}` — stage {site.stage.split()[0]}", text)

    def test_the_envelope_table_marks_exactly_one_field_as_incident_information(self):
        envelope = documented_envelope()
        carriers = [field for field, carries in envelope.items() if carries]
        self.assertEqual(carriers, ["messages"])

    def test_exactly_three_model_stages(self):
        """Design SS7's claim, as a test. A fourth stage appearing without a
        documented egress category is what the inventory exists to catch."""
        self.assertEqual(len(contracts.MODEL_STAGES), 3)

    def test_the_doc_names_what_is_never_sent(self):
        text = EGRESS_DOC.read_text(encoding="utf-8")
        for absent in ("ground_truth.json", "`note`", "credential"):
            with self.subTest(item=absent):
                self.assertIn(absent, text)


class TheUndeclaredCategoryCannotReachAPrompt(unittest.TestCase):
    """The mechanism behind the fixture.

    A test over a fixture pins today's request. `render_payload` is what keeps
    the inventory true once T22, T24 and T31 write the real prompt builders:
    undocumented material cannot reach a prompt at all.
    """

    def test_a_category_the_site_does_not_declare_is_refused(self):
        with self.assertRaises(contracts.UndeclaredEgress) as caught:
            contracts.render_payload(
                contracts.INTERPRET,
                [contracts.PayloadBlock("the analyst's question", "QUESTION x")],
            )
        self.assertIn("docs/egress.md", str(caught.exception))

    def test_a_declared_category_is_accepted(self):
        block = contracts.PayloadBlock(contracts.INTERPRET.egress_categories[0], "OBSERVATIONS x")
        self.assertEqual(contracts.render_payload(contracts.INTERPRET, [block]), "OBSERVATIONS x")

    def test_an_empty_payload_is_refused(self):
        """A prompt with no blocks asks the model to reason over nothing, and
        would pass every category check by vacuity."""
        with self.assertRaises(ValueError):
            contracts.render_payload(contracts.ANSWER, [])

    def test_the_separator_the_check_splits_on_is_the_one_render_joins_with(self):
        first, second = (
            contracts.PayloadBlock(category, category.split()[0].upper())
            for category in contracts.HYPOTHESISE.egress_categories[:2]
        )
        self.assertEqual(
            contracts.render_payload(contracts.HYPOTHESISE, [first, second]),
            first.text + contracts.BLOCK_SEPARATOR + second.text,
        )

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
