"""The prompt/contract set, as a versioned artifact (T06).

Design SS11.1 defines replay reproducibility as: *given the committed trajectory,
the contract-set hash and the validator version, every validation verdict is
bit-for-bit reproducible.* The interpretive layer is an untrusted,
out-of-TCB step that affects coverage only -- the de Bruijn / LCF posture, and
a stronger claim than sampling control could give, since temperature 0 is not
determinism anyway.

That claim needs both of its inputs to exist as *values*, which is what this
module supplies:

* `CONTRACT_SET_HASH` -- a digest over every prompt and every emitted schema, so
  a reworded prompt or a widened contract is visible as a changed number rather
  than as a diff nobody read.
* `VALIDATOR_VERSION` -- bumped when the meaning of accept/reject changes, and
  stamped onto every artifact.

Four contracts across design SS7's three model *stages*, matching
`docs/egress.md` row for row -- INTERPRET and HYPOTHESISE are two contracts at
one stage. A test asserts both numbers: a fourth *stage*, or a category declared
here and not documented there, is the failure the inventory exists to catch.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from . import client, schemas

#: Bumped when the meaning of an accept or a reject changes -- a check added,
#: removed, or altered in what it admits. Not bumped for a refactor that leaves
#: every verdict identical, because then a recorded verdict is still replayable.
VALIDATOR_VERSION = "1"

#: Stated once, shared by all four contracts. Site prompts add to it; none of
#: them contradicts it.
COMMON_SYSTEM = """\
You are an evidence-bound assistant reconstructing a cyber intrusion from \
already-parsed log observations.

Three rules, and they are absolute:

1. Name only entities, values, identifiers and timestamps that appear in an \
observation you cite. An identifier you did not read in the supplied material \
is a fabrication, and a deterministic check will reject the whole proposal and \
name it.
2. Never state a probability, a percentage, a confidence level or an adjective \
of belief. How strongly something is supported is computed from the evidence \
structure afterwards, not asserted by you.
3. Absence is not evidence on its own. If you believe something did not \
happen, say what record would have shown it and which source should have \
carried it, so the difference between "it did not happen" and "no source could \
have seen it" stays visible.
"""


@dataclass(frozen=True)
class Site:
    """One model site: where it sits, what it may send, what it must return."""

    name: str
    stage: str
    purpose: str
    model_type: type[BaseModel]
    system: str
    #: Categories of incident information the prompt may contain. Must match a
    #: row of `docs/egress.md`, and the captured-request test checks that the
    #: body carries nothing outside them.
    egress_categories: tuple[str, ...]

    def wire_schema(self) -> dict[str, Any]:
        return client.wire_schema(self.model_type)


INTERPRET = Site(
    name="interpret",
    stage="3 correlate",
    purpose=(
        "Propose a candidate finding over a neighbourhood of observations and the factual "
        "edges that hold between them. The deterministic layer has already computed every "
        "relation; this step interprets them and computes nothing."
    ),
    model_type=schemas.CandidateFinding,
    system=COMMON_SYSTEM
    + """
You are given a neighbourhood: some observations, and the factual edges that \
hold between them. The edges were computed deterministically and are true; \
your job is to say what they mean, if they mean anything.

Cite the specific edges your reading rests on. If the neighbourhood supports no \
interpretation, say so rather than manufacturing one -- "nothing here" is a \
useful answer and a wrong finding is not.

`temporal_within` reports the interval between two observations rather than \
thresholding it. Decide in context whether a given gap is meaningful: this \
intrusion's own related activities are separated by anything from two seconds \
to an hour and a half.
""",
    egress_categories=(
        "observation ids and their asserted normalised values",
        "record ids, source types and recorded timestamps",
        "relation names and their endpoint observation ids",
        "previously accepted finding statements and ids",
    ),
)

HYPOTHESISE = Site(
    name="hypothesise",
    stage="3 correlate",
    purpose=(
        "Predict what record should exist if the findings so far are right, committed "
        "before looking for it. A prediction written after the search is a description; "
        "written before, it is a test that can fail."
    ),
    model_type=schemas.Hypothesis,
    system=COMMON_SYSTEM
    + """
Given the findings so far, predict one record that should exist if they are \
right, and commit to it before it is looked for.

Be specific enough to be wrong: name the entity, the role it should hold, the \
kind of event, which source should carry it, and the window it should fall in. \
A prediction vague enough to always match tests nothing.

Naming the source matters most. It is what lets the search distinguish "the \
record is absent" from "no source covers this", and those are different \
findings.
""",
    egress_categories=(
        "accepted finding statements, stages and ids",
        "entity names as they appear in observations",
        "source type coverage per entity",
    ),
)

SELECT_TECHNIQUE = Site(
    name="select_technique",
    stage="4 enrich",
    purpose=(
        "Choose one ATT&CK technique for an accepted finding, from a retrieved enum of "
        "candidates, quoting the field values that triggered the choice."
    ),
    model_type=schemas.TechniqueSelection,
    system=COMMON_SYSTEM
    + """
Choose the single ATT&CK technique that best fits the finding, from the \
candidates supplied. You cannot name a technique outside that set -- the \
response contract does not admit one.

Quote the field values that drove the choice, exactly as they appear in an \
observation you cite. Those quotes are checked against the cited record, so an \
approximate quote fails.

If no candidate genuinely fits, say so in `quoted_values` by selecting the \
closest and explaining -- but a poor fit recorded honestly is better than a \
confident wrong mapping, and the caller can record the finding as unmappable. \
That is a legitimate outcome, distinct from a rejection.
""",
    egress_categories=(
        "one accepted finding statement and its stage",
        "the observations it cites, with their fields and values",
        "candidate ATT&CK technique ids, names and descriptions from the local catalogue",
    ),
)

ANSWER = Site(
    name="answer",
    stage="6 answer",
    purpose=(
        "Answer an analyst's question over the frozen artifacts, citing existing nodes. "
        "No tool at this stage can create a node, which is what makes the step "
        "structurally incapable of inventing a finding."
    ),
    model_type=schemas.Answer,
    system=COMMON_SYSTEM
    + """
Answer the question from the investigation graph you are given. You are reading a closed record: you cannot add to it, and every claim you make must cite nodes that already exist in it.

HOW TO WRITE IT. You are talking to a CISO or a SOC analyst, in a chat window, under time pressure. Write the way a good colleague would answer out loud.

* `body` is the answer, in plain English. Short paragraphs. No headings, no bullet lists unless the question genuinely asks for a list, no preamble like "Based on the investigation graph" -- just answer.
* **Reference evidence inline as event ids in square brackets**, like `[EVT-0900]` or `[EVT-0901, EVT-0902]`, placed right after the thing they support. Those are short, meaningful, and an analyst can look them up. Never put `fnd_`, `obs_`, `rec_` or `edg_` ids in the body -- they are internal and unreadable.
* Say what is uncertain in the same breath as the thing it qualifies, not in a separate section. "The archive left via cloud storage [EVT-0903], though no firewall record corroborates the transfer path" is one sentence a reader can act on.
* Length follows the question. A yes/no question gets two sentences. "Walk me through the timeline" gets as long as it needs. Small talk gets one line and **no claims at all**.
* Never use a technique id without its name: `T1566.001 (Spearphishing Attachment)`.

`claims` is the machine-checkable record behind the prose, not a second copy of it for the reader. One entry per assertion the body makes, each citing the nodes that support it. Keep the text short -- it is the audit trail, and the reader is reading `body`.

A claim that attributes activity to the intrusion must cite at least one finding. Citing observations alone supports a fact -- that a value appeared in a record -- not an attribution, and the difference is checked.

A **limitation is not a claim.** "No source covers X" belongs in `gaps`, which needs no citation. Putting it in `claims` makes it an assertion with no evidence and the citation gate will withhold the whole answer for it.
""",
    egress_categories=(
        "the analyst's question",
        "accepted finding statements, stages and ids",
        "observation ids, fields and asserted values",
        "technique mappings and the local catalogue version",
        "computed coverage gaps",
    ),
)

#: Design SS7 puts the model in exactly three *places*; INTERPRET and HYPOTHESISE
#: are two contracts at one of them (stage 3), which is why this tuple has four
#: entries across three stages.
SITES: tuple[Site, ...] = (INTERPRET, HYPOTHESISE, SELECT_TECHNIQUE, ANSWER)

SITES_BY_NAME: dict[str, Site] = {site.name: site for site in SITES}

#: The stages a model appears in. Exactly three, and a test asserts it.
MODEL_STAGES: tuple[str, ...] = tuple(dict.fromkeys(site.stage for site in SITES))

#: What `render_payload` joins blocks with. Named rather than inlined because
#: the egress check reassembles a payload from its labelled blocks to compare
#: against what was captured, and the two have to agree by construction rather
#: than by both happening to say "newline".
BLOCK_SEPARATOR = "\n"


class UndeclaredEgress(ValueError):
    """A payload block claimed a category the site does not declare.

    Raised rather than logged. NFR-04 says the system sends nothing beyond what
    it documents, and the only way to keep that true as the prompt builders
    arrive is for undocumented material to be unable to reach a prompt at all.
    """


@dataclass(frozen=True)
class PayloadBlock:
    """One labelled piece of a user payload: what it is, and its text.

    The label is the load-bearing half. NFR-04's second half -- that the
    inventory is *true* -- is only checkable if each piece of a prompt says
    which documented category it instantiates, so the check is a lookup rather
    than someone reading a prompt and judging.
    """

    category: str
    text: str


def render_payload(site: Site, blocks: Sequence[PayloadBlock]) -> str:
    """Assemble a user payload from labelled blocks, refusing an undeclared one.

    **Every prompt builder goes through here** -- the stage-3 loop, the stage-4
    mapper, the stage-6 answerer. That is what extends the egress check from the
    committed fixture to the real prompts: a builder that wants to send
    something new has to declare a category, which fails here until
    `docs/egress.md` names it and the site declares it.

    The alternative -- f-strings at three call sites and a document describing
    them -- is exactly the arrangement where the document drifts and nothing
    notices.
    """
    if not blocks:
        raise ValueError(f"{site.name}: an empty payload asks the model to reason over nothing")
    for block in blocks:
        if block.category not in site.egress_categories:
            raise UndeclaredEgress(
                f"{site.name}: category {block.category!r} is not declared for this site; "
                f"document it in docs/egress.md and add it to the site's egress_categories. "
                f"Declared: {list(site.egress_categories)}"
            )
    return BLOCK_SEPARATOR.join(block.text for block in blocks)



def contract_set() -> dict[str, Any]:
    """The whole contract set as a plain structure, ready to hash or commit.

    Prompts *and* emitted schemas. Hashing only the prompts would miss a
    widened contract; hashing only the schemas would miss a reworded
    instruction. Either changes what the untrusted step does, so both are in.
    """
    return {
        "validator_version": VALIDATOR_VERSION,
        "model_id": client.MODEL_ID,
        "provider_api_version": client.PROVIDER_API_VERSION,
        "thinking": dict(client.THINKING),
        "sites": {
            site.name: {
                "stage": site.stage,
                "purpose": site.purpose,
                "system": site.system,
                "schema": site.wire_schema(),
                "egress_categories": list(site.egress_categories),
            }
            for site in SITES
        },
    }


def contract_set_hash() -> str:
    """SS11.1's contract-set hash.

    Uses `ids.canonical_json` so it is computed exactly the way every other
    digest in the system is -- sorted keys, no whitespace, no reliance on dict
    ordering -- and is therefore stable across processes and hash seeds.
    """
    from .. import ids

    return ids.content_digest(contract_set())


#: Computed once at import. A module-level constant rather than a call, because
#: it is stamped onto artifacts in many places and must be one value per process.
CONTRACT_SET_HASH: str = contract_set_hash()


def stamp() -> dict[str, str]:
    """What every emitted artifact carries so its verdicts can be replayed."""
    from .. import __version__

    return {
        "contract_set_hash": CONTRACT_SET_HASH,
        "validator_version": VALIDATOR_VERSION,
        "software_version": __version__,
    }
