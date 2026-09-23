"""The contracts for the three model sites (T06).

Every model here is **strict**: `extra="forbid"` becomes
`additionalProperties: false` at every object level, and every closed field is a
`Literal` so a value outside it is unrepresentable rather than merely
detectable. That ordering is D-08's whole posture -- constrain, then validate --
and `wire.wire_schema` is what makes it survive to the wire, because the SDK's
own transform drops `enum` (see `wire._restore_closed_values`).

**No field anywhere carries a probability, a percentage or a confidence value.**
R3.4 forbids them, and the way that requirement normally rots is someone adding
a harmless-looking `confidence: float` two months later. There is no field to
put one in, `wire.schema_defects` scans the emitted schema for the shape of one,
and a test runs that scan over `ALL_CONTRACT_MODELS` -- the nested models
included, since those reach the wire too and are the easier ones to miss.

Two things are deliberately *not* in these models:

* **Node ids for the thing being created.** A finding's id is a hash of its
  structural identity (SS8.2), computed by `ids.finding_id` after the model
  returns. Letting the model propose an id would let it propose two different
  findings with one id, or collide with an existing node.
* **Support labels.** Corroborated / Single-sourced / Absence-based /
  Conflicted are *computed* at close from the count of distinct source types
  across a finding's supporting observations (T25). A model-asserted support
  label would be an opinion wearing the clothes of a measurement.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

#: The ten atomic factual relations of design SS3.2. Ten relation *types*, zero
#: detection rules: the deterministic layer links everything linkable, benign
#: included, and decides nothing. A composite like `staged_then_uploaded` is
#: absent on purpose -- it would both compute a link and call it exfiltration,
#: which is the interpretation leak that killed design draft 3.
RelationName = Literal[
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
]

#: The closed intrusion-stage vocabulary (SS3.4 check 4).
#:
#: These are ATT&CK v19.2's own tactic shortnames, not a parallel vocabulary.
#: Two reasons. The stage/tactic consistency check at stage 4 becomes identity
#: rather than a mapping table that can drift out of date; and the vocabulary is
#: then versioned by the committed catalogue instead of by this file's opinion.
#: `tests/test_agent_contracts.py` asserts this tuple equals the tactic
#: shortnames in `data/attack/catalogue_v19.2.json`, so a catalogue bump that
#: renames a tactic fails here rather than silently narrowing the vocabulary.
#:
#: Note `stealth` rather than `defense-evasion`: v19.2 renamed TA0005.
IntrusionStage = Literal[
    "collection",
    "command-and-control",
    "credential-access",
    "defense-impairment",
    "discovery",
    "execution",
    "exfiltration",
    "impact",
    "initial-access",
    "lateral-movement",
    "persistence",
    "privilege-escalation",
    "reconnaissance",
    "resource-development",
    "stealth",
]

#: What a SEEK returns. `not_covered` is the one that makes `not_found`
#: meaningful: without it, "not found" conflates absence from the environment
#: with blindness of the source.
SeekOutcome = Literal["found", "not_found", "not_covered"]

#: Roles a parsed entity reference can hold (SS2). Kept here because a
#: hypothesis predicts one.
EntityRole = Literal["actor", "observed_on", "origin", "target"]

_STRICT = ConfigDict(extra="forbid")


class CitedEdge(BaseModel):
    """One factual edge a finding rests on.

    An **object**, not a tuple. A 2-tuple would emit `prefixItems`, which is
    poorly supported and would make the ordering positional and easy to
    silently reverse. Naming the endpoints makes direction explicit, which
    matters because several relations are directional -- `process_parent` names
    parent then child, `temporal_within` earlier then later -- and reversing
    them states something different.

    No parameters field. A reported delta-t is derivable from the endpoints, so
    including it would add nothing and churn the edge id if the time base
    shifted (SS8.2).
    """

    model_config = _STRICT

    relation: RelationName = Field(description="Which of the ten atomic factual relations holds.")
    from_observation: str = Field(
        description="Observation id of the first endpoint, in the relation's own order."
    )
    to_observation: str = Field(
        description="Observation id of the second endpoint, in the relation's own order."
    )


class CandidateFinding(BaseModel):
    """A proposed interpretation, for the validator to accept or reject.

    `statement` and `rationale` are prose and are excluded from the finding's
    identity (SS8.2), so rewording either cannot change which finding this is.
    They are still sent and still stored -- they are what a reader reads -- but
    they are not what the node *is*.
    """

    model_config = _STRICT

    statement: str = Field(
        description=(
            "The interpretation, in one or two sentences. Name only entities, values, "
            "identifiers and timestamps that appear in a cited observation: validation "
            "check 3 rejects the proposal otherwise, and names the invented identifier."
        )
    )
    stage: IntrusionStage = Field(description="Which intrusion stage this finding belongs to.")
    cites_observations: list[str] = Field(
        min_length=1,
        description=(
            "Observation ids this finding rests on. At least one: a finding citing "
            "nothing is ungrounded and could not terminate in a raw record."
        ),
    )
    cites_edges: list[CitedEdge] = Field(
        default_factory=list,
        description=(
            "Factual edges this finding rests on. May be empty -- a finding can rest on "
            "observations alone. Each edge is re-evaluated from its relation function "
            "during validation, never looked up in a stored list."
        ),
    )
    rationale: str = Field(
        description="Why these observations and edges support this statement."
    )


class Hypothesis(BaseModel):
    """What should exist if the findings so far are right -- committed *before* looking.

    The order matters more than the shape. A prediction written after the search
    is a description of what was found; written before, it is a test that can
    fail. The three failure modes are then distinguishable: confirmed,
    unconfirmed, and uncoverable because no source could have seen it.

    `status` is absent by design. It changes as the search resolves, and SS8.2
    excludes it from hypothesis identity precisely so the ledger stays joinable
    to itself -- which is what the coverage-gap report reads.
    """

    model_config = _STRICT

    premises: list[str] = Field(
        min_length=1, description="Finding ids this hypothesis is premised on."
    )
    predicted_entity: str = Field(
        description="The entity that should appear -- an account, host, address, process or file."
    )
    predicted_role: EntityRole = Field(
        description="The role that entity should hold in the predicted record."
    )
    predicted_event_kind: str = Field(
        description="The source_type/event_name kind the record should be, e.g. endpoint/process_create."
    )
    predicted_source_type: str = Field(
        description="Which log source should carry it. Used to tell absence from blindness."
    )
    window_start: str = Field(description="Earliest instant the record could hold, ISO-8601 UTC.")
    window_end: str = Field(description="Latest instant the record could hold, ISO-8601 UTC.")
    rationale: str = Field(description="Why the premises imply this record should exist.")


class TechniqueSelection(BaseModel):
    """A technique chosen from a retrieved enum, with the values that triggered it.

    The base class leaves `technique_id` an open string **and is not what stage
    4 sends**. Use `technique_selection_model(candidate_ids)`, which closes the
    field to the ids actually retrieved for that finding. That is the
    constrain-don't-validate move: a hallucinated technique becomes
    unrepresentable in the request body rather than something caught on return.
    MITRE's own TRAM needs no catalogue check at prediction time for the same
    reason -- a closed-label classifier cannot emit a label outside its set.
    """

    model_config = _STRICT

    technique_id: str = Field(description="ATT&CK technique id, from the supplied candidates only.")
    technique_name: str = Field(
        description=(
            "The official ATT&CK name for that id. Checked against the catalogue: the "
            "documented failure mode is a plausible name paired with the wrong id, which "
            "checking the id alone passes."
        )
    )
    quoted_values: list[str] = Field(
        min_length=1,
        description=(
            "The field values that triggered this choice, quoted exactly as they appear "
            "in a cited observation."
        ),
    )
    cited_observations: list[str] = Field(
        min_length=1, description="Observation ids carrying those values."
    )


class AnswerClaim(BaseModel):
    """One claim inside an answer, with the nodes it cites.

    `cites_findings` is the loophole-closing field. An answer that *attributes*
    activity to the intrusion must cite at least one finding node;
    observation-only citations support facts, not attributions. Without that,
    stage 6 could assemble an attribution out of raw observations and mint a
    conclusion the validator never saw.

    **`applies_because` is deliberately not called `basis`.** The payload
    contract in `docs/specs/answer_payload.md` renders `basis` as an object of
    `name` / `requires` / `applies_because`, and `app/components/citation.py`
    reads it with `.get`. Only the third of those is the model's to supply: the
    basis *name* and what it *requires* come from the deterministic basis
    registry, so a model-supplied `basis` would be an invented one. Giving the
    field the payload's own name would invite stage 6 to copy it straight
    through, putting a string where the renderer calls `.get` -- a crash, and
    before that a fabricated basis.
    """

    model_config = _STRICT

    text: str = Field(description="The claim, in one sentence.")
    kind: Literal["observation", "attribution", "absence", "recommendation"] = Field(
        description=(
            "What kind of claim this is. `attribution` requires at least one finding "
            "citation; `absence` requires a named basis."
        )
    )
    cites_findings: list[str] = Field(
        default_factory=list, description="Finding ids. Required for an `attribution` claim."
    )
    cites_observations: list[str] = Field(
        default_factory=list, description="Observation ids supporting a factual claim."
    )
    cites_mappings: list[str] = Field(
        default_factory=list, description="Technique mapping ids, where the claim names a technique."
    )
    applies_because: str | None = Field(
        default=None,
        description=(
            "For an `absence` claim, why the basis applies to this question. Absence "
            "claims are computed after the graph closes, never during the loop."
        ),
    )


class Answer(BaseModel):
    """The stage-6 response. Rendered by `app/components/citation.py`.

    Deliberately not a node in the committed graph (SS8.2): answer claims live in
    the per-question answer record with citations pointing *into* the graph,
    otherwise the graph would vary with whatever anyone happened to ask.
    """

    model_config = _STRICT

    body: str = Field(description="The answer prose. States no claim that is not also in `claims`.")
    claims: list[AnswerClaim] = Field(
        min_length=1, description="Every claim the body makes, each with its citations."
    )
    gaps: list[str] = Field(
        default_factory=list,
        description=(
            "What the available sources cannot settle about this question. Reported "
            "without being asked (R3.6)."
        ),
    )


#: Every model in the contract set, in the order `docs/egress.md` lists the
#: sites. `contracts.CONTRACT_SET_HASH` is computed over these plus the prompts.
CONTRACT_MODELS: tuple[type[BaseModel], ...] = (
    CandidateFinding,
    Hypothesis,
    TechniqueSelection,
    Answer,
)

#: Every strict model defined here, the nested ones included. `CONTRACT_MODELS`
#: is what the four sites send; this is what R3.4's scan has to cover, because a
#: belief field added to a *nested* model reaches the wire just as surely and is
#: the easier one to miss on review.
ALL_CONTRACT_MODELS: tuple[type[BaseModel], ...] = (
    CitedEdge,
    CandidateFinding,
    Hypothesis,
    TechniqueSelection,
    AnswerClaim,
    Answer,
)


def technique_selection_model(candidate_ids: tuple[str, ...]) -> type[TechniqueSelection]:
    """A `TechniqueSelection` whose `technique_id` is closed to `candidate_ids`.

    Built per finding, because the retrieved candidate set is per finding. The
    model is constructed with `Literal[*candidate_ids]`, so the emitted schema
    carries an `enum` of exactly those ids and nothing else can be sent back.

    Raises on an empty candidate set rather than falling back to an open string:
    "we retrieved nothing" is a `non_mappable` outcome for the caller to record,
    not a licence to let the model pick freely.
    """
    if not candidate_ids:
        raise ValueError(
            "no candidate techniques retrieved; record non_mappable rather than "
            "sending an unconstrained field"
        )
    unique = tuple(dict.fromkeys(candidate_ids))

    class ConstrainedTechniqueSelection(TechniqueSelection):
        model_config = _STRICT

        technique_id: Literal[unique] = Field(  # type: ignore[valid-type]
            description="ATT&CK technique id. Exactly one of the retrieved candidates."
        )

    ConstrainedTechniqueSelection.__name__ = "TechniqueSelection"
    ConstrainedTechniqueSelection.__qualname__ = "TechniqueSelection"
    # Pydantic uses __doc__ as the schema's object `description`, and this
    # module's commentary has no business being sent to the provider.
    ConstrainedTechniqueSelection.__doc__ = None
    return ConstrainedTechniqueSelection
