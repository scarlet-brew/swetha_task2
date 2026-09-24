"""Strict structured model contracts; observations remain the evidence authority."""

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
    "process_pid",
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
from .stages import IntrusionStage


#: The 14 logical event kinds the dataset contains, and its 4 source types.
#:
#: Closed, because an open string here produced the worst failure in the build:
#: 18 of 24 hypotheses predicted kinds like `authentication/logon`, which cannot
#: exist, so the search never matched and every miss was reported as "no source
#: covers this". A false claim of blindness is worse than a missed detection --
#: it tells a reader to stop looking.
#:
#: `tests/test_agent_contracts.py` pins both to the committed census, so a
#: dataset with different kinds fails loudly instead of silently degrading every
#: absence claim.
EventKind = Literal[
    "auth/failed_logon",
    "auth/user_logoff",
    "auth/user_logon",
    "cloud_storage/file_download",
    "cloud_storage/file_share",
    "cloud_storage/file_upload",
    "cloud_storage/file_view",
    "endpoint/file_create",
    "endpoint/file_delete",
    "endpoint/process_access",
    "endpoint/process_create",
    "endpoint/service_create",
    "endpoint/service_delete",
    "network/network_connection",
]

SourceType = Literal["auth", "cloud_storage", "endpoint", "network"]

#: What a SEEK returns. `not_covered` is the one that makes `not_found`
#: meaningful: without it, "not found" conflates absence from the environment
#: with blindness of the source.
SeekOutcome = Literal["found", "not_found", "not_covered"]

#: Roles a parsed entity reference can hold (SS2). Kept here because a
#: hypothesis predicts one.
EntityRole = Literal["actor", "observed_on", "origin", "target"]

_STRICT = ConfigDict(extra="forbid")


class CitedEdge(BaseModel):
    """A factual edge with named, ordered endpoints; parameters are derived."""

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
    subject_event_ids: list[str] = Field(default_factory=list, description="Only event IDs demonstrating the stated action, excluding contextual events. Required for model-backed final findings.")
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


class CandidateAssessment(BaseModel):
    model_config = _STRICT
    disposition: Literal["candidate", "unresolved", "not_linked"]
    reason: str = Field(description="Why this evidence warrants incident investigation, or why it does not. A shared entity alone is insufficient.")
    findings: list[CandidateFinding] = Field(default_factory=list, description="Zero findings is valid. Only candidate disposition may contain findings. Each finding describes one distinct behaviour, not one per record.")


class ReviewedFinding(BaseModel):
    model_config = _STRICT
    statement: str
    stage: IntrusionStage
    subject_event_ids: list[str] = Field(min_length=1, description="Events demonstrating this single incident behaviour.")
    context_event_ids: list[str] = Field(default_factory=list, description="Other source events needed for comparison, sequence or limitations; not additional attack actions.")
    rationale: str


from .case_schema import CaseReview, CaseAction, ActionGroup, EventDisposition


class EventConstraint(BaseModel):
    model_config = _STRICT
    field: Literal["dest_host", "source_host", "hostname", "src_host", "dst_host", "username", "result", "logon_type", "src_ip", "dst_ip", "source_ip", "dest_ip", "dst_port", "protocol", "action", "process_name", "parent_process", "file_path", "file_name", "service_name", "bucket"] = Field(description="Exact source field name. Authentication destination is dest_host; origin is source_host.")
    value: str = Field(description="Required source field value; compared case-insensitively.")


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
    event_constraints: list[EventConstraint] = Field(default_factory=list, description="All required fields on the SAME predicted record. Include destination for actor auth predictions and every condition stated in the rationale.")
    predicted_entity: str = Field(
        description="The entity that should appear -- an account, host, address, process or file."
    )
    predicted_role: EntityRole = Field(
        description="The role that entity should hold in the predicted record."
    )
    predicted_event_kind: EventKind = Field(
        description=(
            "The source_type/event_name kind the record should be. Closed to the kinds "
            "this dataset actually contains, so a prediction cannot fail merely for "
            "naming something that never existed."
        )
    )
    predicted_source_type: SourceType = Field(
        description=(
            "Which log source should carry it, closed for the same reason. This field is "
            "what lets the search tell absence from blindness, so it has to name a real "
            "source."
        )
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
        default_factory=list,
        description=(
            "Every claim the body asserts about the incident, each with its citations. "
            "May be empty: an answer that asserts nothing -- a greeting, or a question "
            "the graph does not speak to -- has nothing to cite, and forcing a claim "
            "would push the model toward inventing one."
        ),
    )
    gaps: list[str] = Field(
        default_factory=list,
        description=(
            "What the available sources cannot settle about this question. This is where "
            "a limitation belongs: it is not a claim, it needs no citation, and it is "
            "reported without being asked (R3.6)."
        ),
    )


#: Every model in the contract set, in the order `docs/egress.md` lists the
#: sites. `contracts.CONTRACT_SET_HASH` is computed over these plus the prompts.
CONTRACT_MODELS: tuple[type[BaseModel], ...] = (
    CandidateFinding,
    CandidateAssessment,
    CaseReview,
    Hypothesis,
    TechniqueSelection,
    Answer,
)

#: Every strict model defined here, the nested ones included. `CONTRACT_MODELS`
#: is what the four sites send; this is what R3.4's scan has to cover, because a
#: belief field added to a *nested* model reaches the wire just as surely and is
#: the easier one to miss on review.
ALL_CONTRACT_MODELS: tuple[type[BaseModel], ...] = (
    EventConstraint, CaseAction, ActionGroup, EventDisposition, ReviewedFinding,
    CitedEdge,
    CandidateFinding,
    CandidateAssessment,
    CaseReview,
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


def technique_decision_model(candidate_ids: tuple[str, ...]) -> type[BaseModel]:
    selection = technique_selection_model(candidate_ids)
    class TechniqueDecision(BaseModel):
        model_config = _STRICT
        selections: list[selection] = Field(default_factory=list, max_length=1, description="Empty when no candidate's defining behaviour is demonstrated. Never choose the closest merely to fill this list.")
        reason: str = Field(description="Explain the defining behaviour or the reason for abstaining.")
    TechniqueDecision.__doc__ = None
    return TechniqueDecision
