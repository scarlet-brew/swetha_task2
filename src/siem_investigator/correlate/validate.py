"""The deterministic gate -- six checks the interpretive layer cannot bypass (T18).

This is the trusted kernel in the de Bruijn / LCF sense: the generator is
untrusted and supplies completeness, the verifier is small and supplies
soundness. Every rejection carries a **specific diagnostic**, not a boolean --
which is what makes the rejection log a coverage backlog rather than noise, and
what the bounded back-prompt feeds on.

The six checks:

1. Every cited observation exists.
2. **Every cited edge re-evaluates to true** -- recomputed from its relation
   function, never looked up in a stored list.
3. **Invented-identifier check** -- every identifier named in the statement
   appears in a cited observation. Cheap, total, and it catches the commonest
   fabrication mode.
3b. **Basis role fulfilment** -- the cited edges actually connect the cited
   observations, so a finding cannot cite five true edges about unrelated things.
4. Stage is from the closed vocabulary.
5. Layer discipline, acyclicity, termination in records.
6. **At close only** -- no two accepted findings mutually incompatible.

Check 6 is deferred deliberately: acyclicity and mutual compatibility are
**set-level** properties, so two findings can each be individually valid and
jointly inconsistent. It lives in `evidence/close.py`.

**What none of this checks: whether the interpretation is apt.** A finding can
cite real observations and real edges, name only real identifiers, and still
conclude wrongly. That is the test oracle problem, it is irreducible here, and
it is stated rather than papered over.
"""

from __future__ import annotations

import re
import typing
from dataclasses import dataclass, field
from typing import Any

from ..agent import schemas

STAGES = frozenset(typing.get_args(schemas.IntrusionStage))

#: Tokens in a statement that look like an identifier a reader could check:
#: event ids, hostnames, account names, filenames, addresses, process names.
#: Deliberately generous about what counts as a candidate -- a false candidate
#: costs one lookup, a missed one lets a fabrication through.
_IDENTIFIER = re.compile(
    r"""
    (?:EVT-\d{3,})                                  # event ids
  | (?:\b\d{1,3}(?:\.\d{1,3}){3}\b)                 # IPv4
  | (?:\b[A-Za-z0-9_-]+\.(?:exe|dll|zip|ps1|bat|dmp|7z|log|dit|tmp)\b)  # filenames
  | (?:\bpid\s+\d+\b)                              # pid 5104
  | (?:\b\d{1,3}(?:,\d{3})+\b)                      # 2,473,829,122
  | (?:\b\d{7,}\b)                                  # 2473829122
    """,
    re.VERBOSE | re.IGNORECASE,
)

#: Entity kinds checked by **lookup against the graph** rather than by pattern.
#:
#: `wkstn-07` and `hidden-window` are the same shape once lowercased, so no
#: regex can tell a hostname from an English compound. Matching on shape
#: rejected `document-borne`, `hidden-window` and `one-off` as invented
#: hostnames -- 58 of 60 rejections in one build, including the initial-access
#: finding, which cost 50 points of recall.
#:
#: Lookup is also the stronger check. A name the graph has never seen is prose;
#: a name the graph *does* know, appearing in a statement that never cited it,
#: is exactly the misattribution worth catching -- "jclark exfiltrated the
#: archive" when the record says jdavis.
LOOKED_UP_ENTITIES = ("account", "host", "process", "file", "bucket", "service")

#: R3.4 -- no probability, percentage or adjective of belief in a conclusion.
_BELIEF = re.compile(
    r"\b(probably|likely|almost certainly|certainly|possibly|perhaps|maybe|"
    r"confident|confidence|probability|\d{1,3}\s?%)\b",
    re.IGNORECASE,
)


@dataclass
class Verdict:
    """Accept or reject, with every failure named."""

    accepted: bool
    diagnostics: list[str] = field(default_factory=list)
    checks: dict[str, bool] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"accepted": self.accepted, "diagnostics": self.diagnostics, "checks": self.checks}


def candidate_identifiers(statement: str) -> set[str]:
    """Tokens in a statement a reader could go and check.

    Widened after an audit found the original pattern caught almost nothing: it
    matched hostnames only in upper case, while the pipeline lowercases every
    hostname, so `wkstn-07` and `file-srv-02` were never checked at all.
    Account names, pids and byte counts were never checked either. On
    "on wkstn-07 under user jdavis, pid 5104 dumped lsass.exe" it found exactly
    two tokens, and neither was the host or the account.

    Accounts are handled by the caller rather than by a pattern: a bare
    lowercase word is indistinguishable from prose, so the check tests whether
    every account *known to the graph* that appears in the statement is also in
    a cited observation.
    """
    # No blocklist any more: every pattern above has unambiguous syntax, so
    # there is nothing to exempt. The blocklist existed only to hold back the
    # hyphenated-word pattern that has been removed.
    return {match.group(0) for match in _IDENTIFIER.finditer(statement)}


def validate(
    proposal: dict,
    *,
    index,
    known_findings: frozenset[str] = frozenset(),
) -> Verdict:
    """Checks 1-5 over one candidate finding.

    `index` is a `relations.RelationIndex`; edges are re-evaluated through it.
    """
    diagnostics: list[str] = []
    checks: dict[str, bool] = {}

    cited_observations = list(proposal.get("cites_observations") or [])
    cited_edges = list(proposal.get("cites_edges") or [])

    # ---- check 1: cited observations exist --------------------------------
    missing = [obs for obs in cited_observations if obs not in index.by_id]
    checks["1_observations_exist"] = not missing and bool(cited_observations)
    if not cited_observations:
        diagnostics.append("check 1: the proposal cites no observations, so it is ungrounded")
    for obs in missing:
        diagnostics.append(f"check 1: cited observation {obs} does not exist")

    subjects = set(proposal.get("subject_event_ids") or [])
    cited_events = {index.by_id[o]["event_id"] for o in cited_observations if o in index.by_id}
    checks["subject_events_are_cited"] = subjects <= cited_events
    if not checks["subject_events_are_cited"]:
        diagnostics.append("subject events must be demonstrated by cited observations")

    # ---- check 2: every cited edge re-evaluates to true -------------------
    edge_ok = True
    for edge in cited_edges:
        relation = edge.get("relation")
        left, right = edge.get("from_observation"), edge.get("to_observation")
        holds, params = index.evaluate(relation, left, right)
        if not holds:
            edge_ok = False
            reason = params.get("error", "the relation does not hold between these observations")
            diagnostics.append(f"check 2: {relation}({left}, {right}) re-evaluates false -- {reason}")
    checks["2_edges_reevaluate"] = edge_ok

    # ---- check 3: no invented identifier ----------------------------------
    statement = str(proposal.get("statement", ""))

    # Grounding is every value on every **cited record**, not only the values of
    # the cited observations.
    #
    # This distinction cost a whole build. Grounded in the observations alone, a
    # finding citing the process fields of an endpoint record and then writing
    # "under user jdavis" was rejected for inventing `jdavis` -- whose username
    # sits on that same record, uncited. 68 of 91 proposals were refused and
    # recall went to zero.
    #
    # A record is the atomic unit of evidence. Citing one of its fields does not
    # make the others invented. The check still bites: an identifier from a
    # record the finding never cited is still refused, which is the fabrication
    # it exists to catch.
    grounded_values: set[str] = set()
    cited_records: set[str] = set()
    for obs in cited_observations:
        observation = index.by_id.get(obs)
        if observation is None:
            continue
        cited_records.add(observation["record"])
        grounded_values.add(observation["event_id"])
    for record_id in cited_records:
        for sibling in index.by_record.get(record_id, []):
            grounded_values.add(str(sibling["normalised_value"]))
            grounded_values.add(str(sibling["raw_value"]))
            grounded_values.add(sibling["event_id"])
    lowered = {value.lower() for value in grounded_values}

    invented = []

    # Entity names by lookup rather than by shape. Every account, host, process,
    # file, bucket and service the *graph* knows is looked for in the statement;
    # one that appears without being on a cited record is an invented
    # attribution. A word the graph has never seen is prose.
    known = {
        str(observation["normalised_value"]).lower()
        for observation in index.observations
        if observation.get("entity_type") in LOOKED_UP_ENTITIES
        and len(str(observation["normalised_value"])) > 2
    }
    cited_entities = {
        str(sibling["normalised_value"]).lower()
        for record_id in cited_records
        for sibling in index.by_record.get(record_id, [])
        if sibling.get("entity_type") in LOOKED_UP_ENTITIES
    }
    # `.rstrip(".")` matters: the character class admits dots so that
    # `winword.exe` matches as one token, which means a name at the end of a
    # sentence arrives as `file-srv-02.` and misses the lookup. Trailing dots go;
    # interior ones stay.
    tokens = {
        token.rstrip(".")
        for token in re.findall(r"[a-z][a-z0-9_.\-]{2,}", statement.lower())
    }
    for name in sorted((known & tokens) - cited_entities):
        # A known name found *inside* a cited value is on the record --
        # `powershell.exe` inside a cited command line. Equality alone refused
        # the initial-access finding twice for naming the shell its own cited
        # command line launches; the identifier check below already grounds
        # by containment, and this one now agrees with it.
        if any(name in value for value in lowered):
            continue
        invented.append(name)

    for token in candidate_identifiers(statement):
        needle = token.lower()
        # `pid 5104` is matched as a phrase so the digits are not mistaken for a
        # byte count, but grounding holds the bare value `5104`. Without this
        # every statement naming a process id was rejected for inventing it --
        # which took out the LSASS credential-access finding on step 1 of a run.
        if needle.startswith("pid "):
            needle = needle.split(None, 1)[1]
        # Thousands separators are presentation: 2,473,829,122 is grounded as
        # 2473829122.
        stripped = needle.replace(",", "")
        if needle in lowered or stripped in lowered:
            continue
        # A token appearing inside any cited value also counts as grounded --
        # a command line legitimately contains a filename.
        if any(needle in value or stripped in value for value in lowered):
            continue
        invented.append(token)
    checks["3_no_invented_identifier"] = not invented
    for token in sorted(invented):
        diagnostics.append(
            f"check 3: {token!r} is named in the statement but appears in no cited observation"
        )

    # ---- check 3b: the cited edges connect the cited observations ---------
    cited_set = set(cited_observations)
    unconnected = [
        edge
        for edge in cited_edges
        if edge.get("from_observation") not in cited_set or edge.get("to_observation") not in cited_set
    ]
    checks["3b_basis_roles_fulfilled"] = not unconnected
    for edge in unconnected:
        diagnostics.append(
            f"check 3b: edge {edge.get('relation')}({edge.get('from_observation')}, "
            f"{edge.get('to_observation')}) has an endpoint the finding does not cite, so it "
            "cannot be part of this finding's basis"
        )

    # ---- check 4: stage from the closed vocabulary ------------------------
    stage = proposal.get("stage")
    checks["4_stage_in_vocabulary"] = stage in STAGES
    if stage not in STAGES:
        diagnostics.append(f"check 4: stage {stage!r} is not in the closed vocabulary")

    # ---- check 5 (per-proposal half): cited findings exist ----------------
    unknown = [f for f in proposal.get("cites_findings") or [] if f not in known_findings]
    checks["5_layer_discipline"] = not unknown
    for finding in unknown:
        diagnostics.append(f"check 5: cited finding {finding} is not in the graph")

    # ---- R3.4: no belief language in the statement ------------------------
    belief = _BELIEF.findall(statement)
    checks["r3_4_no_belief_language"] = not belief
    for token in belief:
        diagnostics.append(
            f"R3.4: the statement uses {token!r}; support is computed from evidence "
            "structure, never asserted as a likelihood"
        )

    return Verdict(accepted=all(checks.values()), diagnostics=diagnostics, checks=checks)
