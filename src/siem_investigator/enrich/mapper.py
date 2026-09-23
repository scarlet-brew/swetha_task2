"""Stage 4 ENRICH -- retrieve an enum, select from it, validate what constraint cannot (T23).

Runs over **accepted findings**, not inside the correlation loop, which is the
ordering the brief itself gives.

Retrieval is deterministic over the local catalogue; selection is a model choice
from a closed enum, so a hallucinated technique id is *structurally
unrepresentable* rather than merely detectable. What constraint cannot cover is
then validated: id/name consistency (the documented failure is a right name on a
wrong id, which an existence check passes), that quoted values appear in a cited
observation, and that the technique's tactics are consistent with the finding's
stage.

`non_mappable` is a first-class outcome, distinct from rejected: *we looked, and
there is legitimately nothing here.*
"""

from __future__ import annotations

import re
from typing import Any

from .. import ids
from ..agent import contracts, schemas
from .catalogue import Catalogue

#: How many candidates to retrieve per finding. Small enough that the enum is a
#: real constraint, large enough to contain the right answer.
CANDIDATES = 12

_WORD = re.compile(r"[a-z0-9.]+")


def _terms(text: str) -> set[str]:
    return {word for word in _WORD.findall(text.lower()) if len(word) > 2}


def retrieve(finding: dict, observations: list[dict], catalogue: Catalogue) -> list[dict]:
    """Candidate techniques, scored over names and descriptions.

    Deterministic, local, and restricted to the selectable set -- 697 of the 858,
    excluding the 149 revoked and 12 deprecated, because mapping a finding to a
    revoked technique would be a defect.
    """
    haystack = _terms(finding["statement"]) | _terms(finding.get("rationale", ""))
    for observation in observations:
        haystack |= _terms(str(observation.get("normalised_value", "")))
        haystack |= _terms(str(observation.get("field", "")))

    stage = finding["stage"]
    scored = []
    for technique_id in catalogue.selectable_ids():
        technique = catalogue.techniques[technique_id]
        name_terms = _terms(technique.name)
        description_terms = _terms(technique.description[:600])
        score = 3.0 * len(haystack & name_terms) + 0.5 * len(haystack & description_terms)
        if stage in technique.tactics:
            score += 2.0
        if score > 0:
            scored.append((score, technique))

    scored.sort(key=lambda pair: (-pair[0], pair[1].technique_id))
    return [
        {
            "technique_id": technique.technique_id,
            "name": technique.name,
            "tactics": list(technique.tactics),
            "description": technique.description[:400],
        }
        for _score, technique in scored[:CANDIDATES]
    ]


def validation_failures(
    selection: dict, finding: dict, observations: list[dict], catalogue: Catalogue
) -> list[str]:
    """What the closed enum could not guarantee."""
    problems: list[str] = []
    technique = catalogue.technique(selection["technique_id"])
    if technique is None:
        return [f"{selection['technique_id']} is not in the catalogue"]

    # The documented model failure: a plausible name paired with the wrong id.
    if not catalogue.name_matches_id(technique.technique_id, selection["technique_name"]):
        problems.append(
            f"id/name mismatch: {technique.technique_id} is {technique.name!r}, not "
            f"{selection['technique_name']!r}"
        )

    values = set()
    for observation in observations:
        values.add(str(observation["normalised_value"]).lower())
        values.add(str(observation["raw_value"]).lower())
    for quoted in selection["quoted_values"]:
        needle = quoted.lower()
        if not any(needle in value or value in needle for value in values):
            problems.append(f"quoted value {quoted!r} appears in no cited observation")

    if finding["stage"] not in technique.tactics:
        problems.append(
            f"tactic inconsistency: {technique.technique_id} has tactics {list(technique.tactics)}, "
            f"and the finding is at stage {finding['stage']!r}"
        )

    return problems


def map_findings(
    findings: list[dict], observations: list[dict], catalogue: Catalogue, *, client_module=None
) -> tuple[list[dict], list[dict]]:
    """`(mappings, unmapped)`."""
    by_id = {observation["id"]: observation for observation in observations}
    mappings: list[dict] = []
    unmapped: list[dict] = []

    for finding in findings:
        cited = [by_id[obs] for obs in finding["cites_observations"] if obs in by_id]
        candidates = retrieve(finding, cited, catalogue)

        if not candidates:
            unmapped.append(
                {
                    "id": ids.node_id("map", {"finding": finding["id"], "outcome": "no_candidates"}),
                    "finding": finding["id"],
                    "outcome": "non_mappable",
                    "reason": "retrieval returned no candidate technique for this finding",
                }
            )
            continue

        if client_module is None or not client_module.credential_present():
            unmapped.append(
                {
                    "id": ids.node_id("map", {"finding": finding["id"], "outcome": "no_credential"}),
                    "finding": finding["id"],
                    "outcome": "unmapped",
                    "reason": (
                        "no credential, so technique attribution is reported as unmapped rather "
                        "than omitted (NFR-02)"
                    ),
                    "candidates_retrieved": [c["technique_id"] for c in candidates],
                }
            )
            continue

        model_type = schemas.technique_selection_model(
            tuple(candidate["technique_id"] for candidate in candidates)
        )
        user = _render(finding, cited, candidates)
        try:
            result = client_module.call(
                site=contracts.SELECT_TECHNIQUE.name,
                model_type=model_type,
                system=contracts.SELECT_TECHNIQUE.system,
                user=user,
                max_tokens=1500,
            )
        except Exception as exc:
            unmapped.append(
                {
                    "id": ids.node_id("map", {"finding": finding["id"], "outcome": "call_failed"}),
                    "finding": finding["id"],
                    "outcome": "unmapped",
                    "reason": f"{type(exc).__name__}: {exc}",
                }
            )
            continue

        selection = {
            "technique_id": result.parsed.technique_id,
            "technique_name": result.parsed.technique_name,
            "quoted_values": list(result.parsed.quoted_values),
            "cited_observations": [
                obs for obs in result.parsed.cited_observations if obs in by_id
            ] or finding["cites_observations"],
        }
        problems = validation_failures(selection, finding, cited, catalogue)
        technique = catalogue.technique(selection["technique_id"])

        if problems:
            unmapped.append(
                {
                    "id": ids.node_id(
                        "map", {"finding": finding["id"], "rejected": selection["technique_id"]}
                    ),
                    "finding": finding["id"],
                    "outcome": "rejected",
                    "technique_id": selection["technique_id"],
                    "reason": "; ".join(problems),
                    "candidates_retrieved": [c["technique_id"] for c in candidates],
                }
            )
            continue

        mappings.append(
            {
                "id": ids.mapping_id(
                    technique_id=selection["technique_id"],
                    finding=finding["id"],
                    cited_observations=selection["cited_observations"],
                    quoted_values=selection["quoted_values"],
                ),
                "layer": "mapping",
                "finding": finding["id"],
                "technique_id": technique.technique_id,
                "technique_ref": technique.technique_ref,
                "technique_name": technique.name,
                "tactics": list(technique.tactics),
                "quoted_values": sorted(set(selection["quoted_values"])),
                "cites_observations": sorted(set(selection["cited_observations"])),
                # Provenance, not identity: "this is T1059.001" is unchanged by
                # a catalogue bump.
                "catalogue_version": catalogue.attack_version,
            }
        )

    return mappings, unmapped


def _render(finding: dict, observations: list[dict], candidates: list[dict]) -> str:
    lines = [
        "FINDING",
        f"  [{finding['stage']}] {finding['statement']}",
        "",
        "OBSERVATIONS IT CITES",
    ]
    for observation in observations:
        lines.append(
            f"  {observation['id']}  {observation['event_id']}  {observation['source_type']}  "
            f"{observation['field']} = {observation['normalised_value']!r}"
        )
    lines.append("")
    lines.append("CANDIDATE TECHNIQUES -- choose exactly one")
    for candidate in candidates:
        lines.append(
            f"  {candidate['technique_id']}  {candidate['name']}  tactics={candidate['tactics']}"
        )
        lines.append(f"      {candidate['description'][:200]}")
    return "\n".join(lines)
