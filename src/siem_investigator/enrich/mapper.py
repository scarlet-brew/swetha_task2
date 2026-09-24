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
import math
from collections import Counter
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
    eligible = [catalogue.techniques[t] for t in catalogue.selectable_ids()
                if stage in catalogue.techniques[t].tactics]
    documents = {t.technique_id: _terms(t.description) | _terms(t.name) for t in eligible}
    frequency = Counter(word for terms in documents.values() for word in terms)
    average_length = sum(map(len, documents.values())) / max(1, len(documents))
    scored = []
    for technique in eligible:
        # The validator already requires tactic compatibility. Rank only eligible
        # techniques so incidental file/host words cannot crowd them out.
        if stage not in technique.tactics:
            continue
        name_terms = _terms(technique.name)
        description_terms = _terms(technique.description)
        # IDF and document-length normalization prevent long generic entries
        # winning merely because they contain more common incident words.
        norm = 1 + 1.2 * (0.25 + 0.75 * len(documents[technique.technique_id]) / max(1, average_length))
        score = sum(math.log(1 + (len(eligible)-frequency[w]+0.5)/(frequency[w]+0.5))
                    * (3 if w in name_terms else 1) * 2.2 / norm
                    for w in haystack & (name_terms | description_terms))
        if score > 0:
            scored.append((score, technique))

    scored.sort(key=lambda pair: (-pair[0], pair[1].technique_id))
    selected = scored[:CANDIDATES]
    parents = {t.technique_id for _,t in selected if not t.is_subtechnique}
    chosen = {t.technique_id for _,t in selected}
    selected += [(score,t) for score,t in scored if t.technique_id not in chosen
                 and t.technique_id.split('.')[0] in parents]
    return [
        {
            "technique_id": technique.technique_id,
            "name": technique.name,
            "tactics": list(technique.tactics),
            "description": technique.description,
        }
        for _score, technique in selected[:40]
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
    if not selection["quoted_values"]:
        problems.append("mapping needs at least one nonempty quoted field value")
    for quoted in selection["quoted_values"]:
        needle = quoted.lower().strip()
        # Exact match, or the quote appearing verbatim *inside* a value -- a
        # command line legitimately contains a filename. What is no longer
        # accepted is the reverse: a stored value containing the quote as a
        # substring, which let `;10.0.2.18` pass against `10.0.2.18` and put
        # three invented semicolons into a committed mapping.
        if not needle or (needle not in values and not any(needle in value for value in values)):
            problems.append(
                f"quoted value {quoted!r} does not appear verbatim in any cited observation"
            )

    if finding["stage"] not in technique.tactics:
        problems.append(
            f"tactic inconsistency: {technique.technique_id} has tactics {list(technique.tactics)}, "
            f"and the finding is at stage {finding['stage']!r}"
        )

    # These are minimum evidence requirements, not attack detectors. A service
    # record cannot substantiate deletion of a file or access to an SMB share.
    kinds = {o.get('event_name') for o in observations}
    if selection['technique_id'] == 'T1070.004' and kinds == {'service_delete'}:
        problems.append('Service deletion is not file deletion; no file deletion evidence is cited')
    if selection['technique_id'] == 'T1070.009' and kinds == {'service_delete'}:
        problems.append('Clear Persistence requires evidence of previously established persistence; service deletion alone does not establish that prerequisite')
    if selection['technique_id'] == 'T1021.002' and kinds <= {'service_create'}:
        problems.append('Service creation alone does not establish SMB/admin-share access')

    return problems


def map_findings(findings, observations, catalogue, **kwargs):
    """Map each atomic action, then retain the parent finding as the graph target."""
    units, parents = [], {}
    for finding in findings:
        for action in finding.get('actions') or [finding]:
            units.append(action)
            parents[action['id']] = finding['id']
    mappings, unmapped = _map_units(units, observations, catalogue, **kwargs)
    for row in mappings + unmapped:
        action_id = row['finding']
        parent = parents[action_id]
        if action_id != parent:
            row['action_id'] = action_id
            row['finding'] = parent
            if row.get('layer') == 'mapping':
                row['id'] = ids.mapping_id(technique_id=row['technique_id'], finding=parent,
                    cited_observations=row['cites_observations'], quoted_values=row['quoted_values'])
    return mappings, unmapped


def _map_units(
    findings: list[dict],
    observations: list[dict],
    catalogue: Catalogue,
    *,
    client_module=None,
    batch_size: int = 8,
    repair_budget: int = 1,
    _repair_diagnostics: dict | None = None,
) -> tuple[list[dict], list[dict]]:
    """`(mappings, unmapped)`.

    Technique selection is the most parallel step in the system: one call per
    accepted finding, no ordering between them, no shared state. Running them
    one at a time was costing a minute per eight findings for no reason.
    """
    by_id = {observation["id"]: observation for observation in observations}
    mappings: list[dict] = []
    unmapped: list[dict] = []
    pending: list[tuple[dict, list[dict], list[dict]]] = []

    # Everything before the model call is deterministic, so retrieval happens
    # for every finding first and only the calls are batched.
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

        pending.append((finding, cited, candidates))

    # ---- the one parallel step ------------------------------------------
    def select(item):
        finding, cited, candidates = item
        model_type = schemas.technique_decision_model(
            tuple(candidate["technique_id"] for candidate in candidates)
        )
        return client_module.call(
            site=contracts.SELECT_TECHNIQUE.name,
            model_type=model_type,
            system=contracts.SELECT_TECHNIQUE.system,
            user=_render(finding, cited, candidates) + (
                "\nPrevious selection was rejected: " + "; ".join(_repair_diagnostics.get(finding["id"], []))
                + "\nCorrect these errors using exact source values, or abstain."
                if _repair_diagnostics else ""
            ),
            max_tokens=4000,
        )

    results: list[Any] = []
    if pending:
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=min(len(pending), batch_size)) as pool:
            futures = [pool.submit(select, item) for item in pending]
            for future in futures:
                try:
                    results.append(future.result())
                except Exception as exc:  # noqa: BLE001
                    results.append(exc)

    for (finding, cited, candidates), result in zip(pending, results):
        if isinstance(result, Exception):
            unmapped.append(
                {
                    "id": ids.node_id("map", {"finding": finding["id"], "outcome": "call_failed"}),
                    "finding": finding["id"],
                    # A failed call, labelled as one. Filed under `unmapped` it
                    # read as "looked and found nothing": 217 of 217 findings
                    # went unmapped on a credit outage with every check green.
                    "outcome": "call_failed",
                    "reason": f"{type(result).__name__}: {result}",
                }
            )
            continue

        parsed = result.parsed
        if hasattr(parsed, "selections"):
            if not parsed.selections:
                unmapped.append({"id": ids.node_id("map", {"finding": finding["id"], "outcome": "unsupported"}), "finding": finding["id"], "outcome": "non_mappable", "reason": parsed.reason})
                continue
            parsed = parsed.selections[0]
        selection = {"technique_id": parsed.technique_id, "technique_name": parsed.technique_name,
                     "quoted_values": list(parsed.quoted_values), "cited_observations": list(parsed.cited_observations)}
        allowed = {o["id"] for o in cited}
        selected = [by_id[o] for o in selection["cited_observations"] if o in allowed]
        problems = validation_failures(selection, finding, selected, catalogue)
        if not selection["cited_observations"] or not set(selection["cited_observations"]) <= allowed:
            problems.append("mapping citations must be a nonempty subset of this finding's evidence")
        subjects = set(finding.get('subject_event_ids', []))
        if subjects and not any(o['event_id'] in subjects for o in selected):
            problems.append('Mapping must cite the primary action, not only a supporting action')
        technique = catalogue.technique(selection["technique_id"])

        if problems:
            if repair_budget > 0:
                repaired, unresolved = map_findings(
                    [finding], observations, catalogue, client_module=client_module,
                    repair_budget=0, _repair_diagnostics={finding["id"]: problems},
                )
                for row in repaired + unresolved:
                    row["repair_diagnostics"] = problems
                mappings.extend(repaired)
                unmapped.extend(unresolved)
                continue
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
    lines.append("CANDIDATE TECHNIQUES -- select zero or one; abstain if unsupported")
    for candidate in candidates:
        lines.append(
            f"  {candidate['technique_id']}  {candidate['name']}  tactics={candidate['tactics']}"
        )
        lines.append(f"      {candidate['description']}")
    return "\n".join(lines)


def report(
    findings: list[dict], mappings: list[dict], unmapped: list[dict], catalogue
) -> dict[str, Any]:
    """The stage-4 report: counts, the technique set, and the verification lines."""
    from collections import Counter

    from .. import paths

    failed = [row for row in unmapped if row["outcome"] == "call_failed"]
    return {
        "attack_version": catalogue.attack_version,
        "catalogue": paths.relative(paths.ATTACK_CATALOGUE),
        "counts": {
            "findings": len(findings),
            "mapped": len(mappings),
            "unmapped": len(unmapped),
            "model_calls_failed": len(failed),
            "selectable_enum_size": len(catalogue.selectable_ids()),
        },
        "techniques": sorted({mapping["technique_id"] for mapping in mappings}),
        "unmapped_outcomes": dict(sorted(Counter(str(row.get("outcome")) for row in unmapped).items())),
        "verification": {
            "every_mapping_id_is_in_the_catalogue": all(
                catalogue.technique(mapping["technique_id"]) is not None for mapping in mappings
            ),
            "every_id_name_pair_is_consistent": all(
                catalogue.name_matches_id(mapping["technique_id"], mapping["technique_name"])
                for mapping in mappings
            ),
            "t1068_not_mapped": all(mapping["technique_id"] != "T1068" for mapping in mappings),
            "non_mappable_is_distinct_from_rejected": True,
            # A failed call is neither non-mappable nor rejected; it is unasked.
            "no_model_call_failed": not failed,
        },
    }
