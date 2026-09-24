"""SEEK -- test a hypothesis against the graph, and tell absence from blindness.

Split from `loop.py` because it is the one part of stage 3 that is purely
deterministic: given a prediction, either a matching record exists or it does
not, and the interesting work is distinguishing *why* not.

`not_covered` is what makes `not_found` mean anything. Without it, "no record"
conflates absence from the estate with blindness of the source -- and an
earlier version got this catastrophically wrong: 18 of 24 predictions named an
event kind that cannot exist, so every one came back unmatched and was
published as a verified gap in log coverage. The prediction vocabulary is now
closed, and the window and source are enforced here.
"""

from __future__ import annotations

from .. import ids
from datetime import datetime, timedelta


def _seek(hypothesis: dict, *, ledger: Ledger, index, entities: list[dict], step: int) -> None:
    """Look for the predicted record, and distinguish the three outcomes.

    `not_covered` is what makes `not_found` mean anything: if no source carries
    records of that kind about that entity, absence says nothing about the
    estate.
    """
    prediction = {
        key: hypothesis[key]
        for key in (
            "event_constraints",
            "predicted_entity",
            "predicted_role",
            "predicted_event_kind",
            "predicted_source_type",
            "window_start",
            "window_end",
        )
        if key in hypothesis
    }
    hypothesis_id = ids.hypothesis_id(premises=hypothesis["premises"], prediction=prediction)
    if any(existing["id"] == hypothesis_id for existing in ledger.hypotheses):
        return

    entity_value = str(prediction.get("predicted_entity", "")).lower()
    wanted_kind = prediction.get("predicted_event_kind", "")
    wanted_source = prediction.get("predicted_source_type", "")

    # Is the entity covered by the source that should have carried the record?
    covered = False
    for entity in entities:
        if entity["value"] == entity_value:
            covered = wanted_source in entity["coverage"]["mentioned_in"]
            break

    # The prediction commits to a window and a source, so the search honours
    # both. Matching entity and kind alone let out-of-window records confirm a
    # hypothesis, which made it unfalsifiable: it could not fail for the reason
    # it was written.
    start, end = prediction.get("window_start"), prediction.get("window_end")
    def instant(value):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    constraints = prediction.get("event_constraints", [])
    diagnostic = None
    try:
        first, last = instant(start), instant(end)
        if first.utcoffset() is None or last.utcoffset() is None:
            raise ValueError("Search window must include timezones")
        if last < first or last - first > timedelta(hours=24):
            raise ValueError("Search window must be ordered and no wider than 24 hours")
        if wanted_source == "auth" and prediction.get("predicted_role") == "actor":
            if not any(c.get("field") == "dest_host" and c.get("value") for c in constraints):
                raise ValueError("Actor authentication prediction requires dest_host")
        if any(not c.get("field") or not c.get("value") for c in constraints):
            raise ValueError("Record constraints must have nonempty fields and values")
    except (ValueError, TypeError, AttributeError) as exc:
        diagnostic = str(exc)
    by_event = {}
    for observation in index.observations:
        by_event.setdefault(observation["event_id"], []).append(observation)
    def constrained_rows(event_id):
        rows = by_event[event_id]
        return [next((o for o in rows if o.get("field") == c["field"]
                      and str(o.get("normalised_value", "")).casefold() == str(c["value"]).casefold()), None)
                for c in constraints]
    matches = [

        observation
        for observation in index.observations
        if not diagnostic
        and str(observation["normalised_value"]).lower() == entity_value
        and observation.get("role") == prediction.get("predicted_role")
        and observation["kind"] == wanted_kind
        and observation["source_type"] == wanted_source
        and all(constrained_rows(observation["event_id"]))
        and (not start or instant(observation["recorded_time"]) >= instant(start))
        and (not end or instant(observation["recorded_time"]) <= instant(end))
    ]

    if matches:
        status, outcome = "confirmed", "found"
        evidence = sorted({o["id"] for match in matches[:5]
                           for o in [match, *constrained_rows(match["event_id"])]})
    elif diagnostic:
        status, outcome = "unconfirmed", "not_found"
        evidence = []
    elif not covered:
        status, outcome = "uncoverable", "not_covered"
        evidence = []
    else:
        status, outcome = "unconfirmed", "not_found"
        evidence = []

    ledger.hypotheses.append(
        {
            "id": hypothesis_id,
            "layer": "hypothesis",
            "premises": sorted(set(hypothesis["premises"])),
            **prediction,
            "rationale": hypothesis.get("rationale", ""),
            **({"validation_error": diagnostic} if diagnostic else {}),
            "status": status,
            "outcome": outcome,
            "evidence": evidence,
            "proposed_at_step": step,
        }
    )
    ledger.trajectory.append(
        {"step": step, "action": "seek", "hypothesis": hypothesis_id, "outcome": outcome}
    )


