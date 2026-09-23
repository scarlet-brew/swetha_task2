"""The interpretive layer: SELECT, EXPAND, INTERPRET, HYPOTHESISE, SEEK (T21, T22).

Non-deterministic and untrusted by design. It supplies *completeness* -- finding
things a fixed rule set would not -- while the validator supplies *soundness*.
That is the LLM-Modulo split, and the de Bruijn posture: an untrusted tactic
over a small trusted kernel.

The loop:

    SELECT       which observation next -- anchors order, never filter
    EXPAND       query relations around it, with truncation reported
    INTERPRET    propose a finding citing specific edges
    HYPOTHESISE  what should exist given the findings so far, committed BEFORE looking
    SEEK         FOUND | NOT_FOUND | NOT_COVERED

Termination: the frontier empties, a full pass yields no accepted finding, or
the step budget is exhausted -- which emits `INSUFFICIENT_EVIDENCE` for open
hypotheses rather than concluding.

`interpreter` is injected so the mechanism can be exercised against a scripted
stub with no credential (T21) before the model-backed one is wired in (T22). A
loop failure is then diagnosable as mechanism or as prompt, which it would not
be if the two arrived together.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol

from .. import ids
from ..agent import contracts, schemas
from . import anchors, validate


class Interpreter(Protocol):
    """What the loop needs from whatever is doing the interpreting."""

    def interpret(self, neighbourhood: dict, context: dict) -> dict | None: ...

    def hypothesise(self, findings: list[dict], context: dict) -> dict | None: ...


@dataclass
class Ledger:
    """Everything the loop produced, including what it rejected.

    The rejections are not debris. Every one carries a specific diagnostic, so
    the log is a coverage backlog: it says what the interpretive layer tried to
    claim and exactly why the kernel refused.
    """

    findings: list[dict] = field(default_factory=list)
    hypotheses: list[dict] = field(default_factory=list)
    rejections: list[dict] = field(default_factory=list)
    trajectory: list[dict] = field(default_factory=list)
    edges_traversed: dict[str, dict] = field(default_factory=dict)

    @property
    def finding_ids(self) -> frozenset[str]:
        return frozenset(finding["id"] for finding in self.findings)


def _edge_node(edge: dict, index) -> dict | None:
    holds, params = index.evaluate(
        edge["relation"], edge["from_observation"], edge["to_observation"]
    )
    if not holds:
        return None
    left = index.by_id[edge["from_observation"]]
    right = index.by_id[edge["to_observation"]]
    return {
        "id": ids.edge_id(
            relation=edge["relation"], endpoints=[edge["from_observation"], edge["to_observation"]]
        ),
        "layer": "edge",
        "relation": edge["relation"],
        "from_observation": edge["from_observation"],
        "to_observation": edge["to_observation"],
        "from_event": left["event_id"],
        "to_event": right["event_id"],
        "params": params,
    }


def run(
    *,
    observations: list[dict],
    edges: list[dict],
    index,
    interpreter: Interpreter,
    entities: list[dict],
    max_steps: int = 40,
    expand_k: int = 8,
    back_prompts: int = 1,
) -> Ledger:
    ledger = Ledger()
    order = anchors.ranked(observations, edges)
    anchor_scores = anchors.score(observations, edges)

    # The frontier starts at the anchored observations but is not limited to
    # them: SELECT walks the whole review order, so an intrusion matching no
    # anchor is late in the queue rather than invisible.
    frontier = list(order)
    visited: set[str] = set()
    steps = 0
    passes_without_acceptance = 0

    while frontier and steps < max_steps:
        observation_id = frontier.pop(0)
        if observation_id in visited:
            continue
        visited.add(observation_id)
        steps += 1

        neighbourhood = index.neighbourhood(observation_id, k=expand_k)
        if not neighbourhood.get("relations"):
            continue

        context = {
            "step": steps,
            "anchor": anchor_scores.get(observation_id),
            "accepted_so_far": [
                {"id": f["id"], "stage": f["stage"], "statement": f["statement"]}
                for f in ledger.findings
            ],
        }

        proposal = interpreter.interpret(neighbourhood, context)
        record = {
            "step": steps,
            "action": "interpret",
            "observation": observation_id,
            "relations_offered": {
                relation: {"total": data["total"], "truncated": data["truncated"]}
                for relation, data in neighbourhood["relations"].items()
            },
        }

        if proposal is None:
            record["outcome"] = "nothing_here"
            ledger.trajectory.append(record)
            passes_without_acceptance += 1
            continue

        accepted = _try_accept(
            proposal, index=index, ledger=ledger, back_prompts=back_prompts, interpreter=interpreter,
            neighbourhood=neighbourhood, context=context, step=steps,
        )
        record["outcome"] = "accepted" if accepted else "rejected"
        ledger.trajectory.append(record)

        if accepted:
            passes_without_acceptance = 0
            # Extend the frontier with the neighbourhood we just used, so the
            # search follows the evidence rather than only the anchor order.
            for data in neighbourhood["relations"].values():
                for row in data["observations"]:
                    if row["id"] not in visited:
                        frontier.append(row["id"])

            hypothesis = interpreter.hypothesise(ledger.findings, context)
            if hypothesis is not None:
                _seek(hypothesis, ledger=ledger, index=index, entities=entities, step=steps)
        else:
            passes_without_acceptance += 1

        if passes_without_acceptance >= 12:
            ledger.trajectory.append(
                {"step": steps, "action": "terminate", "reason": "a full pass yielded no accepted finding"}
            )
            break

    if steps >= max_steps:
        ledger.trajectory.append(
            {"step": steps, "action": "terminate", "reason": f"step budget {max_steps} exhausted"}
        )
        for hypothesis in ledger.hypotheses:
            if hypothesis["status"] == "proposed":
                hypothesis["status"] = "unconfirmed"
                hypothesis["outcome"] = "INSUFFICIENT_EVIDENCE"

    return ledger


def _try_accept(
    proposal: dict, *, index, ledger: Ledger, back_prompts: int, interpreter, neighbourhood, context, step: int
) -> bool:
    """Validate, and on rejection back-prompt the diagnostic a bounded number of times."""
    attempt = 0
    while True:
        verdict = validate.validate(proposal, index=index, known_findings=ledger.finding_ids)
        if verdict.accepted:
            _accept(proposal, index=index, ledger=ledger, step=step)
            return True

        ledger.rejections.append(
            {
                "step": step,
                "attempt": attempt,
                "statement": proposal.get("statement"),
                "stage": proposal.get("stage"),
                "cites_observations": proposal.get("cites_observations"),
                "diagnostics": verdict.diagnostics,
                "checks": verdict.checks,
            }
        )
        attempt += 1
        if attempt > back_prompts:
            return False

        repaired = getattr(interpreter, "repair", None)
        if repaired is None:
            return False
        proposal = repaired(proposal, verdict.diagnostics, neighbourhood, context)
        if proposal is None:
            return False


def _accept(proposal: dict, *, index, ledger: Ledger, step: int) -> None:
    edge_nodes = []
    for edge in proposal.get("cites_edges") or []:
        node = _edge_node(edge, index)
        if node is not None:
            edge_nodes.append(node)
            ledger.edges_traversed[node["id"]] = node

    finding_id = ids.finding_id(
        cited_observations=proposal["cites_observations"],
        cited_edges=[node["id"] for node in edge_nodes],
        stage=proposal["stage"],
    )
    if any(finding["id"] == finding_id for finding in ledger.findings):
        # The dedup key and the id are the same mechanism (SS8.2): two proposals
        # citing the same evidence at the same stage are one finding, whatever
        # words they arrived in.
        return

    cited = [index.by_id[obs] for obs in proposal["cites_observations"] if obs in index.by_id]
    ledger.findings.append(
        {
            "id": finding_id,
            "layer": "finding",
            "statement": proposal["statement"],
            "stage": proposal["stage"],
            "rationale": proposal.get("rationale", ""),
            "cites_observations": sorted(set(proposal["cites_observations"])),
            "cites_edges": sorted(node["id"] for node in edge_nodes),
            "cites_findings": sorted(set(proposal.get("cites_findings") or [])),
            "source_types": sorted({observation["source_type"] for observation in cited}),
            "event_ids": sorted({observation["event_id"] for observation in cited}),
            "proposed_at_step": step,
        }
    )


def _seek(hypothesis: dict, *, ledger: Ledger, index, entities: list[dict], step: int) -> None:
    """Look for the predicted record, and distinguish the three outcomes.

    `not_covered` is what makes `not_found` mean anything: if no source carries
    records of that kind about that entity, absence says nothing about the
    estate.
    """
    prediction = {
        key: hypothesis[key]
        for key in (
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

    matches = [
        observation
        for observation in index.observations
        if str(observation["normalised_value"]).lower() == entity_value
        and observation["kind"] == wanted_kind
    ]

    if matches:
        status, outcome = "confirmed", "found"
        evidence = sorted({observation["id"] for observation in matches})[:5]
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
            "status": status,
            "outcome": outcome,
            "evidence": evidence,
            "proposed_at_step": step,
        }
    )
    ledger.trajectory.append(
        {"step": step, "action": "seek", "hypothesis": hypothesis_id, "outcome": outcome}
    )


# `ModelInterpreter` lives in `interpreter.py` -- the mechanism/interpretation
# seam. Re-exported so callers need only one import.
from .interpreter import ModelInterpreter  # noqa: E402,F401

__all__ = ["Interpreter", "Ledger", "ModelInterpreter", "run"]
