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
from .seek import _seek
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
    #: How much of the dataset the loop actually looked at. The instrument that
    #: was missing: three builds passed every invariant while 93 records were
    #: never shown to the model, because nothing counted what was skipped.
    coverage: dict = field(default_factory=dict)

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
    max_steps: int | None = None,
    expand_k: int = 8,
    back_prompts: int = 1,
    batch_size: int = 8,
) -> Ledger:
    """Search the graph, interpreting `batch_size` anchors at a time.

    `max_steps=None` means **every record**, which is the intended setting. A
    budget smaller than the dataset turns the anchors into a filter: two runs
    with the same code and the same model reported different halves of the same
    intrusion purely because they reached different records first.
    """
    ledger = Ledger()
    order = anchors.ranked(observations, edges)
    anchor_scores = anchors.score(observations, edges)

    # One look per record, and by default every record. `steps` counts records
    # examined, not observations, because a record is the unit of evidence.
    total_records = len({observation["record"] for observation in observations})
    budget = total_records if max_steps is None else max_steps

    frontier = list(order)
    visited: set[str] = set()
    anchored_records: set[str] = set()
    steps = 0
    waves_without_acceptance = 0
    isolated = 0
    failed_calls = 0
    first_failure: str | None = None
    batched = getattr(interpreter, "interpret_batch", None)

    while frontier and steps < budget:
        # ---- assemble a wave of distinct records ---------------------------
        wave: list[tuple[str, dict]] = []
        while frontier and len(wave) < batch_size and steps + len(wave) < budget:
            observation_id = frontier.pop(0)
            if observation_id in visited:
                continue
            visited.add(observation_id)

            observation = index.by_id.get(observation_id)
            if observation is None:
                continue
            if observation["record"] in anchored_records:
                # Same log line, already interpreted from another of its fields.
                continue
            anchored_records.add(observation["record"])

            # The neighbourhood of the whole record, never of one field, and a
            # record with no linking relation at all is still shown to the
            # model with its own fields. Examined and found isolated is a
            # result; skipped is a hole -- and skipping here, from a single
            # field's empty neighbourhood, lost 13 of 22 intrusion records.
            neighbourhood = index.neighbourhood(observation_id, k=expand_k)
            if not neighbourhood.get("relations"):
                isolated += 1
            wave.append((observation_id, neighbourhood))

        if not wave:
            break
        steps += len(wave)

        contexts = [
            {
                "step": steps,
                "anchor": anchor_scores.get(observation_id),
                "accepted_so_far": [
                    {"id": f["id"], "stage": f["stage"], "statement": f["statement"]}
                    for f in ledger.findings
                ],
            }
            for observation_id, _ in wave
        ]

        # ---- interpret the wave, concurrently where the interpreter can ----
        if batched is not None:
            proposals = batched([(n, c) for (_, n), c in zip(wave, contexts)])
        else:
            proposals = [
                interpreter.interpret(neighbourhood, context)
                for (_, neighbourhood), context in zip(wave, contexts)
            ]

        # ---- validate and accept, sequentially: the kernel is cheap --------
        accepted_any = False
        for (observation_id, neighbourhood), context, proposal in zip(wave, contexts, proposals):
            record = {
                "step": steps,
                "action": "interpret",
                "observation": observation_id,
                "relations_offered": {
                    relation: {"total": data["total"], "truncated": data["truncated"]}
                    for relation, data in neighbourhood["relations"].items()
                },
            }
            if isinstance(proposal, dict) and "statement" not in proposal and "error" in proposal:
                # The model was never heard from. Recorded as what it is.
                record["outcome"] = "call_failed"
                record["error"] = proposal["error"]
                ledger.trajectory.append(record)
                failed_calls += 1
                first_failure = first_failure or proposal["error"]
                continue
            if proposal is None:
                record["outcome"] = "nothing_here"
                ledger.trajectory.append(record)
                continue

            candidates = proposal.get("proposals", [proposal])
            outcomes = [
                _try_accept(candidate, index=index, ledger=ledger,
                            back_prompts=back_prompts, interpreter=interpreter,
                            neighbourhood=neighbourhood, context=context, step=steps)
                for candidate in candidates if candidate is not None
            ]
            accepted = any(outcomes)
            record["candidate_outcomes"] = outcomes
            record["outcome"] = "accepted" if accepted else "rejected"
            ledger.trajectory.append(record)

            if accepted:
                accepted_any = True
                # Leads go to the *front*, so the next wave follows the chain.
                # Appending them to a 1,951-item tail was identical to
                # discarding them, and it is why the credential theft and the
                # first lateral hop were never reached.
                follow = [
                    row["id"]
                    for data in neighbourhood["relations"].values()
                    for row in data["observations"]
                    if row["id"] not in visited
                ]
                frontier[:0] = follow

        if batched is not None:
            print(f"    correlate {steps}/{total_records} records; {len(ledger.findings)} provisional findings; {failed_calls} failed calls", flush=True)

        # ---- one hypothesis per wave --------------------------------------
        #
        # Per acceptance produced the same prediction up to four times, each
        # costing a call. Once per wave, over everything accepted so far, is
        # both cheaper and less repetitive.
        if accepted_any and ledger.findings:
            hypothesis = interpreter.hypothesise(ledger.findings, {"step": steps})
            if hypothesis is not None:
                _seek(hypothesis, ledger=ledger, index=index, entities=entities, step=steps)
            waves_without_acceptance = 0
        else:
            waves_without_acceptance += 1

        # A patience rule only makes sense under a budget. With every record
        # in scope the loop runs to the end of the frontier: the ranking says
        # where to look first, never where to stop.
        if max_steps is not None and waves_without_acceptance >= 6:
            ledger.trajectory.append(
                {
                    "step": steps,
                    "action": "terminate",
                    "reason": "six consecutive waves yielded no accepted finding",
                }
            )
            break

    if steps >= budget:
        ledger.trajectory.append(
            {
                "step": steps,
                "action": "terminate",
                "reason": (
                    f"examined {steps} of {total_records} records"
                    if steps >= total_records
                    else f"record budget {budget} exhausted before the {total_records} available"
                ),
            }
        )
        for hypothesis in ledger.hypotheses:
            if hypothesis["status"] == "proposed":
                hypothesis["status"] = "unconfirmed"
                hypothesis["outcome"] = "INSUFFICIENT_EVIDENCE"

    ledger.coverage = {
        "records_total": total_records,
        "records_examined": len(anchored_records),
        "records_not_examined": total_records - len(anchored_records),
        "records_examined_without_relations": isolated,
        "records_with_failed_model_calls": failed_calls,
        "first_failure": first_failure,
    }
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
            "subject_event_ids": sorted(set(proposal.get("subject_event_ids") or [o["event_id"] for o in cited])),
            "proposed_at_step": step,
        }
    )


# `ModelInterpreter` lives in `interpreter.py` -- the mechanism/interpretation
# seam. Re-exported so callers need only one import.
from .interpreter import ModelInterpreter  # noqa: E402,F401

__all__ = ["Interpreter", "Ledger", "ModelInterpreter", "run"]
