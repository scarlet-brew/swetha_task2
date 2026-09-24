"""The model-backed interpreter: INTERPRET, HYPOTHESISE, and repair (T22).

Separate from `loop.py` on purpose, and along the seam T21/T22 already draws:
`loop.py` is the *mechanism* -- select, expand, seek, terminate, ledger -- and
this is the *interpretation*. A loop failure is then diagnosable as one or the
other, because the scripted stub can be swapped in for this module without
touching the mechanism.
"""

from __future__ import annotations

import json

from ..agent import contracts, schemas


def _as_proposal(finding) -> dict | None:
    """A parsed `CandidateFinding` as the plain dict the loop validates.

    `NOTHING_HERE` is returned as None: declining is a first-class answer, and a
    wrong finding is worse than no finding.
    """
    if finding.statement.strip().upper().startswith("NOTHING_HERE"):
        return None
    return {
        "statement": finding.statement,
        "stage": finding.stage,
        "rationale": finding.rationale,
        "cites_observations": list(finding.cites_observations),
        "cites_edges": [
            {
                "relation": edge.relation,
                "from_observation": edge.from_observation,
                "to_observation": edge.to_observation,
            }
            for edge in finding.cites_edges
        ],
    }





class ModelInterpreter:
    """INTERPRET and HYPOTHESISE through the constrained contracts of T06."""

    def __init__(self, *, client_module, max_tokens: int = 8000, batch_size: int = 8):
        self.client = client_module
        self.max_tokens = max_tokens
        #: How many interpret calls run at once. Eight is chosen against the
        #: provider's concurrency rather than the machine's: these are HTTPS
        #: round trips, not computation.
        self.batch_size = batch_size
        self.calls: list[dict] = []

    def _render(self, neighbourhood: dict, context: dict) -> str:
        lines = [
            "ANCHOR OBSERVATION",
            f"  {neighbourhood['observation']}  {neighbourhood['event_id']}  "
            f"{neighbourhood['source_type']}  {neighbourhood['field']} = {neighbourhood['value']!r}",
        ]
        if context.get("anchor"):
            lines.append(f"  selected for review because: {'; '.join(context['anchor']['reasons'])}")
        if neighbourhood.get("record_context"):
            lines.append("")
            lines.append("THE REST OF THAT RECORD (same log line, not a correlation)")
            for row in neighbourhood["record_context"]:
                lines.append(f"    {row['id']}  {row['field']} = {row['value']!r}")
            lines.append(
                "  Cite these too where they matter. The account and host on a record are "
                "part of what it evidences, and a finding that cites only the field a "
                "relation matched on leaves a later reader unable to tell whether the "
                "others were absent or merely uncited."
            )
        lines.append("")
        lines.append("FACTUAL RELATIONS AROUND IT")
        if not neighbourhood["relations"]:
            lines.append(
                "  none -- no other record shares an account, host, address, file, size, "
                "pid or process lineage with this one. It stands alone in the 72 hours."
            )
        for relation, data in neighbourhood["relations"].items():
            truncation = (
                f" (showing {data['showing']} nearest of {data['total']})"
                if data["truncated"]
                else f" ({data['total']} complete)"
            )
            lines.append(f"  {relation}{truncation}")
            for row in data["observations"]:
                params = f"  {row['params']}" if row["params"] else ""
                # The edge as it holds, endpoints named, so a citation copies
                # it rather than guessing which of this record's fields matched.
                edge = (
                    f"  [{relation}({row['from_observation']}, {row['to_observation']}) "
                    f"via this record's {row['via']}]"
                    if row.get("via")
                    else ""
                )
                lines.append(
                    f"    {row['id']}  {row['event_id']}  {row['source_type']}  "
                    f"{row['field']} = {row['value']!r}{edge}{params}"
                )
        if neighbourhood.get("ordering"):
            lines.append("")
            lines.append("THESE SAME NEIGHBOURS, IN TIME ORDER RELATIVE TO THE ANCHOR")
            for relation, rows in neighbourhood["ordering"].items():
                lines.append(f"  {relation}")
                for row in rows:
                    lines.append(
                        f"    {row['event_id']}  {row['interval_seconds']:+.1f}s  "
                        f"({row['direction']})"
                    )

        if context.get("accepted_so_far"):
            lines.append("")
            lines.append("FINDINGS ACCEPTED SO FAR")
            for finding in context["accepted_so_far"][-6:]:
                lines.append(f"  {finding['id']}  [{finding['stage']}]  {finding['statement']}")
        lines.append("")
        lines.append(
            "Propose one finding if these relations support an interpretation. Cite the "
            "specific observation ids and edges it rests on. If they support nothing, "
            "say so by proposing a finding whose statement is exactly NOTHING_HERE."
        )
        return "\n".join(lines)

    def interpret(self, neighbourhood: dict, context: dict) -> dict | None:
        user = self._render(neighbourhood, context)
        try:
            result = self.client.call(
                site=contracts.INTERPRET.name,
                model_type=schemas.CandidateFinding,
                system=contracts.INTERPRET.system,
                user=user,
                max_tokens=self.max_tokens,
            )
        except Exception as exc:  # a failed call is a coverage loss, not a crash
            # ...and not a verdict either. `None` means the model looked and
            # said NOTHING_HERE; a failure is returned as such, so the loop
            # can count it. Conflating the two let a credit outage produce
            # 242 "nothing here" outcomes and an all-green empty build.
            message = f"{type(exc).__name__}: {exc}"
            self.calls.append({"site": "interpret", "error": message})
            return {"error": message}

        self.calls.append({"site": "interpret", "provenance": result.provenance.as_dict()})
        return _as_proposal(result.parsed)


    def interpret_batch(self, items: list[tuple[dict, dict]]) -> list[dict | None]:
        """Interpret several neighbourhoods concurrently, in the order given.

        Threads rather than async: these are I/O-bound HTTPS calls and the SDK
        client is safe to share across them, so a pool is the whole mechanism.
        A failure in one anchor becomes `None` for that anchor and nothing else
        -- one bad neighbourhood must not lose the other seven.
        """
        from concurrent.futures import ThreadPoolExecutor

        if not items:
            return []
        with ThreadPoolExecutor(max_workers=min(len(items), self.batch_size)) as pool:
            futures = [
                pool.submit(self.interpret, neighbourhood, context)
                for neighbourhood, context in items
            ]
            out: list[dict | None] = []
            for future in futures:
                try:
                    out.append(future.result())
                except Exception as exc:  # noqa: BLE001
                    message = f"{type(exc).__name__}: {exc}"
                    self.calls.append({"site": "interpret", "error": message})
                    out.append({"error": message})
            return out

    def repair(self, proposal: dict, diagnostics: list[str], neighbourhood: dict, context: dict) -> dict | None:
        """One bounded back-prompt, carrying the diagnostic rather than discarding it.

        This is what replaced union-of-N. Because the validator is
        deterministic, the contract-satisfying-but-wrong region is a *fixed*
        subset of accept-space, so sampling more does not average it out --
        precision is monotone non-increasing in N. Repair uses the information
        the rejection produced instead of throwing it away.
        """
        user = (
            self._render(neighbourhood, context)
            + "\n\nYour previous proposal was REJECTED by the deterministic validator:\n"
            + json.dumps({"statement": proposal.get("statement"), "stage": proposal.get("stage")}, indent=2)
            + "\n\nDiagnostics:\n"
            + "\n".join(f"  - {d}" for d in diagnostics)
            + "\n\nPropose a corrected finding, or NOTHING_HERE if the evidence does not support one."
        )
        try:
            result = self.client.call(
                site=contracts.INTERPRET.name,
                model_type=schemas.CandidateFinding,
                system=contracts.INTERPRET.system,
                user=user,
                max_tokens=self.max_tokens,
            )
        except Exception as exc:
            self.calls.append({"site": "interpret_repair", "error": f"{type(exc).__name__}: {exc}"})
            return None
        self.calls.append({"site": "interpret_repair", "provenance": result.provenance.as_dict()})
        return _as_proposal(result.parsed)

    def hypothesise(self, findings: list[dict], context: dict) -> dict | None:
        if not findings:
            return None
        user = "FINDINGS SO FAR\n" + "\n".join(
            f"  {finding['id']}  [{finding['stage']}]  {finding['statement']}"
            for finding in findings[-8:]
        )
        try:
            result = self.client.call(
                site=contracts.HYPOTHESISE.name,
                model_type=schemas.Hypothesis,
                system=contracts.HYPOTHESISE.system,
                user=user,
                max_tokens=self.max_tokens,
            )
        except Exception as exc:
            self.calls.append({"site": "hypothesise", "error": f"{type(exc).__name__}: {exc}"})
            return None
        self.calls.append({"site": "hypothesise", "provenance": result.provenance.as_dict()})
        hypothesis = result.parsed
        known = {finding["id"] for finding in findings}
        premises = [p for p in hypothesis.premises if p in known] or [findings[-1]["id"]]
        return {
            "premises": premises,
            "predicted_entity": hypothesis.predicted_entity.lower(),
            "predicted_role": hypothesis.predicted_role,
            "predicted_event_kind": hypothesis.predicted_event_kind,
            "predicted_source_type": hypothesis.predicted_source_type,
            "window_start": hypothesis.window_start,
            "window_end": hypothesis.window_end,
            "rationale": hypothesis.rationale,
        }
