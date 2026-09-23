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

    def __init__(self, *, client_module, max_tokens: int = 2000):
        self.client = client_module
        self.max_tokens = max_tokens
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
        for relation, data in neighbourhood["relations"].items():
            truncation = (
                f" (showing {data['showing']} nearest of {data['total']})"
                if data["truncated"]
                else f" ({data['total']} complete)"
            )
            lines.append(f"  {relation}{truncation}")
            for row in data["observations"]:
                params = f"  {row['params']}" if row["params"] else ""
                lines.append(
                    f"    {row['id']}  {row['event_id']}  {row['source_type']}  "
                    f"{row['field']} = {row['value']!r}{params}"
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
            self.calls.append({"site": "interpret", "error": f"{type(exc).__name__}: {exc}"})
            return None

        self.calls.append({"site": "interpret", "provenance": result.provenance.as_dict()})
        return _as_proposal(result.parsed)

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
