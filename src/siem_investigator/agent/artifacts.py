"""The query-time tool surface: the frozen artifacts, loaded read-only (T31).

Split from `answer.py` because it is the part with no opinion about answering.
It loads what the build committed and hands it back; **nothing here can create
a node**, which is what makes stage 6 structurally incapable of inventing a
finding.

`context` is the load-bearing method, and it carries a lesson. It used to print
only the observations a finding cited, which let the answer stage reason from
"this was not cited" to "this is not in the data" -- and report that a 2.47 GB
upload carried no username when the record plainly carries `username: jdavis`.
**A record is the atomic unit of evidence.** Citing one of its fields does not
make the others unknown, so the whole cited record is printed.
"""

from __future__ import annotations

from typing import Any

from .. import jsonl, paths


class Artifacts:
    """The frozen artifacts, loaded read-only. The query tool surface."""

    def __init__(self) -> None:
        self.records = jsonl.index_by_id(jsonl.read(paths.RECORDS)) if paths.RECORDS.exists() else {}
        self.observations = (
            jsonl.index_by_id(jsonl.read(paths.OBSERVATIONS)) if paths.OBSERVATIONS.exists() else {}
        )
        self.edges = jsonl.index_by_id(jsonl.read(paths.EDGES)) if paths.EDGES.exists() else {}
        self.findings = (
            jsonl.index_by_id(jsonl.read(paths.FINDINGS)) if paths.FINDINGS.exists() else {}
        )
        self.mappings = (
            jsonl.index_by_id(jsonl.read(paths.MAPPINGS)) if paths.MAPPINGS.exists() else {}
        )
        self.hypotheses = (
            jsonl.index_by_id(jsonl.read(paths.HYPOTHESES)) if paths.HYPOTHESES.exists() else {}
        )
        self.timeline = jsonl.read_json(paths.TIMELINE) if paths.TIMELINE.exists() else {"steps": []}
        self.scope = jsonl.read_json(paths.SCOPE) if paths.SCOPE.exists() else {"involved": []}
        self.gaps = jsonl.read_json(paths.GAPS) if paths.GAPS.exists() else {}
        self.privilege = jsonl.read_json(paths.PRIVILEGE) if paths.PRIVILEGE.exists() else {}

    @property
    def available(self) -> bool:
        return bool(self.records)

    def resolve(self, node_id: str) -> tuple[str, dict] | None:
        for layer, store in (
            ("finding", self.findings),
            ("mapping", self.mappings),
            ("observation", self.observations),
            ("edge", self.edges),
            ("record", self.records),
            ("hypothesis", self.hypotheses),
        ):
            if node_id in store:
                return layer, store[node_id]
        return None

    def _cited_records(self, step: dict) -> dict[str, dict]:
        """The distinct records behind a step's cited observations."""
        out: dict[str, dict] = {}
        for observation_id in step.get("cites_observations", []):
            observation = self.observations.get(observation_id)
            if observation is None:
                continue
            record = self.records.get(observation["record"])
            if record is not None:
                out[record["id"]] = record
        return out

    def context(self, question: str, *, limit: int = 40) -> str:
        """What stage 6 is allowed to see: the closed graph, nothing computed fresh."""
        lines = ["QUESTION", f"  {question}", "", "ACCEPTED FINDINGS"]
        for step in self.timeline["steps"][:limit]:
            techniques = ", ".join(t["technique_id"] for t in step["techniques"]) or "unmapped"
            lines.append(
                f"  {step['finding']}  [{step['stage']}]  support={step['support']['label']}  "
                f"techniques={techniques}"
            )
            lines.append(f"      {step['statement']}")
            lines.append(
                f"      events={','.join(step['event_ids'][:8])}  sources={','.join(step['source_types'])}"
            )
            lines.append(f"      observations={','.join(step['cites_observations'][:8])}")
            # The full record behind each citation, not just the cited field.
            # A finding that cites a file size does not thereby make the
            # username on the same record unknown, and an earlier version of
            # this context let the answer stage conclude exactly that.
            for record_id, record in self._cited_records(step).items():
                payload = record.get("payload", {})
                fields = "  ".join(
                    f"{key}={value!r}"
                    for key, value in sorted(payload.items())
                    if key not in ("event_id", "source_type", "event_name", "timestamp")
                    and value not in (None, "")
                )
                lines.append(
                    f"      RECORD {record['event_id']} ({record['source_type']}/"
                    f"{record['event_name']}) at {record['recorded_time']}"
                )
                lines.append(f"        {fields}")

        lines.append("")
        lines.append("SCOPE OF COMPROMISE")
        for row in self.scope["involved"][:40]:
            lines.append(
                f"  {row['entity_type']}:{row['value']}  findings={row['finding_count']}  "
                f"first={row['first_involvement']}  last={row['last_involvement']}"
            )

        lines.append("")
        lines.append("GAPS -- what the sources cannot settle")
        for gap in self.gaps.get("structural", []):
            lines.append(f"  {gap['statement']}  limits: {gap['limits']}")
        for gap in self.gaps.get("from_hypotheses", [])[:10]:
            lines.append(f"  [{gap['outcome']}] {gap['statement']}")

        if self.privilege:
            lines.append("")
            lines.append("PRIVILEGE")
            lines.append(
                f"  exploit-based escalation evidenced: "
                f"{self.privilege['exploit_based_escalation']['evidenced']}"
            )
            for host in self.privilege.get("per_host", [])[:6]:
                lines.append(f"  {host['host']}: highest={host['highest']}, rises={len(host['rises'])}")

        lines.append("")
        lines.append(
            "Answer from this material only. In the prose, reference the EVT-xxxx event "
            "ids shown above, in square brackets. In `claims`, cite the fnd_/obs_ node "
            "ids. An `attribution` claim must cite at least one finding id."
        )
        return "\n".join(lines)
