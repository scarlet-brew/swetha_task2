"""Stage 6 ANSWER -- read-only retrieval over the frozen artifacts, then a gate (T31).

**No tool here can create a node.** That is what makes this stage structurally
incapable of inventing a finding: it retrieves, reasons and cites, and every
citation must resolve to a node that already exists in the committed graph.

The gate closes the pivot loophole: **a claim that attributes activity to the
intrusion must cite at least one finding.** Observation-only citations support
facts -- that a value appeared in a record -- not attributions. Without that
rule, stage 6 could assemble an attribution out of raw observations and mint a
conclusion the validator never saw.

R2.9: an answer citing an identifier that does not exist is **withheld**, with
the failing check reported, rather than shown without it.
"""

from __future__ import annotations

import re
from typing import Any

from .. import ids, jsonl, paths
from ..enrich.catalogue import Catalogue
from . import client, contracts, schemas

#: A run of node ids in prose, together with whatever brackets it sits in.
#:
#: Belt and braces. The ANSWER prompt says the ids belong in the `cites_*`
#: fields and nowhere else; this removes them from rendered text if one slips
#: through anyway. A sentence ending `(fnd_28064fa63b48, fnd_b6eade451f6b)` is
#: unreadable, and it was the single worst thing about the first chat surface.
#:
#: Stripping is a presentation decision, not a rewrite of a claim: the id stays
#: attached to the claim as a citation and is still rendered as evidence, so
#: removing it from the sentence changes nothing about what is asserted or what
#: supports it.
_NODE_ID = r"(?:fnd|obs|rec|edg|map|hyp)_[0-9a-f]{6,}"
_ID_RUN_IN_PROSE = re.compile(
    r"\s*\(\s*" + _NODE_ID + r"(?:\s*,\s*" + _NODE_ID + r")*\s*\)"
    r"|\s*\[\s*" + _NODE_ID + r"(?:\s*,\s*" + _NODE_ID + r")*\s*\]"
    r"|\s*\b" + _NODE_ID + r"\b"
)


def strip_node_ids(text: str) -> str:
    """Remove node ids from prose meant to be read by a person."""
    cleaned = _ID_RUN_IN_PROSE.sub("", str(text))
    cleaned = re.sub(r"\s+([,.;:])", r"\1", cleaned)
    cleaned = re.sub(r"\(\s*\)|\[\s*\]", "", cleaned)
    cleaned = re.sub(r"[ \t]{2,}", " ", cleaned)
    return cleaned.strip()


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
            "Answer from this material only. Cite node ids that appear above. An "
            "`attribution` claim must cite at least one finding id."
        )
        return "\n".join(lines)


def gate(answer: dict, artifacts: Artifacts) -> tuple[bool, list[str]]:
    """The deterministic citation gate. `(passes, failures)`."""
    failures: list[str] = []

    # An empty claim list is allowed. R2.2 says an *uncited claim* is a bug, not
    # that every answer must assert something -- and an answer forced to produce
    # a claim it has no evidence for is the failure this design exists to stop.
    # Limitations belong in `gaps`, which need no citation.

    for index, claim in enumerate(answer.get("claims", []), start=1):
        cited = (
            list(claim.get("cites_findings") or [])
            + list(claim.get("cites_observations") or [])
            + list(claim.get("cites_mappings") or [])
        )
        if not cited:
            failures.append(f"claim {index}: cites nothing; an uncited claim is a bug (R2.2)")

        for node_id in cited:
            if artifacts.resolve(node_id) is None:
                # R2.9: withheld rather than rendered without the evidence.
                failures.append(f"claim {index}: cited node {node_id} does not resolve in the graph")

        # The pivot loophole.
        if claim.get("kind") == "attribution" and not claim.get("cites_findings"):
            failures.append(
                f"claim {index}: attributes activity to the intrusion but cites no finding; "
                "observation-only citations support facts, not attributions"
            )

        if claim.get("kind") == "absence" and not claim.get("basis"):
            failures.append(f"claim {index}: an absence claim must name its basis")

    return not failures, failures


def to_payload(question: str, answer: dict, artifacts: Artifacts, provenance: dict) -> dict[str, Any]:
    """The render contract in `docs/specs/answer_payload.md`."""
    claims = []
    for index, claim in enumerate(answer.get("claims", []), start=1):
        citations = []
        for node_id in (
            list(claim.get("cites_findings") or [])
            + list(claim.get("cites_mappings") or [])
            + list(claim.get("cites_observations") or [])
        ):
            resolved = artifacts.resolve(node_id)
            if resolved is None:
                continue
            layer, node = resolved
            if layer == "observation":
                citations.append(
                    {
                        "node_id": node_id,
                        "layer": layer,
                        "record_id": node["record"],
                        "event_id": node["event_id"],
                        "source_type": node["source_type"],
                        "timestamp": node["recorded_time"],
                        "field": node["field"],
                        "asserted_value": node["normalised_value"],
                    }
                )
            elif layer == "finding":
                first = next(
                    (
                        artifacts.observations[obs]
                        for obs in node["cites_observations"]
                        if obs in artifacts.observations
                    ),
                    None,
                )
                citations.append(
                    {
                        "node_id": node_id,
                        "layer": layer,
                        "record_id": first["record"] if first else None,
                        "event_id": ", ".join(node["event_ids"][:4]),
                        "source_type": ", ".join(node["source_types"]),
                        "timestamp": first["recorded_time"] if first else None,
                        "field": node["stage"],
                        "asserted_value": node["statement"][:80],
                    }
                )
            else:
                citations.append(
                    {
                        "node_id": node_id,
                        "layer": layer,
                        "record_id": node.get("finding") or node.get("record"),
                        "event_id": node.get("technique_id") or node.get("event_id"),
                        "source_type": layer,
                        "timestamp": None,
                        "field": node.get("technique_name") or node.get("relation"),
                        "asserted_value": node.get("technique_id") or "",
                    }
                )

        support = _support_of(claim, artifacts)
        claims.append(
            {
                "claim_id": f"clm_{index:02d}",
                "text": strip_node_ids(claim["text"]),
                "kind": claim["kind"],
                "support": support,
                "citations": citations,
                **({"basis": {"name": claim["basis"], "requires": "records not being present",
                              "applies_because": claim["basis"]}} if claim.get("basis") else {}),
            }
        )

    return {
        "answer_id": ids.node_id("obs", {"question": question, "body": answer["body"]}),
        "question": question,
        "body": strip_node_ids(answer["body"]),
        "claims": claims,
        "gaps": [{"statement": gap} for gap in answer.get("gaps", [])],
        "provenance": provenance,
    }


def _support_of(claim: dict, artifacts: Artifacts) -> dict[str, Any]:
    """The support label, taken from the findings the claim cites.

    Computed, never asserted by the model -- stage 6 has no field for it. A
    claim resting on several findings takes the weakest of their labels, because
    a conclusion is no better supported than its weakest premise.
    """
    order = {"corroborated": 3, "single_sourced": 2, "absence_based": 1, "conflicted": 0}
    labels = [
        artifacts.findings[f]["support"]["label"]
        for f in claim.get("cites_findings") or []
        if f in artifacts.findings
    ]
    if not labels:
        return {"label": "absence_based" if claim.get("kind") == "absence" else "single_sourced", "flags": []}
    weakest = min(labels, key=lambda label: order.get(label, 0))
    flags = sorted(
        {
            flag
            for f in claim.get("cites_findings") or []
            if f in artifacts.findings
            for flag in artifacts.findings[f]["support"]["flags"]
        }
    )
    return {"label": weakest, "flags": flags}


def ask(question: str, *, artifacts: Artifacts | None = None) -> dict[str, Any]:
    """Answer one question, or explain why the answer is withheld."""
    artifacts = artifacts or Artifacts()
    if not artifacts.available:
        return {
            "withheld": True,
            "reason": "no committed artifacts; run `python -m siem_investigator.build` first",
        }
    if not client.credential_present():
        return {
            "withheld": True,
            "reason": (
                f"{client.CREDENTIAL_VARIABLE} is not set. The timeline, scope and gap report are "
                "still available on their own surfaces; only the chat answer needs the model."
            ),
        }

    try:
        result = client.call(
            site=contracts.ANSWER.name,
            model_type=schemas.Answer,
            system=contracts.ANSWER.system,
            user=artifacts.context(question),
            max_tokens=3000,
        )
    except Exception as exc:
        return {"withheld": True, "reason": f"{type(exc).__name__}: {exc}"}

    answer = result.parsed.model_dump()
    passes, failures = gate(answer, artifacts)
    catalogue_version = (
        Catalogue.load().attack_version if paths.ATTACK_CATALOGUE.exists() else "unavailable"
    )
    provenance = {
        **result.provenance.as_dict(),
        **contracts.stamp(),
        "attack_version": catalogue_version,
    }

    if not passes:
        # R2.9 -- withheld, and the failing check reported.
        return {"withheld": True, "reason": "citation gate failed", "failures": failures,
                "provenance": provenance}

    return {
        "withheld": False,
        "payload": to_payload(question, answer, artifacts, provenance),
        "provenance": provenance,
    }
