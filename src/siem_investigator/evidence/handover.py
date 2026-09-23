"""The handover report -- self-contained Markdown (R8, T42).

Design SS10.3's cut order puts this **last**: ratified requirements outrank
design preferences, so the handover document survives longer than the pipeline
view even though the pipeline view is worth more to the walkthrough.

It is the thing the CISO actually forwards, so it has to stand alone. No links
into the tool, no "see the timeline surface", no node ids without the record
behind them. Someone reading it in an email thread with no access to this
repository has to be able to follow it and check it.

A projection under SS8.3: derived from the committed artifacts, regenerable, and
never authoritative.
"""

from __future__ import annotations

from typing import Any

from .. import jsonl, paths


def _read(path):
    return jsonl.read_json(path) if path.is_file() else {}


def render() -> str:
    timeline = _read(paths.TIMELINE)
    scope = _read(paths.SCOPE)
    gaps = _read(paths.GAPS)
    privilege = _read(paths.PRIVILEGE)
    manifest = _read(paths.MANIFEST)
    enrich = _read(paths.ENRICH_REPORT)
    correlate = _read(paths.CORRELATE_REPORT)
    ingest = _read(paths.INGEST_REPORT)
    records = jsonl.index_by_id(jsonl.read(paths.RECORDS)) if paths.RECORDS.is_file() else {}
    observations = (
        jsonl.index_by_id(jsonl.read(paths.OBSERVATIONS)) if paths.OBSERVATIONS.is_file() else {}
    )

    steps = timeline.get("steps", [])
    window = ingest.get("collection_window", {})
    out: list[str] = []
    add = out.append

    add(f"# Incident {ingest.get('incident_ref', 'unknown')} — reconstruction")
    add("")
    add(
        f"Reconstructed from {ingest.get('counts', {}).get('records_out', 0)} log records "
        f"across {len(ingest.get('counts', {}).get('by_source_type', {}))} unrelated sources, "
        f"covering {window.get('start')} to {window.get('end')}."
    )
    add("")
    add(
        "**Every statement below cites the records behind it.** The support label on each "
        "step says what *kind* of support that is, counted from the evidence rather than "
        "asserted: *Corroborated* means two or more distinct log sources agree, "
        "*Single-sourced* means one."
    )
    add("")

    # ---- the one thing a reader needs first ------------------------------
    add("## Summary")
    add("")
    if not steps:
        add(
            "No sequence was reconstructed. That is a result rather than a failure: the "
            "relationships between records were computed and none of them supported an "
            "accepted finding."
        )
    else:
        stages = []
        for step in steps:
            if step["stage"] not in stages:
                stages.append(step["stage"])
        add(
            f"- **{len(steps)} steps** reconstructed, spanning "
            f"{str(timeline.get('window', {}).get('first'))[:19]} to "
            f"{str(timeline.get('window', {}).get('last'))[:19]}."
        )
        add(f"- Stages observed, in order of first appearance: {', '.join(stages)}.")
        add(
            f"- **{len(scope.get('involved', []))} entities** implicated — "
            + ", ".join(
                f"{count} {kind}" for kind, count in sorted(scope.get("counts", {}).items())
            )
            + "."
        )
        add(
            f"- **{len(enrich.get('techniques', []))} MITRE ATT&CK techniques** identified "
            f"against catalogue v{enrich.get('attack_version', '?')}: "
            + ", ".join(enrich.get("techniques", []))
            + "."
        )
        support = correlate.get("support_distribution", {})
        add(
            "- Support: "
            + ", ".join(f"{count} {label.replace('_', '-')}" for label, count in sorted(support.items()))
            + "."
        )
    add("")

    # ---- the limits, before the conclusions ------------------------------
    add("## What this reconstruction cannot establish")
    add("")
    add(
        "Stated before the findings, deliberately. These are limits of the available "
        "sources, not of the analysis, and they bound every conclusion below."
    )
    add("")
    for gap in gaps.get("structural", []):
        if gap.get("verified"):
            add(f"- **{gap['statement']}** {gap['limits'].capitalize()}.")
    unresolved = [
        gap for gap in gaps.get("from_hypotheses", []) if gap["outcome"] == "not_covered"
    ]
    if unresolved:
        add(
            f"- **{len(unresolved)} predictions could not be tested at all** because no log "
            "source covers the entity and event kind in question. Their absence says nothing "
            "about whether the activity occurred."
        )
    not_found = [gap for gap in gaps.get("from_hypotheses", []) if gap["outcome"] == "not_found"]
    if not_found:
        add(
            f"- **{len(not_found)} predictions were tested and not confirmed** in a source that "
            "does cover them."
        )
    if privilege:
        escalation = privilege.get("exploit_based_escalation", {})
        if not escalation.get("evidenced", True):
            add(
                "- **No exploit-based privilege escalation is evidenced.** Privilege rises "
                "through credentials and service execution. "
                f"{', '.join(escalation.get('techniques_deliberately_not_mapped', []))} is "
                "deliberately not claimed, because no record shows exploitation of a "
                "vulnerability and inferring one from rising privilege would be a guess."
            )
    add("")

    # ---- the sequence ----------------------------------------------------
    if steps:
        add("## Sequence")
        add("")
        for index, step in enumerate(steps, start=1):
            techniques = (
                ", ".join(
                    f"{t['technique_id']} ({t['technique_name']})" for t in step["techniques"]
                )
                or "no technique mapped"
            )
            flags = (
                f" · flags: {', '.join(step['support']['flags'])}"
                if step["support"]["flags"]
                else ""
            )
            add(f"### {index}. {step['stage']} — {step['first_recorded_time']}")
            add("")
            add(step["statement"])
            add("")
            add(
                f"*Support: {step['support']['label'].replace('_', '-')}{flags} · "
                f"sources: {', '.join(step['source_types'])} · ATT&CK: {techniques}*"
            )
            add("")
            add("| Event | Source | Recorded | Field | Value |")
            add("|---|---|---|---|---|")
            seen = set()
            for obs_id in step["cites_observations"]:
                observation = observations.get(obs_id)
                if observation is None:
                    continue
                key = (observation["event_id"], observation["field"])
                if key in seen:
                    continue
                seen.add(key)
                value = str(observation["normalised_value"])
                if len(value) > 60:
                    value = value[:57] + "..."
                add(
                    f"| {observation['event_id']} | {observation['source_type']} | "
                    f"{observation['recorded_time']} | {observation['field']} | `{value}` |"
                )
            add("")

    # ---- scope -----------------------------------------------------------
    if scope.get("involved"):
        add("## Scope of compromise")
        add("")
        add("| Entity | Kind | First involved | Last involved | Sources | Steps |")
        add("|---|---|---|---|---|---|")
        for row in scope["involved"]:
            add(
                f"| `{row['value']}` | {row['entity_type']} | {row['first_involvement']} | "
                f"{row['last_involvement']} | {', '.join(row['source_types'])} | "
                f"{row['finding_count']} |"
            )
        add("")
        unimplicated = scope.get("cannot_be_ruled_out", {}).get(
            "hosts_observed_but_not_implicated", []
        )
        if unimplicated:
            add("### What cannot be ruled out")
            add("")
            add(
                "These hosts appear in the data but are cited by no accepted finding. That is "
                "**not** the same as being clear — log coverage is uneven across the estate, "
                "so further spread cannot be excluded."
            )
            add("")
            for host in unimplicated:
                add(f"- `{host}`")
            add("")

    # ---- privilege -------------------------------------------------------
    if privilege.get("per_host"):
        add("## Privilege")
        add("")
        add("| Host | Highest observed | Escalations | Path |")
        add("|---|---|---|---|")
        for host in privilege["per_host"]:
            path = " → ".join(level["level"] for level in host["levels_observed"])
            add(f"| `{host['host']}` | {host['highest']} | {len(host['rises'])} | {path} |")
        add("")

    # ---- coverage --------------------------------------------------------
    if gaps.get("uneven_host_coverage"):
        add("## Log coverage")
        add("")
        add(
            "A host absent from a source is invisible to it. This is why absences above are "
            "reported as limits rather than as evidence."
        )
        add("")
        add("| Host | Records nothing |")
        add("|---|---|")
        for row in gaps["uneven_host_coverage"]:
            add(f"| `{row['host']}` | {', '.join(row['absent_from'])} |")
        add("")

    # ---- how to check it -------------------------------------------------
    add("## How this was produced, and how to check it")
    add("")
    add(
        "An automated pipeline of six stages. Four of them are deterministic code: loading "
        "the records, normalising them, computing the relationships between them, and "
        "projecting the result into this document. A language model is used at exactly three "
        "points — interpreting a set of already-computed relationships, predicting what "
        "record should exist if a reading is right, and choosing an ATT&CK technique from a "
        "shortlist retrieved from the local catalogue."
    )
    add("")
    add(
        "**Every proposed finding passes a deterministic check before it is accepted.** The "
        "checks verify that each cited record exists, that each cited relationship "
        "re-computes as true against the raw data, and that every identifier named in a "
        "statement appears in a record that statement cites. On this run "
        f"{correlate.get('counts', {}).get('proposals_rejected', 0)} proposals were rejected "
        "and are logged with the reason."
    )
    add("")
    add(
        "**No confidence scores appear anywhere in this document**, and none exist in the "
        "system. How strongly something is supported is counted from the evidence — how many "
        "independent log sources agree — rather than estimated."
    )
    add("")
    add("What the checks deliberately do **not** establish:")
    add("")
    add(
        "- Whether an interpretation is *apt*. A finding can cite real records, rest on real "
        "relationships, name only real identifiers, and still read them wrongly. That "
        "judgement is a reviewer's."
    )
    add(
        "- Completeness. The design is biased toward missing activity rather than inventing "
        "it. Absence of a finding is not evidence of absence."
    )
    add("")
    if manifest:
        add(
            f"Produced by siem-investigator {manifest.get('software_version', '?')} · "
            f"ATT&CK v{manifest.get('attack_version', '?')} · "
            f"interpreter: {manifest.get('interpreter', '?')} · "
            f"validator v{manifest.get('validator_version', '?')} · "
            f"contract set `{str(manifest.get('contract_set_hash', ''))[:12]}` · "
            f"{manifest.get('elapsed_seconds', '?')} s"
        )
        add("")
    add(
        "*Synthetic dataset, prepared for a technical assessment. Not a real incident.*"
    )

    return "\n".join(out) + "\n"


def write(destination=None):
    destination = destination or (paths.OUTPUTS / "handover.md")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render(), encoding="utf-8", newline="")
    return destination


def main(argv: list[str] | None = None) -> int:
    path = write()
    print(f"{paths.relative(path)}  {path.stat().st_size:,} bytes")
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main(sys.argv[1:]))
