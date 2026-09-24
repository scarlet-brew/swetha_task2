"""The build entry point -- run once, commit the artifacts (T28, T29).

    python -m siem_investigator.build              # full build
    python -m siem_investigator.build --no-model   # deterministic stages only

Two commands, deliberately separate: **the build** writes `data/derived/` and
**the app** only reads it. Nothing is computed at question time that could mint
a claim (NFR-01), and the app therefore starts with no credential and no
network.

With `ANTHROPIC_API_KEY` unset the build still reconstructs the relationships,
the scope of compromise and the absent-source report; technique attribution is
reported as **unmapped** rather than omitted (NFR-02).

Each stage writes a verification report next to its artifacts, so the pipeline
surface is a renderer over six JSON files rather than a second implementation.
"""

from __future__ import annotations

import argparse
import sys
import time
from typing import Any

from . import __version__, jsonl, paths
from .agent import client, contracts
from .correlate import anchors, loop, relations
from .enrich import mapper
from .enrich.catalogue import Catalogue
from .evidence import close, graph, handover, observations as observations_module, synthesise
from .ingest import load, parse, transforms


def _stamp(extra: dict[str, Any] | None = None) -> dict[str, Any]:
    return {**contracts.stamp(), "software_version": __version__, **(extra or {})}


def run(
    *, use_model: bool = True, max_steps: int | None = None, from_stage: int = 1
) -> dict[str, Any]:
    started = time.perf_counter()
    reports: dict[str, Any] = {}

    if from_stage >= 4:
        return _finish(
            **_resume_after_stage_3(reports),
            reports=reports,
            started=started,
            use_model=use_model,
            resumed_from=from_stage,
        )

    # ---- stage 1: INGEST --------------------------------------------------
    records, ingest_report = load.run()
    ingest_report["verification"] = {
        "counts_reconcile": ingest_report["counts"]["events_in"] == ingest_report["counts"]["records_out"],
        "annotation_absent_downstream": all(
            "note" not in record["payload"] for record in records
        ),
        "every_record_retrievable_by_id": len({r["id"] for r in records}) == len(records),
    }
    jsonl.write_json(paths.INGEST_REPORT, ingest_report)
    reports["01_ingest"] = ingest_report
    print(f"  1 INGEST       {len(records)} records, {ingest_report['counts']['annotations_stripped']} annotations stripped")

    # ---- stage 2: PARSE ---------------------------------------------------
    parsed = parse.run(records)
    observation_nodes = observations_module.build(records, parsed["provenance"], parsed["references"])
    grounding = observations_module.grounding_failures(observation_nodes, records)
    parse_report = parsed["report"]
    parse_report["verification"] = {
        "invariant_4_grounding": {"failures": grounding, "holds": not grounding},
        "invariant_5_reproducibility": parse_report["invariant_5_reproducibility"],
        "observations": len(observation_nodes),
    }
    jsonl.write_json(paths.PARSE_REPORT, parse_report)
    jsonl.write(paths.OBSERVATIONS, observation_nodes)
    reports["02_parse"] = parse_report
    print(
        f"  2 PARSE        {len(observation_nodes)} observations, invariant 4 "
        f"{'holds' if not grounding else 'FAILS'}, invariant 5 "
        f"{'holds' if parse_report['invariant_5_reproducibility']['holds'] else 'FAILS'}"
    )

    # ---- stage 3: CORRELATE ----------------------------------------------
    index = relations.RelationIndex(observation_nodes, parsed["resolution"])
    sparse_edges = index.materialise_sparse()

    interpreter: Any
    if use_model and client.credential_present():
        interpreter = loop.ModelInterpreter(client_module=client)
        mode = "model-backed"
    else:
        from .correlate import stub

        interpreter = stub.StubInterpreter(index)
        mode = "deterministic stub (no credential)" if use_model else "deterministic stub (--no-model)"

    ledger = loop.run(
        observations=observation_nodes,
        edges=sparse_edges,
        index=index,
        interpreter=interpreter,
        entities=parsed["entities"],
        max_steps=max_steps,
        batch_size=8,
    )

    failed = ledger.coverage.get("records_with_failed_model_calls", 0)
    if failed and failed == ledger.coverage.get("records_examined"):
        # Nothing was investigated. Writing "0 findings" with every check green
        # would be the fabricated conclusion the whole design exists to avoid.
        print(
            f"  3 CORRELATE    aborted: every one of {failed} model calls failed\n"
            f"    first error  {ledger.coverage.get('first_failure')}"
        )
        raise SystemExit(2)

    closed = close.close(ledger.findings, observation_nodes)
    findings = closed["findings"]

    traversed = list(ledger.edges_traversed.values())
    committed_edges = {edge["id"]: edge for edge in sparse_edges + traversed}

    leak = anchors.leak_independence(observation_nodes, sparse_edges)
    correlate_report = {
        "interpreter": mode,
        "counts": {
            "observations": len(observation_nodes),
            "sparse_edges_materialised": len(sparse_edges),
            "edges_traversed_by_the_investigation": len(traversed),
            "findings_accepted": len(findings),
            "proposals_rejected": len(ledger.rejections),
            "hypotheses": len(ledger.hypotheses),
            "trajectory_steps": len(ledger.trajectory),
        },
        "coverage": ledger.coverage,
        "relations": {
            "sparse_materialised": list(relations.SPARSE),
            "dense_left_as_queries": list(relations.DENSE),
            "counts_by_relation": _count_by(sparse_edges + traversed, "relation"),
        },
        "support_distribution": closed["support_distribution"],
        "flags": closed["flags"],
        "check_6_mutual_compatibility": closed["check_6_mutual_compatibility"],
        "hypothesis_outcomes": _count_by(ledger.hypotheses, "outcome"),
        "rejection_reasons": _rejection_summary(ledger.rejections),
        "leak_independence": leak,
        "verification": {
            # Coverage, not only grounding. Every earlier check asked "could
            # this have been invented?"; none asked "was it looked at?".
            "every_record_examined": ledger.coverage.get("records_not_examined") == 0,
            "no_model_call_failed": ledger.coverage.get("records_with_failed_model_calls") == 0,
            "every_finding_cites_an_observation": all(f["cites_observations"] for f in findings),
            "every_rejection_carries_a_diagnostic": all(
                r["diagnostics"] for r in ledger.rejections
            ),
            "anchors_order_and_do_not_filter": leak["ordering_not_filtering"]["is_permutation"],
            "anchors_independent_of_all_three_leaks": all(
                leak[name]["independent"]
                for name in ("note_field", "timestamp_precision", "event_id_ordering")
            ),
        },
    }

    jsonl.write(paths.EDGES, list(committed_edges.values()))
    jsonl.write(paths.FINDINGS, findings)
    jsonl.write(paths.HYPOTHESES, ledger.hypotheses)
    jsonl.write(
        paths.TRAJECTORY,
        [{**step, "id": f"obs_{i:012d}"} for i, step in enumerate(ledger.trajectory)],
    )
    jsonl.write(
        paths.REJECTIONS,
        [{**row, "id": f"obs_{i:012d}"} for i, row in enumerate(ledger.rejections)],
    )
    jsonl.write_json(paths.CORRELATE_REPORT, correlate_report)
    reports["03_correlate"] = correlate_report
    print(
        f"  3 CORRELATE    {len(findings)} findings accepted, {len(ledger.rejections)} rejected, "
        f"{len(committed_edges)} edges, {len(ledger.hypotheses)} hypotheses  [{mode}]\n"
        f"    coverage     {ledger.coverage.get('records_examined')}/{ledger.coverage.get('records_total')} "
        f"records examined, {ledger.coverage.get('records_examined_without_relations')} of them isolated, "
        f"{ledger.coverage.get('records_with_failed_model_calls')} model calls failed"
    )

    return _finish(
        records=records,
        observation_nodes=observation_nodes,
        parsed=parsed,
        ledger=ledger,
        findings=findings,
        committed_edges=committed_edges,
        mode=mode,
        grounding=grounding,
        parse_report=parse_report,
        reports=reports,
        started=started,
        use_model=use_model,
    )


def _finish(
    *,
    records: list[dict],
    observation_nodes: list[dict],
    parsed: dict[str, Any],
    ledger: loop.Ledger,
    findings: list[dict],
    committed_edges: dict[str, dict],
    mode: str,
    grounding: list,
    parse_report: dict[str, Any],
    reports: dict[str, Any],
    started: float,
    use_model: bool,
    resumed_from: int | None = None,
) -> dict[str, Any]:
    """Stages 4 and 5, the graph invariants and the manifest -- split out so a
    build can resume from stage 4 over committed stage 1-3 artifacts instead of
    re-spending the ~320 model calls of stage 3 (three builds died after it)."""
    # ---- stage 4: ENRICH --------------------------------------------------
    catalogue = Catalogue.load()
    mappings, unmapped = mapper.map_findings(
        findings,
        observation_nodes,
        catalogue,
        client_module=client if (use_model and client.credential_present()) else None,
    )
    enrich_report = mapper.report(findings, mappings, unmapped, catalogue)
    failed_calls = [row for row in unmapped if row["outcome"] == "call_failed"]
    if failed_calls and not mappings and len(failed_calls) == len(unmapped):
        # Nothing was asked, so nothing is written: 217 "unmapped" rows with
        # every check green is how a credit outage once passed for a result.
        print(
            f"  4 ENRICH       aborted: every one of {len(failed_calls)} model calls failed\n"
            f"    first error  {failed_calls[0]['reason'][:160]}\n"
            f"    resume with  python -m siem_investigator.build --from-stage 4"
        )
        raise SystemExit(2)
    jsonl.write(paths.MAPPINGS, mappings)
    jsonl.write(paths.UNMAPPED, unmapped)
    jsonl.write_json(paths.ENRICH_REPORT, enrich_report)
    reports["04_enrich"] = enrich_report
    print(f"  4 ENRICH       {len(mappings)} mapped, {len(unmapped)} unmapped, ATT&CK v{catalogue.attack_version}")

    # ---- stage 5: SYNTHESISE ---------------------------------------------
    timeline = synthesise.timeline(findings, observation_nodes, mappings)
    scope = synthesise.scope(findings, observation_nodes, parsed["entities"])
    gap_report = synthesise.gaps(ledger.hypotheses, parsed["entities"], records, findings)
    privilege = synthesise.privilege_report(findings, observation_nodes, mappings)
    flow = synthesise.attack_flow(findings, mappings, catalogue.attack_version)
    layer = synthesise.navigator_layer(mappings, catalogue.attack_version)

    for path, payload in (
        (paths.TIMELINE, timeline),
        (paths.SCOPE, scope),
        (paths.GAPS, gap_report),
        (paths.PRIVILEGE, privilege),
        (paths.ATTACK_FLOW, flow),
        (paths.NAVIGATOR_LAYER, layer),
    ):
        jsonl.write_json(path, payload)

    # ---- the graph and its invariants ------------------------------------
    investigation = graph.assemble(
        records=records,
        observations=observation_nodes,
        edges=list(committed_edges.values()),
        findings=findings,
        mappings=mappings,
        hypotheses=ledger.hypotheses,
    )
    invariants = investigation.check_all()
    synth_report = synthesise.report(
        timeline=timeline, scope=scope, gap_report=gap_report, flow=flow, layer=layer,
        invariants=invariants, investigation=investigation,
    )
    jsonl.write_json(paths.SYNTHESISE_REPORT, synth_report)
    reports["05_synthesise"] = synth_report
    print(
        f"  5 SYNTHESISE   {timeline['count']} timeline steps, {len(scope['involved'])} entities in scope, "
        f"{gap_report['counts']['structural']} structural gaps"
    )
    print(
        f"    invariants   1 layer {_ok(invariants['invariant_1_layer_order']['holds'])}  "
        f"2 termination {_ok(invariants['invariant_2_termination']['holds'])}  "
        f"3 acyclic {_ok(invariants['invariant_3_acyclicity']['holds'])}  "
        f"4 grounding {_ok(not grounding)}  "
        f"5 reproducible {_ok(parse_report['invariant_5_reproducibility']['holds'])}"
    )

    # R8, and SS10.3 cuts this last: the document the CISO actually forwards.
    handover_path = handover.write()
    print(f"  handover       {paths.relative(handover_path)}  {handover_path.stat().st_size:,} bytes")

    manifest = {
        **_stamp({"attack_version": catalogue.attack_version, "interpreter": mode}),
        "elapsed_seconds": round(time.perf_counter() - started, 2),
        "resumed_from_stage": resumed_from,  # stated: stages 1-3 came from disk
        "artifacts": {
            paths.relative(path): path.stat().st_size
            for path in (
                paths.RECORDS, paths.INGEST_REPORT, paths.EVENTS, paths.ENTITIES,
                paths.RESOLUTION, paths.PARSE_REPORT, paths.OBSERVATIONS, paths.EDGES,
                paths.FINDINGS, paths.HYPOTHESES, paths.TRAJECTORY, paths.REJECTIONS,
                paths.CORRELATE_REPORT, paths.MAPPINGS, paths.UNMAPPED, paths.ENRICH_REPORT,
                paths.TIMELINE, paths.SCOPE, paths.GAPS, paths.PRIVILEGE,
                paths.ATTACK_FLOW, paths.NAVIGATOR_LAYER, paths.SYNTHESISE_REPORT,
            )
            if path.exists()
        },
        "stage_verification": {name: report.get("verification", {}) for name, report in reports.items()},
    }
    jsonl.write_json(paths.MANIFEST, manifest)
    print(f"  manifest       {len(manifest['artifacts'])} artifacts, {manifest['elapsed_seconds']}s")
    return manifest


def _resume_after_stage_3(reports: dict[str, Any]) -> dict[str, Any]:
    """Load what stages 1-3 committed, so stage 4 can start from it."""
    for name, path in (
        ("01_ingest", paths.INGEST_REPORT),
        ("02_parse", paths.PARSE_REPORT),
        ("03_correlate", paths.CORRELATE_REPORT),
    ):
        if not path.exists():
            raise SystemExit(f"cannot resume: {paths.relative(path)} is missing; run the full build")
        reports[name] = jsonl.read_json(path)
    parse_report = reports["02_parse"]
    correlate_report = reports["03_correlate"]
    print(f"  1-3 RESUMED    from committed artifacts  [{correlate_report.get('interpreter')}]")
    return {
        "records": jsonl.read(paths.RECORDS),
        "observation_nodes": jsonl.read(paths.OBSERVATIONS),
        "parsed": {"entities": jsonl.read(paths.ENTITIES)},
        "ledger": loop.Ledger(hypotheses=jsonl.read(paths.HYPOTHESES)),
        "findings": jsonl.read(paths.FINDINGS),
        "committed_edges": {edge["id"]: edge for edge in jsonl.read(paths.EDGES)},
        "mode": correlate_report.get("interpreter", "unknown"),
        "grounding": parse_report.get("verification", {}).get("invariant_4_grounding", {}).get("failures", []),
        "parse_report": parse_report,
    }


def _ok(value: bool) -> str:
    return "ok" if value else "FAIL"


def _count_by(rows: list[dict], key: str) -> dict[str, int]:
    from collections import Counter

    return dict(sorted(Counter(str(row.get(key)) for row in rows).items()))


def _rejection_summary(rejections: list[dict]) -> dict[str, int]:
    from collections import Counter

    failed = Counter()
    for rejection in rejections:
        for check, passed in rejection["checks"].items():
            if not passed:
                failed[check] += 1
    return dict(sorted(failed.items()))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Reconstruct the incident from the raw logs.")
    parser.add_argument(
        "--no-model", action="store_true", help="deterministic stages only, no model calls"
    )
    parser.add_argument("--max-steps", type=int, default=None, help="records to examine; default is all of them")
    parser.add_argument(
        "--from-stage",
        type=int,
        choices=(1, 4),
        default=1,
        help="4 resumes over the committed stage 1-3 artifacts instead of re-spending their model calls",
    )
    args = parser.parse_args(argv)

    print(f"siem-investigator {__version__}  build")
    if not args.no_model and not client.credential_present():
        print(
            f"  note: {client.CREDENTIAL_VARIABLE} is unset. The deterministic stages still run; "
            "technique attribution is reported as unmapped rather than omitted."
        )
    try:
        run(use_model=not args.no_model, max_steps=args.max_steps, from_stage=args.from_stage)
    except Exception as exc:  # NFR-06: a stage failure names itself
        print(f"\nBUILD FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
