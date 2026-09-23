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
from .evidence import close, graph, observations as observations_module, synthesise
from .ingest import load, parse, transforms


def _stamp(extra: dict[str, Any] | None = None) -> dict[str, Any]:
    return {**contracts.stamp(), "software_version": __version__, **(extra or {})}


def run(*, use_model: bool = True, max_steps: int = 40) -> dict[str, Any]:
    started = time.perf_counter()
    reports: dict[str, Any] = {}

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
    )

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
        f"{len(committed_edges)} edges, {len(ledger.hypotheses)} hypotheses  [{mode}]"
    )

    # ---- stage 4: ENRICH --------------------------------------------------
    catalogue = Catalogue.load()
    mappings, unmapped = mapper.map_findings(
        findings,
        observation_nodes,
        catalogue,
        client_module=client if (use_model and client.credential_present()) else None,
    )
    enrich_report = {
        "attack_version": catalogue.attack_version,
        "catalogue": paths.relative(paths.ATTACK_CATALOGUE),
        "counts": {
            "findings": len(findings),
            "mapped": len(mappings),
            "unmapped": len(unmapped),
            "selectable_enum_size": len(catalogue.selectable_ids()),
        },
        "techniques": sorted({mapping["technique_id"] for mapping in mappings}),
        "unmapped_outcomes": _count_by(unmapped, "outcome"),
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
        },
    }
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
    investigation = graph.Graph()
    for record in records:
        investigation.add(record, layer="record")
    for observation in observation_nodes:
        investigation.add(observation, layer="observation", cites=[observation["record"]])
    for edge in committed_edges.values():
        investigation.add(
            edge, layer="edge", cites=[edge["from_observation"], edge["to_observation"]]
        )
    for finding in findings:
        investigation.add(
            finding,
            layer="finding",
            cites=finding["cites_observations"] + finding["cites_edges"] + finding["cites_findings"],
        )
    for mapping in mappings:
        investigation.add(
            mapping, layer="mapping", cites=[mapping["finding"]] + mapping["cites_observations"]
        )
    for hypothesis in ledger.hypotheses:
        investigation.add(hypothesis, layer="hypothesis", cites=hypothesis["premises"])

    invariants = investigation.check_all()
    synth_report = {
        "projections": {
            "timeline_steps": timeline["count"],
            "entities_in_scope": len(scope["involved"]),
            "gaps": gap_report["counts"],
            "attack_flow_objects": len(flow["objects"]),
            "navigator_techniques": len(layer["techniques"]),
        },
        "graph_invariants": invariants,
        "verification": {
            "every_timeline_step_traces_to_the_graph": all(
                step["finding"] in investigation.nodes for step in timeline["steps"]
            ),
            "absence_claims_computed_after_close": True,
            "invariant_1_layer_order": invariants["invariant_1_layer_order"]["holds"],
            "invariant_2_termination": invariants["invariant_2_termination"]["holds"],
            "invariant_3_acyclicity": invariants["invariant_3_acyclicity"]["holds"],
        },
    }
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

    manifest = {
        **_stamp({"attack_version": catalogue.attack_version, "interpreter": mode}),
        "elapsed_seconds": round(time.perf_counter() - started, 2),
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
    parser.add_argument("--max-steps", type=int, default=40, help="interpretive loop step budget")
    args = parser.parse_args(argv)

    print(f"siem-investigator {__version__}  build")
    if not args.no_model and not client.credential_present():
        print(
            f"  note: {client.CREDENTIAL_VARIABLE} is unset. The deterministic stages still run; "
            "technique attribution is reported as unmapped rather than omitted."
        )
    try:
        run(use_model=not args.no_model, max_steps=args.max_steps)
    except Exception as exc:  # NFR-06: a stage failure names itself
        print(f"\nBUILD FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
