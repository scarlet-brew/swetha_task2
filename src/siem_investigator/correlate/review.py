"""Bounded final verification within correlation; raw events remain authoritative."""
from __future__ import annotations

import json

from ..agent import contracts, schemas
from . import validate


def context_only_reason(finding, index):
    """Conservative evidence limits of the supplied log schemas, not detections."""
    subjects = set(finding.subject_event_ids)
    rows = [o for o in index.by_id.values() if o["event_id"] in subjects]
    kinds = {o["event_name"] for o in rows}
    if kinds == {"user_logoff"}:
        return "Session closure is context, not evidence of a new lateral movement or concealment action."
    if finding.stage == "command-and-control" and kinds == {"network_connection"}:
        return "Connection telemetry alone does not establish command-and-control; application or process-level evidence is required."
    if finding.stage == "collection" and kinds == {"file_create"}:
        cited = subjects | set(finding.context_event_ids)
        if not any(o["event_id"] in cited and o["event_name"] == "process_create" and o["field"] == "command_line" for o in index.by_id.values()):
            return "An unidentified file creation alone does not demonstrate collection or credential-dump contents."
    return None


def resolve_event_evidence(finding, index):
    """Resolve model-cited event IDs to complete records; never infer new records."""
    evidence_ids = set(finding.subject_event_ids) | set(finding.context_event_ids)
    known = {observation["event_id"] for observation in index.by_id.values()}
    unknown = evidence_ids - known
    if unknown:
        raise ValueError("Unknown source events: " + ", ".join(sorted(unknown)))
    return {
        "statement": finding.statement, "stage": finding.stage,
        "rationale": finding.rationale, "subject_event_ids": finding.subject_event_ids,
        "cites_observations": sorted(o["id"] for o in index.by_id.values() if o["event_id"] in evidence_ids),
        "cites_edges": [],
    }


def reconcile(ledger, index, client_module):
    from .loop import Ledger
    from .actions import records, partition_errors, project_action, event_ledger
    from .. import ids, jsonl, paths
    events = records(index)
    payloads = (list(events.values()), [], ledger.hypotheses)
    user = contracts.render_payload(contracts.REVIEW, [
        contracts.PayloadBlock(category, json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
        for category, payload in zip(contracts.REVIEW.egress_categories, payloads)
    ])
    if len(user) > 600_000:
        raise ValueError("Case exceeds prototype context bound; explicit partitioning required")
    problems = []
    for attempt in range(2):
        result = client_module.call(site=contracts.REVIEW.name, model_type=schemas.CaseReview,
            system=contracts.REVIEW.system,
            user=user + ("\nCorrect the following structural defects: " + json.dumps(problems) if problems else ""),
            max_tokens=20000, effort="medium")
        case = result.parsed
        raw_response = case.model_dump()
        narrowed = []
        for group in case.findings:
            retained = []
            for action in group.actions:
                reason = context_only_reason(action, index)
                if reason:
                    case.context.append(schemas.EventDisposition(event_ids=action.subject_event_ids, reason=reason))
                    narrowed.append({'event_ids':action.subject_event_ids,'reason':reason})
                else:
                    retained.append(action)
            group.actions = retained
        # The UI exposes one stage per finding. Split mixed-stage groups so
        # execution cannot disappear under a lateral-movement heading.
        stage_groups = []
        for group in case.findings:
            stages = {}
            for action in group.actions:
                stages.setdefault(action.stage, []).append(action)
            stage_groups.extend(schemas.ActionGroup(actions=items) for items in stages.values())
        case.findings = stage_groups
        problems = partition_errors(case, events)
        final = Ledger()
        context = [row.model_dump() for row in case.context]
        for group in case.findings:
            if problems:
                break
            actions = []
            for action in group.actions:
                reason = context_only_reason(action, index)
                if reason:
                    problems.append("Move to context: " + str(action.subject_event_ids) + ": " + reason)
                    continue
                projected = project_action(action, events, index)
                verdict = validate.validate(projected, index=index)
                if not verdict.accepted:
                    problems.extend(verdict.diagnostics)
                    continue
                actions.append(projected)
            if not actions:
                continue
            subjects = sorted({e for a in actions for e in a['subject_event_ids']})
            cited = sorted({e for a in actions for e in a['cites_observations']})
            finding_id = ids.node_id('fnd', {'actions':sorted(a['id'] for a in actions)})
            final.findings.append({'id':finding_id,'layer':'finding',
                'statement':'; '.join(a['statement'] for a in actions),
                'stage':actions[0]['stage'], 'rationale':' '.join(a['rationale'] for a in actions),
                'actions':actions, 'subject_event_ids':subjects,
                'cites_observations':cited,'cites_edges':[],'cites_findings':[],
                'event_ids':sorted({index.by_id[o]['event_id'] for o in cited}),
                'source_types':sorted({index.by_id[o]['source_type'] for o in cited}),
                'proposed_at_step':len(events)})
        jsonl.write_json(paths.DERIVED / '03_review_attempt.json', {
            'attempt':attempt+1,'response':raw_response,'normalized_response':case.model_dump(),'diagnostics':problems,
            'provenance':result.provenance.as_dict(),
            'input_tokens':result.input_tokens,'output_tokens':result.output_tokens})
        if problems:
            continue
        rows = event_ledger(case, events, final.findings)
        final.trajectory.append({'step':len(events),'action':'case_review',
            'events_accounted':len(rows),'findings':len(final.findings),
            'atomic_actions':sum(len(f['actions']) for f in final.findings)})
        report = {'candidate_count':len(ledger.findings),'final_count':len(final.findings),
            'events_reviewed':len(events),'attempts':attempt+1,'limitations':case.limitations,
            'provenance':result.provenance.as_dict(), 'input_tokens':result.input_tokens,
            'output_tokens':result.output_tokens,'context_only':context,
            'unresolved':[row.model_dump() for row in case.unresolved], 'narrowed_to_context':narrowed,
            'event_ledger':rows,'event_partition_valid':True,
            'semantic_accuracy_requires_evaluation':True,
            'evidence_resolution':'source-derived facts; grouped atomic actions; exhaustive dispositions'}
        jsonl.write_json(paths.DERIVED / '03_event_ledger.json', rows)
        return final, report
    raise ValueError('Correlation failed structural validation: '+json.dumps(problems))
