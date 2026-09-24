"""Atomic action accounting and source-derived descriptions, without detection rules."""
from collections import Counter
from datetime import datetime
from .. import ids

def instant(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

def records(index):
    return {e["event_id"]: {**e, "recorded_time":e['time'], "fields": {k:v["value"] for k,v in e["fields"].items()}}
            for e in index.event_context()}

def facts(event):
    """No AI-generated observed-action text is promoted to a source fact."""
    p = event["fields"]
    kind = event.get("event_name") or event.get("kind", "").split("/")[-1]
    host = p.get("hostname", p.get("source_host", p.get("src_host", "unspecified host")))
    if kind == "process_create":
        return f"{host}: {p.get('parent_process', 'unspecified parent')} started {p.get('process_name', 'process')}; command: {p.get('command_line', 'not recorded')}"
    if kind == "process_access":
        return f"{host}: {p.get('process_name')} (PID {p.get('pid')}) accessed {p.get('target_process')} with recorded rights {p.get('access_rights')}"
    if kind in ("file_create", "file_delete"):
        return f"{host}: {'created' if kind == 'file_create' else 'deleted'} {p.get('file_path', 'unspecified file')}" + (f" ({p['file_size_bytes']} bytes)" if 'file_size_bytes' in p else '')
    if kind in ("service_create", "service_delete"):
        return f"{host}: {'created' if kind == 'service_create' else 'deleted'} service {p.get('service_name')}" + (f"; path {p['service_path']}" if p.get('service_path') else '')
    if kind == "network_connection":
        return f"{p.get('src_ip')}: recorded {p.get('protocol')} connection to {p.get('dst_ip')}:{p.get('dst_port')}; action {p.get('action')}"
    if kind in ("user_logon", "user_logoff", "failed_logon"):
        return f"{kind.replace('_', ' ')}: {p.get('username')} from {p.get('source_host')} to {p.get('dest_host')}; type {p.get('logon_type')}; result {p.get('result')}"
    if kind == "file_upload":
        return f"{host}: uploaded {p.get('file_name')} ({p.get('file_size_bytes')} bytes) to bucket {p.get('bucket')}; owner {p.get('bucket_owner')}; action {p.get('action')}"
    return f"{kind}: " + '; '.join(f"{k}={v}" for k,v in p.items())

def partition_errors(case, events):
    dispositions = list(case.unrelated_event_ids)
    primary = []
    referenced = set()
    errors = []
    for group in case.findings:
        for action in group.actions:
            primary += action.subject_event_ids
            dispositions += action.subject_event_ids
            referenced.update(action.subject_event_ids + action.context_event_ids)
            subjects = [events[e] for e in action.subject_event_ids if e in events]
            # Distinct source actions are separate mapping units. A command and its
            # resulting file can share an action, but different commands cannot.
            commands = {e['fields'].get('command_line') for e in subjects if e['fields'].get('command_line')}
            kinds = {e.get('event_name', e.get('kind','').split('/')[-1]) for e in subjects}
            if len(commands) > 1:
                errors.append(f"Split distinct command records into separate actions: {action.subject_event_ids}")
            if len(kinds) > 1 and kinds != {'process_create', 'file_create'}:
                errors.append(f"Split distinct event kinds into separate actions: {action.subject_event_ids}")
    for row in case.context + case.unresolved:
        dispositions += row.event_ids
    referenced.update(dispositions)
    counts = Counter(dispositions)
    if set(events) - set(dispositions): errors.append('Missing dispositions: '+str(sorted(set(events)-set(dispositions))))
    if referenced - set(events): errors.append('Unknown event IDs: '+str(sorted(referenced-set(events))))
    if any(n != 1 for n in counts.values()): errors.append('Duplicate dispositions: '+str([e for e,n in counts.items() if n != 1]))
    return errors

def project_action(action, events, index):
    subjects = sorted(action.subject_event_ids, key=lambda e:instant(events[e]['recorded_time']))
    cited = set(subjects + action.context_event_ids)
    times = [events[e]['recorded_time'] for e in subjects]
    action_id = ids.node_id('fnd', {'action_events':sorted(subjects),'stage':action.stage})
    return {'id':action_id, 'stage':action.stage, 'subject_event_ids':subjects,
            'context_event_ids':sorted(set(action.context_event_ids)),
            'statement':'; '.join(facts(events[e]) for e in subjects),
            'interpretation':action.interpretation, 'limitations':action.limitations,
            'rationale':'Interpretation (not source fact): '+action.interpretation+' Limitations: '+'; '.join(action.limitations),
            'cites_observations':sorted(o['id'] for o in index.by_id.values() if o['event_id'] in cited),
            'cites_edges':[], 'first_recorded_time':times[0], 'last_recorded_time':times[-1],
            'duration_seconds':(instant(times[-1])-instant(times[0])).total_seconds()}

def event_ledger(case, events, findings):
    placement = {e:('unrelated',None) for e in case.unrelated_event_ids}
    for row in case.context:
        placement.update({e:('context',None) for e in row.event_ids})
    for row in case.unresolved:
        placement.update({e:('unresolved',None) for e in row.event_ids})
    for finding in findings:
        placement.update({e:('finding',finding['id']) for e in finding['subject_event_ids']})
    rows = []
    for eid,event in sorted(events.items(),key=lambda pair:instant(pair[1]['recorded_time'])):
        disposition,finding = placement[eid]
        rows.append({'event_id':eid,'recorded_time':event['recorded_time'], 'disposition':disposition,
                     'finding':finding,'observation':facts(event)})
    previous = None
    for row in rows:
        if row['disposition'] not in ('finding','context'): continue
        row['seconds_since_previous_investigated_event'] = ((instant(row['recorded_time'])-instant(previous['recorded_time'])).total_seconds() if previous else None)
        row['previous_investigated_event'] = previous['event_id'] if previous else None
        previous = row
    return rows
