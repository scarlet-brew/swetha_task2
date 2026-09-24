"""Read-only presentation adapter. The investigation engine remains authoritative."""
from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path

from siem_investigator import paths
from siem_investigator.agent import answer, client, contracts
from workspace_context import WorkspaceArtifacts, audit_graph


class SnapshotChanged(Exception):
    pass


class Workspace:
    def __init__(self):
        self.lock = threading.RLock()
        self.answer_lock = threading.Lock()
        self.signature = None
        self.data = None
        self.artifacts = None

    def files(self):
        return sorted(paths.DERIVED.glob('*.json*'))

    def fingerprint(self):
        return tuple((p.name, p.stat().st_mtime_ns, p.stat().st_size) for p in self.files())

    @staticmethod
    def read(path, default=None):
        return json.loads(path.read_text(encoding='utf-8')) if path.exists() else (default or {})

    def snapshot(self):
        with self.lock:
            before = self.fingerprint()
            if self.data is not None and before == self.signature:
                return self.data
            a = WorkspaceArtifacts()
            manifest = self.read(paths.MANIFEST)
            ingest = self.read(paths.INGEST_REPORT)
            reports = [self.read(p) for p in (paths.INGEST_REPORT, paths.PARSE_REPORT, paths.CORRELATE_REPORT, paths.ENRICH_REPORT, paths.SYNTHESISE_REPORT)]
            if before != self.fingerprint():
                raise SnapshotChanged('Investigation files are changing. Wait for the build to finish, then refresh.')
            issues = []
            if not manifest:
                issues.append('No completed build manifest is available.')
            for relative, size in manifest.get('artifacts', {}).items():
                target = (paths.ROOT / relative).resolve()
                if not target.is_relative_to(paths.DERIVED.resolve()):
                    continue
                if not target.exists() or target.stat().st_size != size:
                    issues.append('The saved files differ from the completed build manifest. A rebuild may still be running.')
                    break
            if manifest.get('contract_set_hash') != contracts.CONTRACT_SET_HASH:
                issues.append('The saved investigation was built with a different analysis contract. Rebuild it before asking new questions.')
            graph = audit_graph(a)
            if graph['errors']:
                issues.append('Some saved results do not resolve to the investigation graph. See How it works for details; rebuild before asking questions.')
            records = []
            for r in a.records.values():
                payload = dict(r.get('payload', {}))
                payload.pop('note', None)
                records.append(payload)
            records.sort(key=lambda r: (r.get('timestamp', ''), r.get('event_id', '')))
            revision = hashlib.sha256(repr(before).encode()).hexdigest()[:16]
            stages = []
            definitions = [('Collect logs', 'Ingest', 'Code', '01_'), ('Read fields', 'Parse', 'Code', '02_'), ('Connect events', 'Correlate', 'Code + AI', '03_'), ('Identify techniques', 'Enrich', 'Catalogue + AI', '04_'), ('Build the case', 'Synthesise', 'Code', '05_')]
            for i, (title, name, mode, prefix) in enumerate(definitions):
                artifacts = [{'name': p.name, 'bytes': p.stat().st_size} for p in self.files() if p.name.startswith(prefix)]
                stages.append(dict(title=title, name=name, mode=mode, state='Outputs available' if artifacts else 'Not built', artifacts=artifacts, report=reports[i], checks=next((v for k, v in manifest.get('stage_verification', {}).items() if k.startswith(prefix)), {})))
            if before != self.fingerprint():
                raise SnapshotChanged('The investigation changed while loading.')
            self.data = dict(revision=revision, incident=ingest.get('incident_ref', 'Incident investigation'), organisation='Meridian Health Partners', records=records, timeline=a.timeline.get('steps', []), event_ledger=a.timeline.get('events', []), scope=a.scope, gaps=a.gaps, privilege=a.privilege, stages=stages, manifest=manifest, issues=issues, chat_ready=bool(a.available and client.credential_present() and not issues), credential_present=client.credential_present(), window=ingest.get('collection_window', {}))
            self.artifacts, self.signature = a, before
            self.data['graph'] = graph
            return self.data

    @staticmethod
    def sources_for(node_id, artifacts, visited=None):
        visited = visited or set()
        if node_id in visited:
            return set()
        visited.add(node_id)
        resolved = artifacts.resolve(node_id)
        if not resolved:
            return set()
        layer, node = resolved
        if layer in ('record', 'observation'):
            return {node['event_id']} if node.get('event_id') else set()
        found = set(node.get('event_ids', []))
        for key in ('finding', 'record', 'from_observation', 'to_observation'):
            if node.get(key):
                found |= Workspace.sources_for(node[key], artifacts, visited)
        for key in ('cites_observations', 'cites_findings', 'cites_edges'):
            for child in node.get(key, []):
                found |= Workspace.sources_for(child, artifacts, visited)
        return found

    def ask(self, question, revision, history):
        if not self.answer_lock.acquire(blocking=False):
            return {'withheld': True, 'reason': 'An answer is already being prepared. Please try again when it finishes.'}
        try:
            with self.lock:
                data = self.snapshot()
                if revision != data['revision']:
                    return {'withheld': True, 'reason': 'The investigation has changed. Refresh the workspace before asking again.', 'refresh_required': True}
                if data['issues']:
                    return {'withheld': True, 'reason': ' '.join(data['issues'])}
                artifacts = self.artifacts
                signature = self.signature
            # Prior questions resolve follow-up references without treating old AI prose as evidence.
            previous = [x for x in history[-4:] if isinstance(x, str) and len(x) <= 4000]
            context = question if not previous else ('Earlier user questions (context only, not evidence):\n' + '\n'.join(previous) + '\n\nCurrent question:\n' + question)
            result = answer.ask(context, artifacts=artifacts)
            if signature != self.fingerprint():
                return {'withheld': True, 'reason': 'The investigation changed while answering. Refresh and ask again.', 'refresh_required': True}
            if not result.get('withheld'):
                valid = {r['event_id'] for r in data['records']}
                payload = result['payload']
                payload['question'] = question
                for claim in payload.get('claims', []):
                    ids = set()
                    for citation in claim.get('citations', []):
                        ids |= self.sources_for(citation.get('node_id', ''), artifacts)
                    claim['event_ids'] = sorted(ids & valid)
                payload['revision'] = revision
            return result
        finally:
            self.answer_lock.release()

    def brief(self, revision):
        data = self.snapshot()
        if data['revision'] != revision:
            raise SnapshotChanged('Refresh before exporting the updated investigation.')
        lines = [data['incident'], 'Investigation snapshot: ' + data['revision'], 'Generated from saved pipeline outputs. Findings require analyst review.', '']
        lines.extend('NOTICE: ' + issue for issue in data['issues'])
        for step in data['timeline']:
            lines.extend([step.get('first_recorded_time', '') + ' — ' + step.get('stage', ''), step.get('statement', ''), 'Evidence: ' + ', '.join(step.get('event_ids', [])), ''])
        lines.append('Known limitations')
        lines.extend(g.get('statement', '') for g in data['gaps'].get('structural', []))
        lines.extend(['', 'Source records cited by these findings'])
        cited = {event for step in data['timeline'] for event in step.get('event_ids', [])}
        lines.extend(f"{r['event_id']} | {r.get('source_type', '')} | {r.get('timestamp', '')} | {r.get('event_name', '')}" for r in data['records'] if r['event_id'] in cited)
        return '\n'.join(lines)
