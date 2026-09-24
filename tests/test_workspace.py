"""Contract tests for the local workspace; no provider requests are made."""
from __future__ import annotations
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'app')]
from workspace_service import Workspace
from workspace_context import WorkspaceArtifacts, audit_graph


class FakeArtifacts:
    def __init__(self):
        self.nodes = {
            'obs': ('observation', {'event_id':'EVT-0001'}),
            'finding': ('finding', {'event_ids':['EVT-0001','EVT-0002','EVT-0003','EVT-0004','EVT-0005'], 'cites_observations':['obs']}),
            'mapping': ('mapping', {'finding':'finding'}),
            'edge': ('edge', {'from_observation':'obs','to_observation':'obs'}),
            'cycle': ('edge', {'cites_edges':['cycle']})}
    def resolve(self, key): return self.nodes.get(key)


class WorkspaceTests(unittest.TestCase):
    def setup_workspace(self):
        workspace=Workspace();workspace.artifacts=FakeArtifacts();workspace.signature=('stable',)
        workspace.data={'revision':'rev', 'issues':[], 'records':[{'event_id':f'EVT-{i:04}'} for i in range(1,6)]}
        workspace.snapshot=lambda: workspace.data
        workspace.fingerprint=lambda: ('stable',)
        return workspace

    def test_mapping_resolves_all_underlying_records_not_first_four(self):
        self.assertEqual(len(Workspace.sources_for('mapping',FakeArtifacts())),5)

    def test_unknown_and_cyclic_nodes_terminate(self):
        self.assertEqual(Workspace.sources_for('missing',FakeArtifacts()),set())
        self.assertEqual(Workspace.sources_for('cycle',FakeArtifacts()),set())

    def test_edge_resolves_its_observation_endpoints(self):
        self.assertEqual(Workspace.sources_for('edge',FakeArtifacts()),{'EVT-0001'})

    def test_stale_snapshot_does_not_call_model(self):
        workspace=self.setup_workspace()
        with patch('workspace_service.answer.ask') as ask:
            self.assertTrue(workspace.ask('Question','old',[])['refresh_required']);ask.assert_not_called()

    def test_gate_rejection_is_preserved(self):
        workspace=self.setup_workspace();result={'withheld':True,'reason':'citation gate failed','failures':['missing source']}
        with patch('workspace_service.answer.ask',return_value=result):
            self.assertEqual(workspace.ask('Question','rev',[]),result)

    def test_model_answer_is_withheld_if_build_changes(self):
        workspace=self.setup_workspace();workspace.fingerprint=lambda:('changed',)
        with patch('workspace_service.answer.ask',return_value={'withheld':False,'payload':{'claims':[]}}):
            self.assertTrue(workspace.ask('Question','rev',[])['refresh_required'])

    def test_followup_context_and_claim_sources(self):
        workspace=self.setup_workspace();result={'withheld':False,'payload':{'claims':[{'citations':[{'node_id':'mapping'}]}]}}
        with patch('workspace_service.answer.ask',return_value=result) as ask:
            response=workspace.ask('What happened next?','rev',['What happened first?'])
            self.assertIn('What happened first?',ask.call_args.args[0])
            self.assertEqual(len(response['payload']['claims'][0]['event_ids']),5)
            self.assertEqual(response['payload']['question'],'What happened next?')

    def test_concurrent_request_does_not_reach_model(self):
        workspace=self.setup_workspace();workspace.answer_lock.acquire()
        try:
            with patch('workspace_service.answer.ask') as ask:
                self.assertTrue(workspace.ask('Question','rev',[])['withheld']);ask.assert_not_called()
        finally:workspace.answer_lock.release()

    def test_stale_contract_prevents_request(self):
        workspace=self.setup_workspace();workspace.data['issues']=['Rebuild required']
        with patch('workspace_service.answer.ask') as ask:
            self.assertTrue(workspace.ask('Question','rev',[])['withheld']);ask.assert_not_called()


class FullGraphContextTests(unittest.TestCase):
    def artifact(self):
        a=WorkspaceArtifacts.__new__(WorkspaceArtifacts)
        a.records={'rec':{'id':'rec','event_id':'EVT-0001','source_type':'endpoint','event_name':'process_create','recorded_time':'2026-06-10T00:00:00Z','payload':{'event_id':'EVT-0001','command_line':'visible original command','note':'DO NOT SEND THIS ANNOTATION'}}}
        a.observations={'obs':{'id':'obs','record':'rec','event_id':'EVT-0001','field':'command_line','normalised_value':'visible original command'}}
        a.edges={};a.mappings={};a.hypotheses={};a.privilege={}
        a.findings={f'fnd_{i}':{'statement':f'finding number {i}','event_ids':[],'id':f'fnd_{i}'} for i in range(63)}
        a.timeline={'steps':[{'finding':f'fnd_{i}','statement':f'finding number {i}','stage':'execution','support':{'label':'single_sourced'},'techniques':[],'event_ids':[],'source_types':[],'cites_observations':[]} for i in range(63)]}
        a.scope={'involved':[{'value':f'host-{i}','entity_type':'host','finding_count':1,'first_involvement':'start','last_involvement':'end'} for i in range(85)]}
        a.gaps={'structural':[],'from_hypotheses':[{'outcome':'not_covered','statement':f'gap-{i}'} for i in range(20)]}
        return a

    def test_last_finding_entity_and_gap_are_not_truncated(self):
        context=self.artifact().context('Explain the whole investigation')
        for expected in ('fnd_62','host-84','gap-19'):
            self.assertIn(expected,context)

    def test_explicit_record_outside_timeline_includes_citable_observations(self):
        context=self.artifact().context('Explain EVT-0001')
        self.assertIn('visible original command',context)
        self.assertIn('"id": "obs"',context)
        self.assertNotIn('DO NOT SEND THIS ANNOTATION',context)

    def test_unrequested_unrelated_record_is_not_added(self):
        self.assertNotIn('visible original command',self.artifact().context('Explain the timeline'))

    def test_graph_audit_catches_broken_projection(self):
        a=self.artifact();a.timeline['steps'][-1]['statement']='stale statement'
        self.assertTrue(any('differs from' in e for e in audit_graph(a)['errors']))

if __name__=='__main__':unittest.main()
