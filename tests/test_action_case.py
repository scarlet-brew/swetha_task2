import unittest
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from siem_investigator.agent.schemas import CaseReview, CaseAction, ActionGroup
from siem_investigator.correlate.actions import partition_errors, facts, project_action, event_ledger
from siem_investigator.enrich import mapper

class ActionCaseTests(unittest.TestCase):
    def setUp(self):
        self.events = {f'e{i}': {'event_id':f'e{i}','event_name':'process_create',
            'recorded_time':t,'fields':{'hostname':'host','process_name':'net.exe','parent_process':'cmd.exe','command_line':c}}
            for i,t,c in [(1,'2026-06-10T10:07:51Z','net group /domain'),(2,'2026-06-10T10:08:03Z','net user /domain')]}
    def action(self, subjects, context=None):
        return CaseAction(stage='discovery',subject_event_ids=subjects,context_event_ids=context or [],interpretation='Discovery')
    def test_distinct_commands_cannot_be_one_mapping_unit(self):
        case=CaseReview(findings=[ActionGroup(actions=[self.action(['e1','e2'])])])
        self.assertTrue(any('distinct command' in e for e in partition_errors(case,self.events)))
    def test_group_keeps_distinct_actions_and_complete_partition(self):
        case=CaseReview(findings=[ActionGroup(actions=[self.action(['e1']),self.action(['e2'],['e1'])])])
        self.assertEqual(partition_errors(case,self.events),[])
    def test_missing_duplicate_and_unknown_records_rejected(self):
        for subjects in (['e1'],['e1','e1','e2'],['e1','e2','unknown']):
            case=CaseReview(findings=[ActionGroup(actions=[self.action(subjects)])])
            self.assertTrue(partition_errors(case,self.events))
    def test_facts_do_not_invent_parent_pid_or_macro(self):
        row=self.events['e1'];row['fields']['parent_process']='WINWORD.EXE'
        self.assertIn('WINWORD.EXE started',facts(row))
        self.assertNotIn('macro',facts(row))
    def test_time_is_computed_from_primary_records_not_context(self):
        class Index: by_id={}
        action=project_action(self.action(['e2'],['e1']),self.events,Index())
        self.assertEqual(action['duration_seconds'],0)
        case=CaseReview(findings=[ActionGroup(actions=[self.action(['e1']),self.action(['e2'])])])
        rows=event_ledger(case,self.events,[{'id':'f','subject_event_ids':['e1','e2']}])
        self.assertEqual(rows[1]['seconds_since_previous_investigated_event'],12)
    def test_action_identity_ignores_supporting_context(self):
        class Index: by_id={}
        a=project_action(self.action(['e2']),self.events,Index())
        b=project_action(self.action(['e2'],['e1']),self.events,Index())
        self.assertEqual(a['id'],b['id'])
    def test_group_maps_actions_independently(self):
        from unittest.mock import patch
        findings=[{'id':'parent','actions':[{'id':'a'},{'id':'b'}]}]
        with patch.object(mapper,'_map_units',return_value=([],[{'finding':'a'},{'finding':'b'}])) as call:
            _,rows=mapper.map_findings(findings,[],None)
        self.assertEqual([a['id'] for a in call.call_args.args[0]],['a','b'])
        self.assertEqual([r['finding'] for r in rows],['parent','parent'])
        self.assertEqual([r['action_id'] for r in rows],['a','b'])
    def test_service_removal_cannot_prove_file_deletion_or_persistence(self):
        from siem_investigator.enrich.catalogue import Catalogue
        catalogue=Catalogue.load()
        obs=[{'event_name':'service_delete','normalised_value':'PSEXESVC','raw_value':'PSEXESVC'}]
        for technique in ('T1070.004','T1070.009'):
            selection={'technique_id':technique,'technique_name':catalogue.technique(technique).name,'quoted_values':['PSEXESVC']}
            self.assertTrue(mapper.validation_failures(selection,{'stage':'stealth'},obs,catalogue))
    def test_absence_needs_a_verified_gap_when_it_has_no_citation(self):
        from siem_investigator.agent.answer import gate
        from types import SimpleNamespace
        artifacts=SimpleNamespace(gaps={'structural':[{'id':'no_mail_source','verified':True}]},resolve=lambda _:None)
        claim={'kind':'absence','text':'No mail source is present.','applies_because':'no_mail_source'}
        self.assertTrue(gate({'body':'No mail source is present.','claims':[claim]},artifacts)[0])
        claim['applies_because']='invented_gap'
        self.assertFalse(gate({'body':'No mail source is present.','claims':[claim]},artifacts)[0])
