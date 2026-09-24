"""Regression cases for overclassification boundaries; no model or labels required."""
import unittest
from types import SimpleNamespace

import _env
from siem_investigator.agent import schemas
from siem_investigator.correlate import relations, seek, loop, validate
from siem_investigator.correlate.interpreter import _as_proposal
from siem_investigator.enrich import mapper
from siem_investigator.enrich.catalogue import Catalogue


def event(event_id, name, fields, time="2026-06-10T10:00:00Z", source="endpoint"):
    types = {"hostname": ("host", "observed_on"), "username": ("account", "actor"),
             "pid": ("pid", "actor"), "dest_host": ("host", "target")}
    return [dict(id=f"{event_id}-{field}", record=event_id, event_id=event_id,
                 source_type=source, event_name=name, kind=f"{source}/{name}",
                 field=field, raw_value=value, normalised_value=value,
                 entity_type=types.get(field, (None, None))[0],
                 role=types.get(field, (None, None))[1], recorded_time=time)
            for field,value in fields.items()]


class CorrelationBoundaries(unittest.TestCase):
    def test_assessment_preserves_multiple_distinct_candidates(self):
        from siem_investigator.correlate.interpreter import ModelInterpreter
        findings = [schemas.CandidateFinding(statement=text, stage="execution", rationale="Observed action",
                     cites_observations=["a-hostname"], cites_edges=[], subject_event_ids=["a"])
                    for text in ("First action", "Second action")]
        assessment = schemas.CandidateAssessment(disposition="candidate", reason="Two behaviours", findings=findings)
        fake = SimpleNamespace(call=lambda **kwargs: SimpleNamespace(parsed=assessment,
                               provenance=SimpleNamespace(as_dict=lambda: {})))
        interpreter = ModelInterpreter(client_module=fake)
        interpreter._render = lambda *args: "events"
        self.assertEqual([p["statement"] for p in interpreter.interpret({}, {})["proposals"]],
                         ["First action", "Second action"])

    def test_review_resolves_event_citations_and_rejects_unknown_events(self):
        from siem_investigator.correlate.review import resolve_event_evidence
        index = relations.RelationIndex(event("a", "process_create", {"hostname": "one", "process_name": "cmd.exe"}))
        candidate = schemas.ReviewedFinding(statement="cmd.exe ran on one.", stage="execution",
                    rationale="Source action", subject_event_ids=["a"], context_event_ids=[])
        proposal = resolve_event_evidence(candidate, index)
        self.assertEqual(proposal["cites_observations"], ["a-hostname", "a-process_name"])
        self.assertEqual(proposal["cites_edges"], [])
        candidate.context_event_ids = ["missing"]
        with self.assertRaises(ValueError):
            resolve_event_evidence(candidate, index)

    def test_context_records_cannot_be_promoted_by_an_attack_stage_label(self):
        from siem_investigator.correlate.review import context_only_reason
        for kind, stage in (("user_logoff", "lateral-movement"),
                            ("network_connection", "command-and-control"),
                            ("file_create", "collection")):
            index = relations.RelationIndex(event("a", kind, {"hostname": "one"}))
            finding = schemas.ReviewedFinding(statement="Context", rationale="Related record",
                        subject_event_ids=["a"], context_event_ids=[], stage=stage)
            self.assertIsNotNone(context_only_reason(finding, index))

    def test_archive_command_plus_creation_is_not_discarded_as_context(self):
        from siem_investigator.correlate.review import context_only_reason
        index = relations.RelationIndex(event("a", "file_create", {"file_path": "archive.zip"})
                                        + event("b", "process_create", {"command_line": "7z a archive.zip files"}))
        finding = schemas.ReviewedFinding(statement="Archive created", rationale="Observed command and output",
                    subject_event_ids=["a"], context_event_ids=["b"], stage="collection")
        self.assertIsNone(context_only_reason(finding, index))

    def test_declining_requires_no_intrusion_stage(self):
        for disposition in ("unresolved", "not_linked"):
            assessment=schemas.CandidateAssessment(disposition=disposition, reason="Only shared identity", findings=[])
            self.assertIsNone(_as_proposal(assessment))

    def test_neighbours_include_actions_not_just_matching_identity(self):
        observations=event("a", "user_logon", {"hostname":"host-a", "username":"alice"})
        observations+=event("b", "process_access", {"hostname":"host-a", "username":"alice", "target_process":"lsass.exe"})
        index=relations.RelationIndex(observations)
        context=index.neighbourhood("a-hostname", k=8)["event_context"]
        other=next(row for row in context if row["event_id"]=="b")
        self.assertEqual(other["fields"]["target_process"]["value"], "lsass.exe")

    def test_cross_host_pid_is_not_a_process_link(self):
        index=relations.RelationIndex(event("a","process_create",{"hostname":"host-a","pid":12})+event("b","process_access",{"hostname":"host-b","pid":12}))
        self.assertFalse(index.evaluate("process_pid","a-pid","b-pid")[0])

    def test_same_host_pid_remains_a_candidate_association(self):
        index=relations.RelationIndex(event("a","process_create",{"hostname":"host-a","pid":12})+event("b","process_access",{"hostname":"host-a","pid":12}))
        self.assertTrue(index.evaluate("process_pid","a-pid","b-pid")[0])

    def test_sessions_on_different_targets_do_not_join(self):
        index=relations.RelationIndex(event("a","user_logon",{"dest_host":"one","username":"alice","result":"success"},source="auth")+event("b","user_logoff",{"dest_host":"two","username":"alice"},time="2026-06-10T11:00:00Z",source="auth"))
        self.assertFalse(index.evaluate("session_bracket","a-username","b-username")[0])

    def test_auth_conflict_is_exposed_without_rewriting_source(self):
        index=relations.RelationIndex(event("a","failed_logon",{"result":"success"},source="auth"))
        row=index.event_context()[0]
        self.assertTrue(row["data_quality"])
        self.assertEqual(row["fields"]["result"]["value"],"success")

    def test_subject_event_must_be_in_cited_evidence(self):
        observations=event("a","process_create",{"hostname":"host-a"})
        verdict=validate.validate({"statement":"Activity on host-a.","stage":"execution","cites_observations":["a-hostname"],"subject_event_ids":["missing"]},index=relations.RelationIndex(observations))
        self.assertFalse(verdict.accepted)

    def _seek(self, role, end):
        observations=event("a","user_logon",{"dest_host":"one"},source="auth")
        ledger=loop.Ledger()
        seek._seek(dict(premises=["fnd-test"],predicted_entity="one",predicted_role=role,
                        predicted_event_kind="auth/user_logon",predicted_source_type="auth",
                        window_start="2026-06-10T09:00:00Z",window_end=end),ledger=ledger,
                   index=relations.RelationIndex(observations),entities=[{"value":"one","coverage":{"mentioned_in":["auth"]}}],step=1)
        return ledger.hypotheses[0]

    def test_seek_does_not_match_wrong_role(self):
        self.assertNotEqual(self._seek("origin","2026-06-10T11:00:00Z")["outcome"],"found")

    def test_seek_compares_instants_not_timestamp_strings(self):
        self.assertEqual(self._seek("target","2026-06-10T10:00:00.500000Z")["outcome"],"found")


class MappingBoundaries(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalogue=Catalogue.load()

    def test_retrieval_keeps_eligible_cloud_exfiltration_candidate(self):
        finding = {"statement": "An archive file was uploaded from a host to an external cloud storage bucket.",
                   "rationale": "Matching archive name and size", "stage": "exfiltration"}
        rows = mapper.retrieve(finding, [], self.catalogue)
        self.assertTrue(rows)
        self.assertTrue(all("exfiltration" in row["tactics"] for row in rows))
        self.assertIn("T1567.002", {row["technique_id"] for row in rows})

    def setUp(self):
        self.observations=event("a","process_create",{"process_name":"powershell.exe"})
        self.finding=dict(id="fnd-test",statement="PowerShell ran.",stage="execution",cites_observations=["a-process_name"])

    def test_empty_quote_is_rejected(self):
        issues=mapper.validation_failures(dict(technique_id="T1059.001",technique_name="PowerShell",quoted_values=[""]),self.finding,self.observations,self.catalogue)
        self.assertTrue(issues)

    def test_explicit_abstention_creates_no_mapping(self):
        fake=SimpleNamespace(credential_present=lambda:True,call=lambda **kwargs:SimpleNamespace(parsed=SimpleNamespace(selections=[],reason="Evidence does not demonstrate a candidate")))
        mappings,unmapped=mapper.map_findings([self.finding],self.observations,self.catalogue,client_module=fake)
        self.assertEqual(mappings,[])
        self.assertEqual(unmapped[0]["outcome"],"non_mappable")

    def test_unknown_citations_are_rejected_not_replaced(self):
        selected=SimpleNamespace(technique_id="T1059.001",technique_name="PowerShell",quoted_values=["powershell.exe"],cited_observations=["missing"])
        fake=SimpleNamespace(credential_present=lambda:True,call=lambda **kwargs:SimpleNamespace(parsed=SimpleNamespace(selections=[selected],reason="test")))
        mappings,unmapped=mapper.map_findings([self.finding],self.observations,self.catalogue,client_module=fake)
        self.assertEqual(mappings,[])
        self.assertEqual(unmapped[0]["outcome"],"rejected")

    def test_selected_evidence_cannot_borrow_quotes_from_other_citations(self):
        self.observations+=event("b","process_create",{"process_name":"cmd.exe"})
        self.finding["cites_observations"].append("b-process_name")
        selected=SimpleNamespace(technique_id="T1059.001",technique_name="PowerShell",quoted_values=["powershell.exe"],cited_observations=["b-process_name"])
        fake=SimpleNamespace(credential_present=lambda:True,call=lambda **kwargs:SimpleNamespace(parsed=SimpleNamespace(selections=[selected],reason="test")))
        mappings,unmapped=mapper.map_findings([self.finding],self.observations,self.catalogue,client_module=fake)
        self.assertEqual(mappings,[])
        self.assertEqual(unmapped[0]["outcome"],"rejected")

    def test_definition_is_not_silently_clipped(self):
        text=mapper._render(self.finding,self.observations,[dict(technique_id="T1059.001",name="PowerShell",tactics=["execution"],description="x"*500+" defining condition")])
        self.assertIn("defining condition",text)

if __name__ == '__main__':
    unittest.main()
