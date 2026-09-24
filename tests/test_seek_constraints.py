"""Conjunctive record matching and bounded temporal hypotheses."""
import unittest
import _env
from test_correlation_repair import event
from siem_investigator.correlate import seek, loop, relations

class SeekConstraints(unittest.TestCase):
    def run_seek(self, rows, **overrides):
        prediction = dict(premises=["fnd-test"], predicted_entity="jdavis", predicted_role="actor",
            predicted_event_kind="auth/user_logon", predicted_source_type="auth",
            event_constraints=[{"field":"dest_host", "value":"FILE-SRV-02"}, {"field":"result", "value":"success"}],
            window_start="2026-06-10T09:00:00Z", window_end="2026-06-10T11:00:00Z")
        prediction.update(overrides)
        ledger=loop.Ledger()
        seek._seek(prediction, ledger=ledger, index=relations.RelationIndex(rows),
                   entities=[{"value":"jdavis", "coverage":{"mentioned_in":["auth"]}}], step=1)
        return ledger.hypotheses[0]

    def rows(self, target="file-srv-02", actor="jdavis", result="success", **kw):
        return event(kw.pop("event_id", "a"), "user_logon", {"username":actor,"dest_host":target,"result":result}, source="auth", **kw)

    def test_wrong_destination_cannot_confirm(self):
        self.assertEqual(self.run_seek(self.rows(target="auth-srv-01"))["outcome"],"not_found")

    def test_constraints_cannot_join_different_records(self):
        rows=self.rows(target="auth-srv-01")+self.rows(actor="another", event_id="b")
        self.assertEqual(self.run_seek(rows)["outcome"],"not_found")

    def test_all_constraints_required_and_cited(self):
        self.assertEqual(self.run_seek(self.rows(result="failure"))["outcome"],"not_found")
        matched=self.run_seek(self.rows())
        self.assertEqual(matched["outcome"],"found")
        self.assertEqual(set(matched["evidence"]),{"a-username","a-dest_host","a-result"})

    def test_invalid_windows_and_missing_target_fail_closed(self):
        for change in [dict(window_start="2026-01-01T00:00:00Z"), dict(window_end="bad"),
                       dict(window_end="2026-06-10T08:00:00Z"),dict(window_start="2026-06-10T09:00:00"),
                       dict(event_constraints=[])]:
            with self.subTest(change=change):
                actual=self.run_seek(self.rows(),**change)
                self.assertEqual(actual["status"],"unconfirmed")
                self.assertIn("validation_error",actual)

    def test_window_boundary_and_outside(self):
        self.assertEqual(self.run_seek(self.rows(time="2026-06-10T11:00:00Z"))["outcome"],"found")
        self.assertEqual(self.run_seek(self.rows(time="2026-06-10T11:00:01Z"))["outcome"],"not_found")

    def test_destination_is_part_of_identity(self):
        a=self.run_seek(self.rows())
        b=self.run_seek(self.rows(),event_constraints=[{"field":"dest_host","value":"auth-srv-01"}])
        self.assertNotEqual(a["id"],b["id"])

    def test_invalid_prediction_is_not_a_log_coverage_gap(self):
        from siem_investigator.evidence.gaps import gaps
        invalid=self.run_seek(self.rows(),window_end="bad")
        report=gaps([invalid],[],[],[])
        self.assertEqual(report["from_hypotheses"],[])
        self.assertEqual(len(report["invalid_predictions"]),1)
