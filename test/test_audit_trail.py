import json, shutil, tempfile, unittest
from pathlib import Path
from storage.evidence_store import EvidenceStore


class AuditTrailTests(unittest.TestCase):
    def test_approval_appears_in_audit_trail(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        store = EvidenceStore(Path(tmp) / "audit_test.sqlite")
        store.initialize()
        payload = {"response_workflow": {
            "state": "pending_analyst_approval",
            "tasks": [{"status": "proposed"}]}}
        with store._connect() as conn:
            conn.execute(
                "INSERT INTO incidents(id,created_at,updated_at,status,severity,"
                "risk_score,source,payload_json) VALUES(?,?,?,?,?,?,?,?)",
                ("INC-TEST", "t", "t", "Triaged", "HIGH", 60, "test", json.dumps(payload)))
        store.approve_response("INC-TEST", "tester")
        trail = store.audit_trail(10)
        self.assertEqual(trail[0]["event_type"], "response.simulation_logged")
        self.assertEqual(trail[0]["details"]["label"], "SIMULATION")
        self.assertFalse(trail[0]["details"]["executed"])
        approval = next(event for event in trail if event["event_type"] == "response.approved")
        self.assertEqual(approval["incident_id"], "INC-TEST")
        self.assertEqual(approval["details"]["approved_by"], "tester")
        saved = store.get_incident("INC-TEST")["payload"]["response_workflow"]
        self.assertEqual(saved["state"], "approved_for_simulation")
        self.assertFalse(saved["simulation_logs"][0]["executed"])


if __name__ == "__main__":
    unittest.main()
