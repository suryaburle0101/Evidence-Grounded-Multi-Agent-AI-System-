import json
import shutil
import tempfile
import unittest
from pathlib import Path

from storage.evidence_store import EvidenceStore


class IncidentCorrelationTests(unittest.TestCase):
    def test_groups_shared_endpoints_within_time_window(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        store = EvidenceStore(Path(tmp) / "correlation.sqlite")
        rows = [
            ("inc-a", "2026-10-11T10:00:00+00:00", {"source_ip": "10.0.0.4"}),
            ("inc-b", "2026-10-11T10:20:00+00:00", {"destination_ip": "10.0.0.4"}),
            ("inc-c", "2026-10-11T12:00:00+00:00", {"source_ip": "10.0.0.4"}),
        ]
        with store._connect() as conn:
            for incident_id, created, context in rows:
                payload = {"flow_context": context, "final_attack": "DoS"}
                conn.execute(
                    "INSERT INTO incidents(id,created_at,updated_at,status,severity,risk_score,source,payload_json) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    (incident_id, created, created, "open", "HIGH", 60, "test", json.dumps(payload)),
                )
        result = store.correlate_incidents(window_minutes=60)
        self.assertEqual(len(result["groups"]), 1)
        self.assertEqual(set(result["groups"][0]["incident_ids"]), {"inc-a", "inc-b"})
        self.assertIn("analyst review", result["interpretation"])


if __name__ == "__main__":
    unittest.main()
