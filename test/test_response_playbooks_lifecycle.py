import json
import shutil
import tempfile
import unittest
from pathlib import Path

from reporting.incident_report import render_markdown
from response.playbooks import build_playbook
from storage.evidence_store import EvidenceStore


class ResponsePlaybookLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.temp_dir, True)
        self.store = EvidenceStore(Path(self.temp_dir) / "response.sqlite")
        self.playbook = build_playbook("DDoS", [
            {"id": "E1", "type": "model", "source": "Random Forest",
             "value": {"attack_family": "DDoS"}, "direction": "supports ATTACK", "weight": 0.3},
            {"id": "E2", "type": "reference_doc", "source": "ddos:T1498",
             "value": {"family": "DDoS", "technique_id": "T1498"},
             "direction": "supports ATTACK", "weight": 0.1},
            {"id": "E3", "type": "threat_intel", "source": "storage/evidence_store.py",
             "value": {"matched": True, "family": "DDoS"},
             "direction": "supports ATTACK", "weight": 0.15},
        ])

    def _new_incident(self):
        return self.store.save_incident({
            "final_decision": "ATTACK",
            "final_attack": "DDoS",
            "risk": {"score": 70, "level": "HIGH"},
            "playbook": self.playbook,
            "evidence_trail": [{"id": "E1"}, {"id": "E2"}, {"id": "E3"}],
            "response_workflow": {
                "state": "pending_analyst_approval",
                "tasks": [{"description": "Review the proposed response", "status": "proposed"}],
            },
        })

    def test_playbook_steps_use_existing_techniques_and_evidence_ids(self):
        sources = json.loads(Path("evidence/knowledge/authoritative_sources.json").read_text(encoding="utf-8"))["sources"]
        known_techniques = {item.get("technique_id") for item in sources if item.get("technique_id")}
        steps = [step for phase in self.playbook["phases"] for step in phase["steps"]]
        self.assertEqual({phase["name"] for phase in self.playbook["phases"]}, {"contain", "eradicate", "recover", "verify"})
        self.assertTrue(steps)
        for step in steps:
            self.assertIn(step["technique_id"], known_techniques)
            self.assertTrue(step["evidence_ids"])
            self.assertTrue(set(step["evidence_ids"]) <= {"E1", "E2", "E3"})

    def test_unknown_family_uses_generic_playbook_without_invented_technique(self):
        generic = build_playbook("Unlisted Family", [{
            "id": "E1", "type": "model", "source": "Random Forest",
            "value": {"attack_family": "Unlisted Family"},
            "direction": "supports ATTACK", "weight": None,
        }])
        self.assertTrue(generic["generic_playbook"])
        self.assertEqual(generic["playbook_label"], "generic playbook")
        self.assertIsNone(generic["technique_id"])
        steps = [step for phase in generic["phases"] for step in phase["steps"]]
        self.assertTrue(steps)
        self.assertTrue(all(step["evidence_ids"] == ["E1"] for step in steps))

    def test_empty_phase_explains_that_evidence_is_required(self):
        sparse_playbook = build_playbook("DDoS", [{
            "id": "E1", "type": "model", "source": "Random Forest",
            "value": {"attack_family": "DDoS"},
            "direction": "supports ATTACK", "weight": 0.3,
        }])
        phase = next(item for item in sparse_playbook["phases"] if item["name"] == "recover")
        self.assertEqual(phase["steps"], [])
        self.assertEqual(
            phase["empty_reason"],
            "Left empty on purpose: steps must be justified by evidence.",
        )

    def test_lifecycle_transitions_are_enforced_and_audited(self):
        incident_id = self._new_incident()
        self.assertEqual(self.store.get_incident(incident_id)["status"], "New")
        self.assertEqual(self.store.get_incident(incident_id)["allowed_transitions"], ["Triaged", "False positive"])
        self.store.validate_incident(incident_id, "Triaged", note="Analyst reviewed evidence.")
        with self.assertRaisesRegex(ValueError, "transition"):
            self.store.validate_incident(incident_id, "Resolved")
        self.assertEqual(self.store.get_incident(incident_id)["status"], "Triaged")
        self.store.validate_incident(incident_id, "Contained")
        self.store.validate_incident(incident_id, "Resolved")
        events = [event for event in self.store.audit_trail(20) if event["event_type"] == "incident.validated"]
        self.assertEqual(len(events), 3)
        self.assertTrue(all(event["details"].get("previous_state") for event in events))
        self.assertEqual(len(self.store.get_incident(incident_id)["payload"]["lifecycle_history"]), 3)

    def test_approval_log_and_report_are_labelled_simulation_only(self):
        incident_id = self._new_incident()
        self.store.validate_incident(incident_id, "Triaged")
        saved = self.store.approve_response(incident_id, "test analyst")
        payload = saved["payload"]
        log = payload["response_workflow"]["simulation_logs"][0]
        self.assertEqual(log["label"], "SIMULATION")
        self.assertEqual(log["mode"], "dry-run")
        self.assertFalse(log["executed"])
        self.assertTrue(log["steps"])
        self.assertTrue(all(step["status"] == "WOULD_RUN" for step in log["steps"]))

        report = render_markdown(payload, incident_id)
        self.assertIn("## Incident playbook", report)
        self.assertIn("## Incident timeline", report)
        self.assertIn("## SIMULATION dry-run log", report)
        self.assertIn("No commands were executed", report)
        self.assertIn("E1", report)


if __name__ == "__main__":
    unittest.main()
