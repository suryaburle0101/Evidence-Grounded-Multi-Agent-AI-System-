import json
import re
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

import agents.orchestrator as orchestrator_module
from agents.orchestrator import orchestrator
from reporting.incident_report import write_report
from pipeline.evidence_trail import _cite_reason


class EvidenceTrailTests(unittest.TestCase):
    def _analyze_with_stubbed_components(self):
        detection = {
            "agent": "Detection Agent",
            "detection_state": "ATTACK_DETECTED",
            "model_agreement": True,
            "predicted_attack": "DDoS",
            "random_forest": {
                "model": "random_forest",
                "attack_family": "DDoS",
                "binary_prediction": 1,
                "binary_attack_probability": 0.90,
                "binary_benign_probability": 0.10,
                "confidence": 0.95,
            },
            "xgboost": {
                "model": "xgboost",
                "attack_family": "DDoS",
                "binary_prediction": 1,
                "binary_attack_probability": 0.92,
                "binary_benign_probability": 0.08,
                "confidence": 0.93,
            },
        }
        investigation = {
            "finding": "ATTACK_INDICATED",
            "severity": "HIGH",
            "investigation_required": True,
            "random_forest_attack_probability": 0.90,
            "xgboost_attack_probability": 0.92,
            "random_forest_benign_probability": 0.10,
            "xgboost_benign_probability": 0.08,
            "average_attack_probability": 0.91,
            "probability_difference": 0.02,
        }
        evidence = {
            "evidence_found": True,
            "attack": "DDoS",
            "source_name": "MITRE ATT&CK",
            "technique_id": "T1498",
            "technique_name": "Network Denial of Service",
            "flow_evidence_score": 0.75,
            "flow_evidence_level": "high",
            "flow_evidence_triggered": False,
        }
        rare = {
            "agent": "Rare Family Detector",
            "available": True,
            "any_triggered": True,
            "top_family": "Heartbleed",
            "top_probability": 0.81,
            "scores": {"Heartbleed": 0.81, "Infiltration": 0.0},
            "thresholds": {"Heartbleed": 0.05, "Infiltration": 0.05},
            "triggered": {"Heartbleed": True, "Infiltration": False},
        }
        intel = {
            "available": True,
            "matched": True,
            "match_count": 1,
            "max_confidence": 0.95,
            "family": "DDoS",
            "matches": [{"indicator_type": "ip", "indicator_value": "203.0.113.4"}],
        }

        stack = ExitStack()
        stack.enter_context(patch.object(orchestrator_module.detection_agent, "analyze", return_value=detection))
        stack.enter_context(patch.object(orchestrator_module.rare_family_detector, "analyze", return_value=rare))
        stack.enter_context(patch.object(orchestrator_module.investigation_agent, "analyze", return_value=investigation))
        stack.enter_context(patch.object(orchestrator_module.evidence_agent, "analyze", return_value=evidence))
        stack.enter_context(patch.object(orchestrator_module, "analyze_threat_intel", return_value=intel))
        stack.enter_context(patch.object(orchestrator_module.local_rag, "analyze", return_value={"status": "ok"}))
        stack.enter_context(patch.object(orchestrator_module.risk_analyzer, "analyze", return_value={"score": 80.0, "level": "HIGH"}))
        stack.enter_context(patch.object(orchestrator_module.response_agent, "analyze", return_value={}))
        stack.enter_context(patch.object(orchestrator_module, "build_workflow", return_value={}))
        return stack, orchestrator.analyze({"Flow Duration": 12})

    def test_pipeline_result_has_cited_evidence_trail_and_reports_include_it(self):
        stack, result = self._analyze_with_stubbed_components()
        stack.close()

        trail = result["evidence_trail"]
        ids = {item["id"] for item in trail}
        self.assertTrue(ids)
        self.assertEqual("ATTACK", result["final_decision"])
        self.assertEqual(result["decision"]["evidence_trail"], trail)
        self.assertEqual(
            {item["type"] for item in trail},
            {"model", "decision", "investigation", "rare_family", "flow_evidence", "threat_intel", "reference_doc"},
        )
        allowed_types = {"model", "decision", "investigation", "rare_family", "flow_evidence", "threat_intel", "reference_doc"}
        allowed_directions = {"supports ATTACK", "supports BENIGN", "neutral"}
        self.assertEqual([item["id"] for item in trail], [f"E{i}" for i in range(1, len(trail) + 1)])
        for item in trail:
            self.assertEqual(
                set(item), {"id", "type", "source", "value", "direction", "weight"}
            )
            self.assertIn(item["type"], allowed_types)
            self.assertTrue(item["source"])
            self.assertIn(item["direction"], allowed_directions)
            self.assertTrue(item["weight"] is None or isinstance(item["weight"], (int, float)))
        decision_item = next(item for item in trail if item["id"] == "E3")
        investigation_item = next(item for item in trail if item["id"] == "E4")
        self.assertEqual(decision_item["type"], "decision")
        self.assertEqual(investigation_item["type"], "investigation")
        self.assertEqual(investigation_item["value"], {"finding": "ATTACK_INDICATED", "severity": "HIGH"})
        for reason in result["decision"]["correlation_reasons"]:
            for sentence in re.split(r"(?<=[.!?])\s+", reason.strip()):
                cited = set(re.findall(r"\[(E\d+)\]", sentence))
                self.assertTrue(cited, sentence)
                self.assertTrue(cited <= ids, sentence)

        with tempfile.TemporaryDirectory() as temp_dir:
            report_paths = write_report(result, temp_dir, "trail-test")
            markdown = Path(report_paths["markdown"]).read_text(encoding="utf-8")
            json_result = json.loads(Path(report_paths["json"]).read_text(encoding="utf-8"))

        self.assertIn("## Evidence trail", markdown)
        self.assertIn("| ID | Type | Source | Value | Direction | Weight |", markdown)
        self.assertIn("[E", markdown)
        self.assertEqual(json_result["evidence_trail"], trail)
        self.assertEqual(json_result["decision"]["correlation_reasons"], result["decision"]["correlation_reasons"])

    def test_each_sentence_in_a_multi_sentence_reason_gets_a_valid_citation(self):
        reason = _cite_reason(
            "The first signal supports ATTACK. A second signal adds context!",
            ["E1", "E2"],
        )
        sentences = re.split(r"(?<=[.!?])\s+", reason.strip())
        self.assertEqual(len(sentences), 2)
        for sentence in sentences:
            self.assertTrue(set(re.findall(r"\[(E\d+)\]", sentence)) <= {"E1", "E2"})
            self.assertTrue(re.search(r"\[E\d+\]", sentence), sentence)

if __name__ == "__main__":
    unittest.main()
