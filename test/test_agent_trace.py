import re
import unittest
from unittest.mock import patch

import agents.orchestrator as orchestrator_module
from agents.orchestrator import orchestrator
from reporting.incident_report import render_markdown


class AgentTraceTests(unittest.TestCase):
    def test_failed_stage_is_unavailable_in_result_and_report_warning(self):
        with patch.object(
            orchestrator_module.detection_agent,
            "analyze",
            side_effect=ValueError("private failure detail"),
        ):
            result = orchestrator.analyze({"Flow Duration": 12})

        self.assertFalse(result["pipeline_completed"])
        trace = result["agent_trace"]
        self.assertEqual(len(trace), 1)
        failed = trace[0]
        self.assertEqual(failed["agent"], "Detection Agent")
        self.assertEqual(failed["status"], "unavailable")
        self.assertIsInstance(failed["duration_ms"], int)
        self.assertIn("Flow Duration", failed["input_summary"])
        self.assertNotIn("private failure detail", failed["output_summary"])

        report = render_markdown(result, "failed-stage")
        self.assertIn("**Warning:** One or more analysis stages were unavailable", report)
        self.assertIn("Detection Agent", report)
        self.assertIn("| Detection Agent |", report)

    def test_successful_stage_trace_has_required_fields_and_complete_status(self):
        with patch.object(
            orchestrator_module.detection_agent,
            "analyze",
            return_value={"agent": "Detection Agent", "detection_state": "BENIGN"},
        ), patch.object(
            orchestrator_module.rare_family_detector,
            "analyze",
            return_value={"available": True, "any_triggered": False},
        ), patch.object(
            orchestrator_module.investigation_agent,
            "analyze",
            side_effect=ValueError("stop after trace assertions"),
        ):
            result = orchestrator.analyze({"Flow Duration": 12})

        self.assertEqual([entry["status"] for entry in result["agent_trace"]], ["complete", "complete", "unavailable"])
        for entry in result["agent_trace"]:
            self.assertEqual(
                set(entry),
                {"agent", "role", "status", "duration_ms", "input_summary", "output_summary"},
            )
            self.assertTrue(re.fullmatch(r"\d+", str(entry["duration_ms"])))
            self.assertTrue(entry["input_summary"])
            self.assertTrue(entry["output_summary"])


if __name__ == "__main__":
    unittest.main()
