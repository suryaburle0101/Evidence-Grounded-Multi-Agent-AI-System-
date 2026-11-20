import json
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

import pandas as pd

import agents.orchestrator as orchestrator_module
from analysis_service import analyze_flow
from agents.orchestrator import orchestrator
from detection.model_predictor import prepare_input


class RareFamilyOrchestratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        schema_path = Path(__file__).resolve().parents[1] / "pipeline" / "feature_schema.json"
        cls.features = json.loads(schema_path.read_text(encoding="utf-8"))["features"]

    def _stub_pipeline_agents(self, stack):
        stack.enter_context(patch.object(
            orchestrator_module.detection_agent,
            "analyze",
            return_value={"random_forest": {}, "xgboost": {}},
        ))
        stack.enter_context(patch.object(
            orchestrator_module.investigation_agent, "analyze", return_value={}
        ))
        stack.enter_context(patch.object(
            orchestrator_module.evidence_agent, "analyze", return_value={}
        ))
        stack.enter_context(patch.object(
            orchestrator_module, "analyze_threat_intel", return_value={}
        ))
        stack.enter_context(patch.object(
            orchestrator_module.decision_agent,
            "analyze",
            return_value={"final_decision": "BENIGN", "final_attack": "Benign"},
        ))
        stack.enter_context(patch.object(
            orchestrator_module.local_rag, "analyze", return_value={"status": "ok"}
        ))
        stack.enter_context(patch.object(
            orchestrator_module.risk_analyzer, "analyze", return_value={"level": "LOW"}
        ))
        stack.enter_context(patch.object(
            orchestrator_module.response_agent, "analyze", return_value={}
        ))
        stack.enter_context(patch.object(
            orchestrator_module, "build_workflow", return_value={}
        ))

    def test_dict_flow_runs_rare_family_stage_and_matches_cli_series(self):
        flow = {feature: 0 for feature in self.features}
        with ExitStack() as stack:
            self._stub_pipeline_agents(stack)
            direct_orchestrator_result = orchestrator.analyze(flow)
            prepare_input(flow)
            api_path_result = analyze_flow(
                flow, source="api", persist=False
            )
            cli_path_result = analyze_flow(
                pd.Series(flow), source="cli", persist=False
            )

        self.assertTrue(direct_orchestrator_result["pipeline_completed"])
        self.assertTrue(direct_orchestrator_result["rare_family"]["available"])
        self.assertNotIn("error", direct_orchestrator_result["rare_family"])
        rare_result = api_path_result["rare_family"]
        self.assertTrue(rare_result["available"])
        self.assertNotIn("error", rare_result)
        self.assertEqual(rare_result, cli_path_result["rare_family"])
        self.assertTrue(cli_path_result["pipeline_completed"])


if __name__ == "__main__":
    unittest.main()
