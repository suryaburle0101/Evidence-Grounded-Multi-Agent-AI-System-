import unittest

from reporting.incident_report import render_markdown


class IncidentReportExplanationTests(unittest.TestCase):
    def test_report_renders_checked_shap_contributions(self):
        report = render_markdown({
            "final_decision": "REVIEW",
            "final_attack": "DDoS",
            "pipeline_completed": True,
            "detection": {"random_forest": {"attack_probability_explanation": {
                "status": "available", "baseline_value": 0.1, "model_output": 0.6,
                "additivity_absolute_error": 0.0,
                "top_features": [{"feature": "SYN Flag Count", "value": 4,
                                  "contribution": 0.5, "direction": "raises attack score"}],
            }}},
        })
        self.assertIn("## Model feature contributions", report)
        self.assertIn("SYN Flag Count", report)
        self.assertIn("not causal proof", report)


if __name__ == "__main__":
    unittest.main()
