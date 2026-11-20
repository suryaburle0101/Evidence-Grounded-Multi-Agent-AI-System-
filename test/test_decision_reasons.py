import unittest
from correlation.decision_agent import DecisionAgent


class DecisionReasonTests(unittest.TestCase):
    def test_benign_class_with_high_attack_score_explains_disagreement(self):
        detection = {
            "detection_state": "ATTACK",
            "model_agreement": True,
            "predicted_attack": "Benign",
            "random_forest": {"attack_family": "Benign", "confidence": 0.99},
            "xgboost": {"attack_family": "Benign", "confidence": 0.95},
        }
        investigation = {
            "severity": "HIGH",
            "rf_attack_probability": 1.0,
            "xgboost_attack_probability": 0.983,
            "average_attack_probability": 0.992,
        }
        evidence = {"evidence_found": False}
        result = DecisionAgent().analyze(detection, investigation, evidence)
        text = " ".join(str(r) for r in result["correlation_reasons"])
        self.assertIn("disagree", text)
        self.assertNotIn("high prediction confidence", text)


if __name__ == "__main__":
    unittest.main()

