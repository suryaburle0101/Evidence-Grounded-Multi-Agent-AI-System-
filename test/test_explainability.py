import unittest

import pandas as pd

from detection.explainability import explain_attack_probability
from detection.model_predictor import FEATURE_NAMES


class ProductionExplainabilityTests(unittest.TestCase):
    def test_saved_random_forest_has_additivity_checked_shap_values(self):
        row = pd.DataFrame([{name: 0.0 for name in FEATURE_NAMES}])
        result = explain_attack_probability(row)
        self.assertEqual(result["status"], "available", result)
        self.assertLessEqual(result["additivity_absolute_error"], 1e-4)
        self.assertEqual(len(result["top_features"]), 8)
        self.assertTrue(all("contribution" in item for item in result["top_features"]))


if __name__ == "__main__":
    unittest.main()
