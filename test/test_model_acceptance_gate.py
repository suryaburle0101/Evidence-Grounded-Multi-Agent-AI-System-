import unittest

from evaluation.model_acceptance_gate import evaluate


class ModelAcceptanceGateTests(unittest.TestCase):
    def test_fails_if_any_family_misses_recall_target_without_promotion(self):
        report = {"dataset": "sample", "out_of_fold_per_family": {
            "candidate": {
                "Benign": {"false_positive_rate": 0.005},
                "DoS": {"recall": 0.95},
                "Infiltration": {"recall": 0.10},
            }
        }}
        result = evaluate(report)
        self.assertEqual(result["decision"], "IMPROVE")
        self.assertEqual(result["promotion"], "not_performed")


if __name__ == "__main__":
    unittest.main()
