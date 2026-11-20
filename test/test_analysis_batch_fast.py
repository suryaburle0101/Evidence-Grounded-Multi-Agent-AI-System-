import unittest
from pathlib import Path

import pandas as pd

from analysis_service import analyze_batch_fast, analyze_flow


class AnalysisBatchFastTests(unittest.TestCase):
    def test_50_flow_batch_matches_single_flow_decisions_risk_and_probabilities(self):
        source = pd.read_parquet(Path(__file__).resolve().parents[1] / "data" / "processed" / "end_to_end_sample.parquet")
        flows = pd.concat([source, source.iloc[:10]], ignore_index=True).to_dict(orient="records")
        expected = [analyze_flow(flow, persist=False, generate_llm=False) for flow in flows]
        actual = analyze_batch_fast(flows, persist=False, generate_llm=False)
        self.assertEqual(len(actual), 50)
        for index, (single, batched) in enumerate(zip(expected, actual)):
            with self.subTest(row=index):
                self.assertEqual(single["final_decision"], batched["final_decision"])
                self.assertEqual(single["risk"]["score"], batched["risk"]["score"])
                for model in ("random_forest", "xgboost"):
                    self.assertAlmostEqual(
                        single["detection"][model]["binary_attack_probability"],
                        batched["detection"][model]["binary_attack_probability"],
                        delta=1e-9,
                    )
                    self.assertAlmostEqual(
                        single["detection"][model]["binary_benign_probability"],
                        batched["detection"][model]["binary_benign_probability"],
                        delta=1e-9,
                    )


if __name__ == "__main__":
    unittest.main()
