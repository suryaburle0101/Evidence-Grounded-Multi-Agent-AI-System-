import unittest
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from evaluation.ablation_study import (
    _bootstrap_binary_ci,
    _candidate_model_path,
    _candidate_prediction,
    _shared_candidate_features,
)
from evaluation.tri_dataset_benchmark import FEATURES


class AblationLodoAdapterTests(unittest.TestCase):
    def test_confidence_interval_resamples_capture_blocks(self):
        low, high = _bootstrap_binary_ci(
            np.array([False, False, True, True]), 42,
            np.array(["capture-a", "capture-a", "capture-b", "capture-b"]),
        )
        self.assertEqual(low, 0.0)
        self.assertEqual(high, 1.0)

    def test_candidate_path_matches_lodo_2018_filename(self):
        path = _candidate_model_path(
            Path("models/experimental/lodo"),
            "randomforest", "CSE-CIC-IDS2018", 42,
        )
        self.assertEqual(
            path.as_posix(),
            "models/experimental/lodo/randomforest_except_CSE_CIC_IDS2018_seed_42.joblib",
        )

    def test_shared_mapping_matches_lodo_feature_order(self):
        frame = pd.DataFrame({
            "Protocol": [6, 17, 1],
            "Flow Duration": [1_000_000, 2_000_000, 500_000],
            "Total Fwd Packets": [2, 3, 1],
            "Total Backward Packets": [1, 2, 1],
            "Fwd Packets Length Total": [100, 300, 40],
            "Bwd Packets Length Total": [50, 200, 10],
        })
        mapped = _shared_candidate_features(frame, list(frame.columns))
        self.assertEqual(list(mapped.columns), FEATURES)
        self.assertEqual(mapped.shape, (3, 11))
        self.assertTrue(np.isfinite(mapped.to_numpy()).all())

    def test_candidate_output_has_detection_agent_probability_fields(self):
        features = pd.DataFrame(np.arange(66, dtype=float).reshape(6, 11), columns=FEATURES)
        labels = np.array([0, 1, 0, 1, 0, 1])
        model = RandomForestClassifier(n_estimators=3, random_state=42).fit(features, labels)
        rows = _candidate_prediction(model, features.iloc[:2], "random_forest")
        self.assertEqual(len(rows), 2)
        for result in rows:
            self.assertIn(result["attack_family"], {"Benign", "Attack"})
            self.assertAlmostEqual(result["binary_attack_probability"] + result["binary_benign_probability"], 1.0)
            self.assertIn("binary_prediction", result)


if __name__ == "__main__":
    unittest.main()
