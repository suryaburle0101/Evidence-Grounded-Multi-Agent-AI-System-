import unittest

import numpy as np
import pandas as pd

from evaluation.tri_dataset_benchmark import (
    FEATURES, _build_shared_features, _exclude_feature_overlap, _feature_drift, _metrics, _protocol_flags,
)
from correlation.decision_agent import _near_decision_threshold


class TriDatasetBenchmarkTests(unittest.TestCase):
    def test_protocol_flags_recognize_numeric_and_named_protocols(self):
        flags = _protocol_flags(pd.Series([6, "UDP", 1, "unknown"]))
        self.assertEqual(flags["protocol_tcp"].tolist(), [1.0, 0.0, 0.0, 0.0])
        self.assertEqual(flags["protocol_udp"].tolist(), [0.0, 1.0, 0.0, 0.0])
        self.assertEqual(flags["protocol_icmp"].tolist(), [0.0, 0.0, 1.0, 0.0])

    def test_shared_feature_rates_and_duration_unit_conversion(self):
        source = pd.DataFrame({"proto": [6], "dur": [2_000_000], "sp": [4],
                               "dp": [2], "sb": [400], "db": [200]})
        features = _build_shared_features(source, protocol="proto", duration="dur",
            duration_scale=1_000_000, fwd_packets="sp", bwd_packets="dp",
            fwd_bytes="sb", bwd_bytes="db")
        self.assertEqual(float(features.loc[0, "duration_s"]), 2.0)
        self.assertEqual(float(features.loc[0, "packets_per_second"]), 3.0)
        self.assertEqual(len([name for name in FEATURES if name in features]), len(FEATURES))

    def test_metrics_and_drift_are_finite(self):
        metrics = _metrics(np.array([0, 0, 1, 1]), np.array([.1, .2, .8, .9]), .5)
        self.assertEqual(metrics["confusion_matrix_tn_fp_fn_tp"], [2, 0, 0, 2])
        train = pd.DataFrame({name: np.linspace(0, 1, 100) for name in FEATURES})
        test = train.copy()
        test[FEATURES[0]] = test[FEATURES[0]] + 10
        drift = _feature_drift(train, test)
        self.assertTrue(np.isfinite(drift["mean_psi"]))
        self.assertEqual(drift["top_shifted_features"][0]["feature"], FEATURES[0])

    def test_raw_scores_near_boundary_are_marked_for_review(self):
        self.assertTrue(_near_decision_threshold(0.50))
        self.assertTrue(_near_decision_threshold(0.46))
        self.assertFalse(_near_decision_threshold(0.40))
        self.assertFalse(_near_decision_threshold(0.61))

    def test_later_partition_excludes_duplicate_feature_vectors(self):
        prior = pd.DataFrame({name: [0.0, 1.0] for name in FEATURES})
        later = pd.DataFrame({name: [1.0, 2.0] for name in FEATURES})
        unique, removed = _exclude_feature_overlap(later, prior)
        self.assertEqual(removed, 1)
        self.assertEqual(len(unique), 1)


if __name__ == "__main__":
    unittest.main()
