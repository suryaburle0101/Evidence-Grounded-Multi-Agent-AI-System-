import unittest
import tempfile
from pathlib import Path

import numpy as np

from evaluation.calibration_study import (
    _plot_reliability,
    apply_calibrator,
    expected_calibration_error,
    fit_calibrators,
    reliability_curve_data,
    score_probabilities,
    threshold_for_benign_fpr,
)


class CalibrationStudyTests(unittest.TestCase):
    def setUp(self):
        self.y = np.array([0, 0, 0, 0, 1, 1, 1, 1])
        self.p = np.array([0.05, 0.10, 0.35, 0.45, 0.55, 0.65, 0.90, 0.95])

    def test_fits_both_calibrators_and_returns_probabilities(self):
        fitted = fit_calibrators(self.y, self.p)
        self.assertEqual(set(fitted), {"platt", "isotonic"})
        for name, calibrator in fitted.items():
            output = apply_calibrator(calibrator, name, self.p)
            self.assertEqual(output.shape, self.p.shape)
            self.assertTrue(np.all((output >= 0) & (output <= 1)))

    def test_threshold_uses_only_benign_validation_scores(self):
        threshold, observed = threshold_for_benign_fpr(self.y, self.p, 0.01)
        self.assertGreaterEqual(threshold, self.p[self.y == 0].max())
        self.assertLessEqual(observed, 0.01)
        result = score_probabilities(self.y, self.p, threshold)
        self.assertIn("brier_score", result)
        self.assertIn("recall_at_validation_threshold", result)

    def test_reliability_curve_has_ten_bins_and_ece_is_bounded(self):
        curve = reliability_curve_data(self.y, self.p)
        self.assertEqual(len(curve), 10)
        self.assertEqual(sum(row["count"] for row in curve), len(self.y))
        ece = expected_calibration_error(self.y, self.p)
        self.assertGreaterEqual(ece, 0.0)
        self.assertLessEqual(ece, 1.0)

    def test_rejects_single_class_calibration_validation(self):
        with self.assertRaises(ValueError):
            fit_calibrators(np.zeros(4, dtype=int), np.array([0.1, 0.2, 0.3, 0.4]))

    def test_reliability_plot_is_a_png(self):
        curve = reliability_curve_data(self.y, self.p)
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / "curve.png"
            _plot_reliability({"raw": curve, "platt": curve, "isotonic": curve},
                              destination, "synthetic test")
            self.assertEqual(destination.read_bytes()[:8], b"\x89PNG\r\n\x1a\n")


if __name__ == "__main__":
    unittest.main()
