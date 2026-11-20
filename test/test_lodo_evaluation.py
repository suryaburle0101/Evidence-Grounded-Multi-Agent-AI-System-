import unittest

import numpy as np
import pandas as pd

from evaluation.lodo_evaluation import (
    block_bootstrap_ci,
    metric_row,
    remove_train_test_duplicates,
    stratified_cap,
)
from evaluation.tri_dataset_benchmark import FEATURES


def sample_frame(rows, groups=None):
    frame = pd.DataFrame({name: np.arange(rows, dtype=float) for name in FEATURES})
    frame["target"] = np.array([i % 2 for i in range(rows)], dtype=np.int8)
    frame["capture_group"] = groups or ["capture-a"] * rows
    return frame


class LodoEvaluationTests(unittest.TestCase):
    def test_stratified_cap_is_deterministic_and_bounded(self):
        frame = sample_frame(40)
        first = stratified_cap(frame, 12, 42)
        second = stratified_cap(frame, 12, 42)
        self.assertEqual(len(first), 12)
        self.assertEqual(first.target.value_counts().to_dict(), {0: 6, 1: 6})
        pd.testing.assert_frame_equal(first, second)

    def test_shared_train_test_vectors_are_removed_from_training(self):
        train = sample_frame(6)
        test = train.iloc[[1, 4]].copy()
        kept, removed = remove_train_test_duplicates(train, test)
        self.assertEqual(removed, 2)
        self.assertEqual(len(kept), 4)

    def test_metrics_and_capture_block_interval(self):
        frame = sample_frame(8, ["a"] * 4 + ["b"] * 4)
        probs = np.array([0.1, 0.9, 0.1, 0.9, 0.1, 0.9, 0.1, 0.9])
        metrics = metric_row(frame.target, probs)
        self.assertEqual(metrics["recall"], 1.0)
        self.assertEqual(metrics["benign_false_alarm_rate"], 0.0)
        ci = block_bootstrap_ci(frame, probs, "recall", 42, draws=20)
        self.assertEqual(ci["blocks"], 2)
        self.assertIsNotNone(ci["low"])

    def test_bootstrap_reports_too_few_capture_blocks(self):
        frame = sample_frame(4)
        ci = block_bootstrap_ci(frame, np.full(4, 0.5), "recall", 42, draws=10)
        self.assertIsNone(ci["low"])
        self.assertIn("fewer than two", ci["limitation"])


if __name__ == "__main__":
    unittest.main()
