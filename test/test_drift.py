import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline.data_pipeline import FEATURES
from pipeline.drift import assess_batch_drift

BASE = {
    "features": list(FEATURES), "lo": [0.0] * len(FEATURES), "hi": [1.0] * len(FEATURES),
    "per_flow_threshold": 0.1, "caution_share": 0.25, "warning_share": 0.5,
}


def flows(value, count):
    return [{name: value for name in FEATURES} for _ in range(count)]


class DriftTests(unittest.TestCase):
    def test_in_range_batch_is_ok(self):
        result = assess_batch_drift(flows(0.5, 4), BASE)
        self.assertEqual(result["status"], "ok")

    def test_out_of_range_batch_warns(self):
        result = assess_batch_drift(flows(100.0, 4), BASE)
        self.assertEqual(result["status"], "warning")
        self.assertTrue(result["top_out_of_range_features"])

    def test_quarter_unfamiliar_is_caution(self):
        result = assess_batch_drift(flows(0.5, 3) + flows(100.0, 1), BASE)
        self.assertEqual(result["status"], "caution")

    def test_missing_features_report_unavailable(self):
        result = assess_batch_drift([{"unrelated": 1}], BASE)
        self.assertEqual(result["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
