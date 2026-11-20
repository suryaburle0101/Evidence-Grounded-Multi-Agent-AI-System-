import unittest

from pipeline.flow_metadata import extract_flow_context, resolve_metadata_columns
from pipeline.data_pipeline import FEATURES, validate_frame
import pandas as pd


class FlowMetadataTests(unittest.TestCase):
    def test_resolves_aliases_and_keeps_values_outside_model_schema(self):
        row = {
            "src_ip": "10.2.0.8", "Destination Port": 443,
            "proto": "TCP", "stime": "2026-10-08T10:00:00Z",
            "Flow Duration": 42,
        }
        context = extract_flow_context(row)
        self.assertEqual(context["source_ip"], "10.2.0.8")
        self.assertEqual(context["destination_port"], 443)
        self.assertEqual(context["protocol"], "TCP")
        self.assertEqual(context["timestamp"], "2026-10-08T10:00:00Z")
        self.assertNotIn("Flow Duration", context)

    def test_rejects_empty_values_and_bounds_strings(self):
        context = extract_flow_context({"source_host": " " , "source_ip": "x" * 300})
        self.assertNotIn("source_host", context)
        self.assertEqual(len(context["source_ip"]), 255)

    def test_column_resolver_is_case_and_separator_insensitive(self):
        self.assertEqual(resolve_metadata_columns(["Source-IP"])["source_ip"], "Source-IP")

    def test_schema_validator_accepts_valid_rows_and_rejects_nonfinite_values(self):
        frame = pd.DataFrame([{name: 1.0 for name in FEATURES}])
        self.assertTrue(validate_frame(frame)["valid"])
        frame.loc[0, FEATURES[0]] = float("inf")
        result = validate_frame(frame)
        self.assertFalse(result["valid"])
        self.assertEqual(result["invalid_rows"], 1)

    def test_schema_validator_reports_missing_features_and_required_labels(self):
        result = validate_frame(pd.DataFrame({FEATURES[0]: [1]}), require_label=True)
        self.assertFalse(result["valid"])
        self.assertIn(FEATURES[1], result["missing_features"])
        self.assertTrue(any("Label/Attack/Class" in error for error in result["errors"]))


if __name__ == "__main__":
    unittest.main()
