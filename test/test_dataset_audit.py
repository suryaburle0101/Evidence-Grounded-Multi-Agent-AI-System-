import json
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from evaluation.dataset_audit import PROJECT_ROOT, load_production_features, run_audit


class DatasetAuditTests(unittest.TestCase):
    def test_streamed_capture_statistics_and_cross_dataset_feature_duplicates(self):
        features = load_production_features()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "raw"
            output = Path(temp) / "audit"
            cic = root / "CICIDS2017"
            cse = root / "CSE_CIC_IDS2018"
            cic.mkdir(parents=True)
            cse.mkdir(parents=True)
            unsw = root / "UNSW_NB15"
            unsw.mkdir(parents=True)

            base = {feature: float(index + 1) for index, feature in enumerate(features)}
            repeated = dict(base)
            nan_row = {feature: float(index + 2) for index, feature in enumerate(features)}
            nan_row[features[4]] = float("nan")
            inf_row = {feature: float(index + 3) for index, feature in enumerate(features)}
            inf_row[features[5]] = float("inf")
            csv_rows = []
            for values, label, stamp in (
                (base, "BENIGN", "2017-01-01T00:00:00Z"),
                (repeated, "BENIGN", "2017-01-01T00:00:00Z"),
                (nan_row, "DoS", "2017-01-02T00:00:00Z"),
                (inf_row, "Attack", "2017-01-03T00:00:00Z"),
            ):
                csv_rows.append({**values, "Label": label, "Timestamp": stamp})
            pd.DataFrame(csv_rows).to_csv(cic / "tiny.csv", index=False)

            other = {feature: float(index + 1) for index, feature in enumerate(features)}
            pd.DataFrame([{**other, "Label": "WebAttack"}]).to_parquet(cse / "tiny.parquet", index=False)
            unsw_columns = ["srcip", "sport", "dstip", "dsport", "proto", "Stime", "Ltime", "attack_cat", "Label"]
            pd.DataFrame({"Name": unsw_columns}).to_csv(unsw / "NUSW-NB15_features.csv", index=False)
            (unsw / "UNSW-NB15_1.csv").write_text(
                "192.0.2.1,1234,198.51.100.2,80,tcp,1421927414,1421927415,Normal,0\n"
                "192.0.2.3,2345,198.51.100.4,443,tcp,1421927416,1421927417,DoS,1\n",
                encoding="utf-8",
            )

            result = run_audit(root, output, batch_size=2, repo_root=PROJECT_ROOT)
            self.assertEqual(result["capture_count"], 3)
            self.assertEqual(result["complete_count"], 3)
            captures = {item["file"]: item for item in json.loads((output / "audit.json").read_text(encoding="utf-8"))["captures"]}
            cic_result = captures["CICIDS2017/tiny.csv"]
            self.assertEqual(cic_result["row_count"], 4)
            self.assertEqual(cic_result["label_column"], "Label")
            self.assertEqual(cic_result["label_counts"], {"BENIGN": 2, "DoS": 1, "Attack": 1})
            self.assertEqual(cic_result["production_features_present"], 77)
            self.assertEqual(cic_result["duplicate_row_count"], 1)
            self.assertAlmostEqual(cic_result["duplicate_row_rate"], 0.25)
            self.assertEqual(cic_result["rows_with_nan"], 1)
            self.assertEqual(cic_result["rows_with_inf"], 1)
            self.assertEqual(cic_result["rows_with_nan_or_inf"], 2)
            self.assertEqual(cic_result["date_min"], "2017-01-01T00:00:00+00:00")
            self.assertEqual(cic_result["date_max"], "2017-01-03T00:00:00+00:00")
            duplicate_pairs = json.loads((output / "audit.json").read_text(encoding="utf-8"))["cross_dataset_duplicate_feature_vectors"]
            self.assertEqual(len(duplicate_pairs), 1)
            self.assertEqual(duplicate_pairs[0]["unique_duplicate_feature_vectors"], 1)
            self.assertEqual(cic_result["used_for_active_training"], "unknown")
            self.assertIn("production_2017_source_check.json", cic_result["training_evidence"])
            cse_result = captures["CSE_CIC_IDS2018/tiny.parquet"]
            self.assertEqual(cse_result["used_for_active_training"], "no")
            self.assertIn("production_external_2018.json", cse_result["training_evidence"])
            unsw_result = captures["UNSW_NB15/UNSW-NB15_1.csv"]
            self.assertEqual(unsw_result["label_column"], "Label")
            self.assertEqual(unsw_result["row_count"], 2)
            self.assertEqual(unsw_result["date_column"], "Stime")
            self.assertEqual(unsw_result["used_for_active_training"], "unknown")
            self.assertTrue((output / "audit.csv").is_file())
            manifest = (output / "MANIFEST.md").read_text(encoding="utf-8")
            self.assertIn("CICIDS2017/tiny.csv", manifest)
            self.assertIn("unknown", manifest)

            # A repeated invocation resumes completed captures without recounting.
            resumed = run_audit(root, output, batch_size=2, repo_root=PROJECT_ROOT)
            self.assertEqual(resumed["complete_count"], 3)
            final_cic = next(item for item in json.loads((output / "audit.json").read_text(encoding="utf-8"))["captures"] if item["file"] == "CICIDS2017/tiny.csv")
            self.assertEqual(final_cic["row_count"], 4)


if __name__ == "__main__":
    unittest.main()
