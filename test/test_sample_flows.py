import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd
from fastapi.testclient import TestClient

import api


class BundledSampleFallbackTests(unittest.TestCase):
    def test_attack_filter_uses_processed_sample_when_raw_capture_is_absent(self):
        with tempfile.TemporaryDirectory(prefix="cyber-demo-sample-") as temp_dir:
            root = Path(temp_dir)
            sample_dir = root / "data" / "processed"
            sample_dir.mkdir(parents=True)
            pd.DataFrame(
                {
                    "Label": ["Benign", "DDoS", "Infiltration"],
                    "Flow Duration": [1, 2, 3],
                    "Protocol": [6, 17, 6],
                }
            ).to_parquet(sample_dir / "end_to_end_sample.parquet", index=False)

            with patch.object(api, "__file__", str(root / "api.py")):
                with TestClient(api.app) as client:
                    response = client.get(
                        "/api/sample-flows?limit=10&attack_type=ddos"
                    )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["source"], "bundled demonstration sample")
        self.assertEqual(payload["rows_available"], 1)
        self.assertEqual(payload["rows_selected"], 1)
        self.assertEqual(payload["flows"], [{"Flow Duration": 2, "Protocol": 17}])


if __name__ == "__main__":
    unittest.main()
