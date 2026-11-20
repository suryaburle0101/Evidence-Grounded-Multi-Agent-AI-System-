import tempfile
import unittest
import zipfile
from pathlib import Path

from pipeline.kaggle_acquisition import _safe_extract


class KaggleAcquisitionTests(unittest.TestCase):
    def test_extracts_dataset_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "data.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("dataset/flows.csv", "Label,Feature\nBenign,1\n")
            destination = root / "out"
            destination.mkdir()
            files = _safe_extract(archive, destination)
            self.assertEqual(files, ["dataset/flows.csv"])
            self.assertTrue((destination / "dataset" / "flows.csv").is_file())

    def test_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "bad.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("../outside.txt", "bad")
            destination = root / "out"
            destination.mkdir()
            with self.assertRaises(ValueError):
                _safe_extract(archive, destination)
            self.assertFalse((root / "outside.txt").exists())


if __name__ == "__main__":
    unittest.main()
