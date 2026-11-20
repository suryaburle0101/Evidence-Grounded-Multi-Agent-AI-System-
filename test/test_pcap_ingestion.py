import tempfile
import unittest
from pathlib import Path

from pipeline.pcap_ingestion import expand_command, parse_command_template


class PcapIngestionTests(unittest.TestCase):
    def test_requires_both_safe_path_placeholders(self):
        with self.assertRaises(ValueError):
            parse_command_template('["extractor", "{pcap}"]')

    def test_expands_paths_as_single_arguments(self):
        with tempfile.TemporaryDirectory() as tmp:
            pcap = Path(tmp) / "with spaces.pcap"
            output = Path(tmp) / "output dir"
            args = expand_command(["extractor", "--input", "{pcap}", "--out", "{output_dir}"], pcap, output)
            self.assertEqual(args[2], str(pcap.resolve()))
            self.assertEqual(args[4], str(output.resolve()))


if __name__ == "__main__":
    unittest.main()
