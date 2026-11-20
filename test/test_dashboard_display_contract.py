from pathlib import Path
import unittest


APP_JS = Path(__file__).resolve().parents[1] / "frontend" / "app.js"
INDEX_HTML = APP_JS.with_name("index.html")


class DashboardDisplayContractTests(unittest.TestCase):
    def test_shap_chart_uses_unique_labels_and_draws_both_directions(self):
        source = APP_JS.read_text(encoding="utf-8")
        self.assertIn("function uniqueShapFeatureLabels(features)", source)
        self.assertIn("const shapLabels = uniqueShapFeatureLabels(shapFeatures)", source)
        self.assertIn("contribution < 0 ? `<i style=\"width:${width}%\"></i>` : ''", source)
        self.assertIn("contribution > 0 ? `<i style=\"width:${width}%\"></i>` : ''", source)
        self.assertIn("'Fwd Packet Length Std': 'Variation in outgoing packet sizes'", source)
        self.assertIn("'Bwd Packet Length Std': 'Variation in returning packet sizes'", source)
        self.assertIn("'Packet Length Variance': 'Spread in packet sizes'", source)
        self.assertIn("'Avg Packet Size': 'Average packet size across the flow'", source)

    def test_empty_playbook_phase_displays_evidence_requirement(self):
        source = APP_JS.read_text(encoding="utf-8")
        self.assertIn("Left empty on purpose: steps must be justified by evidence.", source)

    def test_dashboard_copy_and_download_link_hide_dataset_name(self):
        source = INDEX_HTML.read_text(encoding="utf-8").casefold()
        app_source = APP_JS.read_text(encoding="utf-8").casefold()
        self.assertNotIn("cicids", source)
        self.assertNotIn("cicids", app_source)
        self.assertIn('href="/flow-template.csv"', source)


if __name__ == "__main__":
    unittest.main()
