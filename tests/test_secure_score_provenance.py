import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from collect_arg import defender_summary
from export_artifacts import write_pdf, write_xlsx
from generate_report import render_azure_intelligence


class SecureScoreProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.subscription = "synthetic-subscription-a"
        self.score_resource = "score-card-a"
        self.control_resource = "control-a"
        self.summary = defender_summary(
            [{
                "subscriptionId": self.subscription,
                "name": self.score_resource,
                "current": 12.5,
                "max": 20,
                "percentage": 0.625,
            }],
            [{
                "subscriptionId": self.subscription,
                "name": self.control_resource,
                "displayName": "Enable MFA",
                "current": 0,
                "max": 10,
                "unhealthy": "3",
                "healthy": "7",
            }],
        )
        self.data = {
            "metadata": {
                "customer_name": "Synthetic tenant",
                "profile": "synthetic",
                "run_id": "synthetic-run",
                "scope": {"subscriptions": 1},
            },
            "discovery": {
                "resource_map": {"nodes": [], "edges": [], "node_count": 0, "edge_count": 0},
                "resource_hygiene": {},
                "defender_secure_score": self.summary,
                "collection_log": [],
            },
            "findings": [],
            "controls": [],
        }

    def test_normalized_secure_score_keeps_resource_identity_and_scope(self):
        score = self.summary["scores"][0]
        control = self.summary["top_improvements"][0]
        self.assertEqual(score["score_resource"], self.score_resource)
        self.assertEqual(control["subscription"], self.subscription)
        self.assertEqual(control["control_resource"], self.control_resource)

    def test_html_pdf_and_workbook_preserve_secure_score_provenance(self):
        html = render_azure_intelligence(self.data)
        self.assertIn(self.subscription, html)
        self.assertIn(self.score_resource, html)
        self.assertIn(self.control_resource, html)

        with tempfile.TemporaryDirectory() as tmp:
            pdf_path = Path(tmp) / "assessment.pdf"
            xlsx_path = Path(tmp) / "assessment.xlsx"
            write_pdf(self.data, pdf_path)
            write_xlsx(self.data, xlsx_path)

            from pypdf import PdfReader
            import openpyxl

            pdf_text = "\n".join(page.extract_text() or "" for page in PdfReader(str(pdf_path)).pages)
            self.assertIn(self.subscription, pdf_text)
            self.assertIn(self.control_resource, pdf_text)

            workbook = openpyxl.load_workbook(xlsx_path, data_only=True)
            rows = list(workbook["Azure Intelligence"].iter_rows(values_only=True))
            flattened = {str(value) for row in rows for value in row if value is not None}
            self.assertIn(self.subscription, flattened)
            self.assertIn(self.score_resource, flattened)
            self.assertIn(self.control_resource, flattened)


if __name__ == "__main__":
    unittest.main()
