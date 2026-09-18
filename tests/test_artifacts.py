import json
import sys
import unittest
import tempfile
from html.parser import HTMLParser
from pathlib import Path

from openpyxl import load_workbook
from pptx import Presentation

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ai_payload import build
from validate_artifacts import validate, validate_payload


class ArtifactTests(unittest.TestCase):
    def test_html_is_self_contained(self):
        html = (ROOT / "dist/assessment-demo.html").read_text(encoding="utf-8")
        HTMLParser().feed(html)
        self.assertNotIn("<script src=", html)
        self.assertNotIn("http://", html)
        self.assertNotIn("https://", html)
        self.assertIn("FinOps e ciclo de vida", html)
        self.assertIn("Visão visual das políticas", html)
        self.assertIn("ca-card", html)
        self.assertIn("Exclusões identificadas", html)
        self.assertIn("Prioridade combina risco", html)
        self.assertIn("Custo potencial", html)

    def test_spreadsheets_and_deck_open(self):
        workbook = load_workbook(ROOT / "dist/assessment-action-plan.xlsx", read_only=True)
        self.assertIn("Plano de ação", workbook.sheetnames)
        self.assertGreaterEqual(workbook["Plano de ação"].max_row, 2)
        workbook.close()
        deck = Presentation(ROOT / "dist/assessment-executive-summary.pptx")
        self.assertEqual(len(deck.slides), 2)

    def test_ai_payload_contains_aggregates_only(self):
        source = json.loads((ROOT / "mock/assessment.json").read_text(encoding="utf-8"))
        serialized = json.dumps(build(source), ensure_ascii=False)
        for forbidden in ("contoso.example", "Ana Souza", "Bruno Lima", "vm-prd-web-01", "resource_id"):
            self.assertNotIn(forbidden, serialized)

    def test_artifact_validator_accepts_generated_package(self):
        result = validate(ROOT / "dist", ROOT / "runtime/ai-payload.json")
        self.assertEqual(result["status"], "valid", result["errors"])
        self.assertTrue(result["read_only"])

    def test_ai_payload_validator_rejects_identity_fields(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", encoding="utf-8") as handle:
            json.dump({"user_principal_name": "person@example.com"}, handle)
            handle.flush()
            path = Path(handle.name)
            self.assertTrue(validate_payload(path))


if __name__ == "__main__":
    unittest.main()
