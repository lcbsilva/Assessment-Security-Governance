import json
import sys
import unittest
import tempfile
import subprocess
from html.parser import HTMLParser
from pathlib import Path

from openpyxl import load_workbook
from pptx import Presentation
from pypdf import PdfReader

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ai_payload import build
from validate_artifacts import validate, validate_payload


class ArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Gera fixtures temporárias para o teste ser independente de dist/.

        O pacote distribuído não precisa carregar artefatos antigos; o teste
        deve validar o pipeline atual em um checkout limpo.
        """
        cls._temporary = tempfile.TemporaryDirectory(prefix="assessment-artifacts-")
        cls.artifact_dir = Path(cls._temporary.name) / "dist"
        cls.artifact_dir.mkdir(parents=True, exist_ok=True)
        data = ROOT / "mock" / "assessment.json"
        subprocess.run([sys.executable, "src/generate_report.py", "--data", str(data), "--output", str(cls.artifact_dir / "assessment.html")], cwd=ROOT, check=True, capture_output=True, text=True)
        subprocess.run([sys.executable, "src/export_artifacts.py", "--data", str(data), "--output-dir", str(cls.artifact_dir)], cwd=ROOT, check=True, capture_output=True, text=True)
        cls.ai_payload = Path(cls._temporary.name) / "ai-payload.json"
        subprocess.run([sys.executable, "src/ai_payload.py", "--data", str(data), "--output", str(cls.ai_payload)], cwd=ROOT, check=True, capture_output=True, text=True)

    @classmethod
    def tearDownClass(cls):
        cls._temporary.cleanup()

    def test_html_is_self_contained(self):
        html = (self.artifact_dir / "assessment.html").read_text(encoding="utf-8")
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
        self.assertIn('data-view-target="executive"', html)
        self.assertIn('data-view-target="technical"', html)
        self.assertIn('data-view-target="full"', html)
        self.assertIn("risk-matrix", html)
        self.assertIn("top-coverage-banner", html)
        self.assertIn("Limites desta leitura", html)
        self.assertIn("Causa provável", html)
        self.assertIn("Próximo passo", html)

    def test_spreadsheets_and_deck_open(self):
        workbook = load_workbook(self.artifact_dir / "assessment-action-plan.xlsx", read_only=True)
        self.assertIn("Plano de ação", workbook.sheetnames)
        self.assertGreaterEqual(workbook["Plano de ação"].max_row, 2)
        workbook.close()
        deck = Presentation(self.artifact_dir / "assessment-executive-summary.pptx")
        self.assertEqual(len(deck.slides), 4)
        self.assertIn("Cobertura e limitações da execução", " ".join(shape.text for shape in deck.slides[3].shapes if shape.has_text_frame))
        brief = self.artifact_dir / "assessment-one-page-brief.pdf"
        self.assertTrue(brief.exists())
        self.assertEqual(len(PdfReader(str(brief)).pages), 1)

    def test_action_plan_contains_cross_domain_insight_rows(self):
        source = json.loads((ROOT / "mock/assessment.json").read_text(encoding="utf-8"))
        source.setdefault("discovery", {})["cross_domain_insights"] = [{"id": "I-TEST", "title": "Insight de governança", "severity": "high", "risk": 80, "priority": "P2", "suggested_owner": "Cloud Governance", "effort_band": "Médio"}]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "plan.xlsx"
            from export_artifacts import write_xlsx
            write_xlsx(source, path)
            workbook = load_workbook(path, read_only=True)
            rows = list(workbook["Plano de ação"].values)
            workbook.close()
        self.assertTrue(any(row[0] == "I-TEST" for row in rows[1:]))

    def test_executive_artifacts_use_engagement_metadata(self):
        source = json.loads((ROOT / "mock/assessment.json").read_text(encoding="utf-8"))
        source["metadata"].update({"customer_name": "Cliente Demo", "engagement_name": "Discovery Beta", "consultant_name": "Consultor SWO", "classification": "Confidencial"})
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            from export_artifacts import write_pptx, write_pdf
            write_pptx(source, output / "summary.pptx")
            write_pdf(source, output / "summary.pdf")
            deck = Presentation(output / "summary.pptx")
            deck_text = " ".join(shape.text for slide in deck.slides for shape in slide.shapes if hasattr(shape, "text"))
            from pypdf import PdfReader
            pdf_text = "\n".join(page.extract_text() or "" for page in PdfReader(output / "summary.pdf").pages)
        self.assertIn("Discovery Beta", deck_text)
        self.assertIn("Cliente Demo", deck_text)
        self.assertIn("Cliente Demo", pdf_text)

    def test_ai_payload_contains_aggregates_only(self):
        source = json.loads((ROOT / "mock/assessment.json").read_text(encoding="utf-8"))
        serialized = json.dumps(build(source), ensure_ascii=False)
        for forbidden in ("contoso.example", "Ana Souza", "Bruno Lima", "vm-prd-web-01", "resource_id"):
            self.assertNotIn(forbidden, serialized)

    def test_ai_payload_contains_safe_azure_posture_aggregates(self):
        source = json.loads((ROOT / "mock/assessment.json").read_text(encoding="utf-8"))
        source.setdefault("discovery", {})["security_posture_summary"] = {
            "resources": 20,
            "resources_with_explicit_signals": 3,
            "signals_total": 4,
            "by_signal": [{"signal": "Storage: blob público habilitado", "resources": 2}],
        }
        result = build(source)
        self.assertEqual(result["azure_security_posture"]["resources_with_explicit_signals"], 3)
        self.assertEqual(result["azure_security_posture"]["signals"][0]["resources"], 2)
        self.assertNotIn("resource_id", json.dumps(result, ensure_ascii=False))

    def test_ai_payload_contains_safe_rbac_aggregates(self):
        source = json.loads((ROOT / "mock/assessment.json").read_text(encoding="utf-8"))
        source.setdefault("discovery", {})["rbac_summary"] = {
            "assignments": 12,
            "high_risk_assignments": 4,
            "critical_assignments": 2,
            "permanent_or_unknown_assignments": 10,
            "by_scope": [{"scope_kind": "Subscription", "assignments": 3}],
        }
        result = build(source)
        self.assertEqual(result["azure_rbac_posture"]["critical_assignments"], 2)
        self.assertEqual(result["azure_rbac_posture"]["by_scope"][0]["assignments"], 3)
        self.assertIn("não representa uso efetivo", result["azure_rbac_posture"]["interpretation"])
        self.assertNotIn("resource_id", json.dumps(result, ensure_ascii=False))

    def test_ai_payload_contains_safe_governance_aggregates(self):
        source = json.loads((ROOT / "mock/assessment.json").read_text(encoding="utf-8"))
        source.setdefault("discovery", {})["governance_summary"] = {"resources_assessed": 10, "without_owner": 3, "without_environment_tag": 4, "without_tags": 2, "policy_evaluated": 8, "policy_non_compliant": 1, "policy_compliance_rate": 87.5}
        result = build(source)
        self.assertEqual(result["azure_governance_posture"]["without_owner"], 3)
        self.assertEqual(result["azure_governance_posture"]["policy_compliance_rate"], 87.5)
        self.assertIn("não prova risco", result["azure_governance_posture"]["interpretation"])

    def test_artifact_validator_accepts_generated_package(self):
        result = validate(self.artifact_dir, self.ai_payload)
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
