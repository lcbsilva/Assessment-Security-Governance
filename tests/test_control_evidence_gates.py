import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from insight_engine import apply_control_source_gates, control_evidence


class ControlEvidenceGateTests(unittest.TestCase):
    def _catalog(self, control_id):
        return {"controls": [{"id": control_id, "title": control_id, "domain": "security"}]}

    def test_multi_source_control_uses_least_complete_required_source(self):
        data = {
            "controls": [{"id": "SEC-002", "status": "pass", "score": 95, "confidence": "high", "evidence_state": "CONFORMANT"}],
            "discovery": {"collection_log": [
                {"module": "Entra devices", "status": "success", "records": 20},
                {"module": "Intune managed devices", "status": "not_available", "records": 0},
            ]},
        }
        evidence = control_evidence(data, self._catalog("SEC-002"))[0]
        self.assertEqual(evidence["status"], "not_available")
        self.assertEqual(evidence["evidence_state"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(evidence["confidence"], "baixa")
        control = apply_control_source_gates(data["controls"], [evidence])[0]
        self.assertEqual(control["status"], "not_available")
        self.assertIsNone(control["score"])
        self.assertEqual(control["evidence_state"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(control["source_collection_status"], "not_available")

    def test_missing_required_source_does_not_borrow_success_from_another(self):
        data = {"discovery": {"collection_log": [
            {"module": "Enterprise applications", "status": "success", "records": 12},
        ]}}
        evidence = control_evidence(data, self._catalog("SEC-003"))[0]
        self.assertEqual(evidence["status"], "not_available")
        self.assertIn("fontes requeridas", evidence["limitation"].lower())

    def test_all_role_member_queries_must_succeed_for_privileged_mfa_control(self):
        data = {"discovery": {"collection_log": [
            {"module": "Identity", "status": "success"},
            {"module": "MFA", "status": "success"},
            {"module": "Directory roles", "status": "success"},
            {"module": "Role members: Global Administrator", "status": "success"},
            {"module": "Role members: Privileged Role Administrator", "status": "partial"},
        ]}}
        evidence = control_evidence(data, self._catalog("ID-002"))[0]
        self.assertEqual(evidence["status"], "partial")
        self.assertEqual(evidence["evidence_state"], "INSUFFICIENT_EVIDENCE")

    def test_successful_fallback_source_can_support_single_source_group(self):
        data = {"discovery": {"collection_log": [
            {"module": "Identity", "status": "error"},
            {"module": "Identity basic", "status": "success"},
        ]}}
        evidence = control_evidence(data, self._catalog("ID-006"))[0]
        self.assertEqual(evidence["status"], "success")


if __name__ == "__main__":
    unittest.main()
